#!/usr/bin/env python3
"""
VulnWatch — veille automatique des vulnérabilités, 24 h/24, gratuite (GitHub Actions).

Sources : NVD 2.0 (NIST), catalogue CISA KEV, FIRST EPSS.
Sorties  : tableau de bord web (GitHub Pages), classeur Excel, CSV (Power Query), JSON.
Alertes  : Excel (journal + tableau de bord), ntfy (push iPhone/Android), courriel (+ rapport quotidien avec l'Excel joint).

Tous les réglages passent par des variables d'environnement (secrets / variables GitHub),
voir LISEZMOI.md. Le script est idempotent : l'état est conservé dans --state.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import shutil
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage
from pathlib import Path

import requests

import classify  # noqa: E402
import explain  # noqa: E402
import intel  # noqa: E402
import tickets  # noqa: E402
from collections import Counter  # noqa: E402

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

VERSION = "2.0"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
UTC = dt.timezone.utc

SEV_FR = {"CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉE", "MEDIUM": "MOYENNE", "LOW": "FAIBLE", "NONE": "AUCUNE"}
SEV_RANK = {"CRITIQUE": 4, "ÉLEVÉE": 3, "MOYENNE": 2, "FAIBLE": 1}


# --------------------------------------------------------------------------- configuration

# Correspondance variable d'environnement / variable GitHub -> clé du fichier reglages.yml.
# Ordre de priorité : variable GitHub (si renseignée) > reglages.yml > valeur par défaut.
SETTINGS_MAP = {
    "CRITICAL_SCORE": ("seuils", "cvss_critique"), "EPSS_ALERT": ("seuils", "epss_alerte"),
    "WATCHLIST_MIN_SCORE": ("seuils", "cvss_min_parc"),
    "ALERT_ON_KEV": ("alertes", "failles_exploitees"), "ALERT_ON_CRITICAL": ("alertes", "failles_critiques"),
    "SEND_DIGEST": ("alertes", "resume_horaire"), "MAX_ALERTS_PER_RUN": ("alertes", "maximum_par_passage"),
    "QUIET_HOURS": ("alertes", "heures_calmes"), "DAILY_REPORT": ("alertes", "rapport_quotidien"),
    "DAILY_REPORT_HOUR": ("alertes", "heure_du_rapport"), "EMAIL_MIN_PRIORITY": ("alertes", "courriel_niveau_minimum"),
    "RETENTION_DAYS": ("historique", "jours_de_cve"), "KEV_HISTORY_DAYS": ("historique", "jours_catalogue_cisa"),
    "INITIAL_DAYS": ("historique", "jours_premier_passage"),
    "USE_EXPLOIT_SOURCES": ("sources", "exploits_publics"), "USE_VULNRICHMENT": ("sources", "analyse_cisa"),
    "USE_GITHUB_ADVISORIES": ("sources", "bibliotheques_open_source"),
    "ENRICH_MAX_PER_RUN": ("sources", "enrichissements_par_passage"),
    "TICKETS": ("suivi", "tickets"), "TICKET_PRIORITY": ("suivi", "priorite_des_tickets"),
    "TIMEZONE": ("affichage", "fuseau_horaire"), "HIDE_WATCHLIST": ("affichage", "masquer_mots_cles"),
}


def load_settings_file(path: Path | None = None) -> dict:
    path = path or Path(__file__).with_name("reglages.yml")
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] reglages.yml illisible ({e}) : valeurs par défaut utilisées.", flush=True)
        return {}


SETTINGS = load_settings_file()


def _env(name: str, default=None):
    v = os.environ.get(name, "")
    v = v.strip() if isinstance(v, str) else v
    if v:
        return v
    sec, key = SETTINGS_MAP.get(name, (None, None))
    if sec:
        fv = (SETTINGS.get(sec) or {}).get(key)
        if fv is not None and fv != "":
            return str(fv).lower() if isinstance(fv, bool) else str(fv)
    return default


def _envf(name, default):
    try:
        return float(str(_env(name, default)).replace(",", "."))
    except ValueError:
        return default


def _envi(name, default):
    try:
        return int(_env(name, default))
    except ValueError:
        return default


def _envb(name, default):
    v = _env(name)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "oui", "yes", "vrai", "on")


def load_config() -> dict:
    watch = _env("WATCHLIST", "") or ""
    return {
        "nvd_key": _env("NVD_API_KEY"),
        "initial_days": _envi("INITIAL_DAYS", 7),
        "retention_days": _envi("RETENTION_DAYS", 30),
        "kev_days": _envi("KEV_HISTORY_DAYS", 90),
        "critical": _envf("CRITICAL_SCORE", 9.0),
        "epss_alert": _envf("EPSS_ALERT", 0.5),
        "watch_min": _envf("WATCHLIST_MIN_SCORE", 7.0),
        "alert_kev": _envb("ALERT_ON_KEV", True),
        "alert_critical": _envb("ALERT_ON_CRITICAL", True),
        "digest": _envb("SEND_DIGEST", True),
        "max_alerts": _envi("MAX_ALERTS_PER_RUN", 10),
        "silent_first": _envb("SILENT_FIRST_RUN", True),
        "watchlist": list(dict.fromkeys([w.strip() for w in re.split(r"[,;\n]", watch) if w.strip()]
                                        + [str(w).strip() for w in (SETTINGS.get("mots_cles") or []) if str(w).strip()])),
        "hide_watch": _envb("HIDE_WATCHLIST", False),
        "tz": _env("TIMEZONE", "America/Toronto"),
        "site_url": _env("SITE_URL", ""),
        "ntfy_server": (_env("NTFY_SERVER", "https://ntfy.sh") or "https://ntfy.sh").rstrip("/"),
        "ntfy_topic": _env("NTFY_TOPIC"),
        "ntfy_token": _env("NTFY_TOKEN"),
        "smtp_host": _env("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": _envi("SMTP_PORT", 587),
        "smtp_user": _env("SMTP_USER"),
        "smtp_pass": _env("SMTP_PASSWORD"),
        "mail_from": _env("MAIL_FROM"),
        "mail_to": _env("MAIL_TO"),
        "email_min_priority": _envi("EMAIL_MIN_PRIORITY", 4),
        "inventory_csv": os.environ.get("INVENTAIRE", "") or "",
        "excel_password": _env("EXCEL_PASSWORD"),
        "webhook_url": _env("WEBHOOK_URL"),
        "webhook_type": (_env("WEBHOOK_TYPE", "") or "").lower(),
        "quiet_hours": _env("QUIET_HOURS", ""),
        "tickets": _envb("TICKETS", False),
        "ticket_min_priority": _env("TICKET_PRIORITY", "P1"),
        "gh_token": _env("GITHUB_TOKEN"),
        "gh_repo": _env("GITHUB_REPOSITORY"),
        "enrich_max": _envi("ENRICH_MAX_PER_RUN", 600),
        "use_ghsa": _envb("USE_GITHUB_ADVISORIES", True),
        "use_exploits": _envb("USE_EXPLOIT_SOURCES", True),
        "use_vulnrichment": _envb("USE_VULNRICHMENT", True),
        "daily_report": _envb("DAILY_REPORT", True),
        "daily_hour": _envi("DAILY_REPORT_HOUR", 7),
    }


# --------------------------------------------------------------------------- utilitaires

def log(msg: str, level: str = "INFO") -> None:
    print(f"{dt.datetime.now(UTC):%Y-%m-%d %H:%M:%S}Z [{level}] {msg}", flush=True)


def parse_dt(value) -> dt.datetime | None:
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = dt.datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.astimezone(UTC)


def iso(d: dt.datetime | None) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""


def date_only(value) -> str:
    d = parse_dt(value)
    return d.strftime("%Y-%m-%d") if d else ""


def to_float(v):
    if v is None or v == "":
        return None
    try:
        return float(str(v).replace(",", "."))
    except ValueError:
        return None


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, data, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if compact:
        tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    else:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


class Http:
    """Client HTTP avec reprises exponentielles ; 404 n'est jamais retenté."""

    def __init__(self):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = f"VulnWatch/{VERSION} (+https://github.com)"

    def get_raw(self, url, params=None, headers=None, tries=4, timeout=120, quiet=False):
        for i in range(1, tries + 1):
            try:
                r = self.s.get(url, params=params, headers=headers, timeout=timeout)
                if r.status_code == 404:
                    r.raise_for_status()
                if r.status_code in (403, 429) or r.status_code >= 500:
                    raise requests.HTTPError(f"HTTP {r.status_code}")
                r.raise_for_status()
                return r
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    raise
                err = e
            except Exception as e:  # noqa: BLE001
                err = e
            if not quiet:
                log(f"Requête en échec ({err}) tentative {i}/{tries} : {url}", "WARN")
            if i == tries:
                raise err
            time.sleep(min(60, 6 * i * i))

    def get_json(self, url, params=None, headers=None, tries=4, timeout=120, quiet=False):
        return self.get_raw(url, params, headers, tries, timeout, quiet).json()

    def get_text(self, url, params=None, headers=None, tries=4, timeout=120, quiet=False):
        r = self.get_raw(url, params, headers, tries, timeout, quiet)
        r.encoding = r.encoding or "utf-8"
        return r.text

    def post(self, url, **kw):
        kw.setdefault("timeout", 30)
        r = self.s.post(url, **kw)
        r.raise_for_status()
        return r

    def patch(self, url, **kw):
        kw.setdefault("timeout", 30)
        r = self.s.patch(url, **kw)
        r.raise_for_status()
        return r


# --------------------------------------------------------------------------- sources

NVD_KEY_REJECTED: list = []


def fetch_nvd(http: Http, start: dt.datetime, end: dt.datetime, api_key: str | None) -> list:
    """CVE modifiées (ou publiées) dans [start, end], découpage par 120 jours, pagination."""
    headers = {"apiKey": api_key} if api_key else None
    delay = 0.8 if api_key else 6.5  # 50 ou 5 requêtes / 30 s
    out, first = [], True
    chunk_start = start
    while chunk_start < end:
        chunk_end = min(chunk_start + dt.timedelta(days=119), end)
        idx, total = 0, 1
        while idx < total:
            if not first:
                time.sleep(delay)
            first = False
            params = {
                "lastModStartDate": chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "lastModEndDate": chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "resultsPerPage": 1000,
                "startIndex": idx,
            }
            try:
                data = http.get_json(NVD_URL + "?noRejected", params=params, headers=headers)
            except requests.HTTPError as e:
                # La NVD répond 404 quand la clé API est invalide : on continue sans clé (plus lent) et on prévient.
                if headers and e.response is not None and e.response.status_code == 404:
                    log("Clé NVD_API_KEY refusée par la NVD (404) : vérifie le secret. Passage sans clé.", "ERREUR")
                    NVD_KEY_REJECTED.append(True)
                    headers, delay = None, 6.5
                    time.sleep(delay)
                    data = http.get_json(NVD_URL + "?noRejected", params=params, headers=None)
                else:
                    raise
            total = int(data.get("totalResults", 0))
            out.extend(data.get("vulnerabilities") or [])
            idx += 1000
            log(f"NVD : {min(idx, total)}/{total} ({chunk_start:%Y-%m-%d %H:%M} → {chunk_end:%Y-%m-%d %H:%M} UTC)")
        chunk_start = chunk_end
    return out


def parse_nvd(item: dict, now: dt.datetime) -> dict:
    c = item.get("cve", {})
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    metric, ver = None, ""
    metrics = c.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key) or []
        if m:
            metric = next((x for x in m if x.get("type") == "Primary"), m[0])
            ver = key[-2] + "." + key[-1]
            break
    score = sev = vector = None
    if metric:
        cd = metric.get("cvssData", {})
        score = to_float(cd.get("baseScore"))
        sev = cd.get("baseSeverity") or metric.get("baseSeverity")
        vector = cd.get("vectorString")
    cwes = []
    for w in c.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    vendor = product = ""
    for conf in c.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if m.get("vulnerable") and m.get("criteria"):
                    parts = m["criteria"].split(":")
                    if len(parts) >= 5:
                        vendor, product = parts[3].replace("_", " "), parts[4].replace("_", " ")
                    break
            if vendor:
                break
        if vendor:
            break
    refs = c.get("references", []) or []
    ref_patch = next((x.get("url", "") for x in refs if "Patch" in (x.get("tags") or [])), "") or \
        next((x.get("url", "") for x in refs if "Vendor Advisory" in (x.get("tags") or [])), "")
    exploit_ref = next((x.get("url", "") for x in refs if "Exploit" in (x.get("tags") or [])), "")
    src = c.get("sourceIdentifier", "") or ""
    source = src.split("@")[-1] if "@" in src else src
    return {
        "id": c.get("id", ""),
        "published": iso(parse_dt(c.get("published"))),
        "modified": iso(parse_dt(c.get("lastModified"))),
        "severity": SEV_FR.get(str(sev or "").upper(), "NON ÉVALUÉE"),
        "score": score,
        "cvss_version": ver,
        "vector": vector or "",
        "epss": None,
        "epss_pct": None,
        "kev": bool(c.get("cisaExploitAdd")),
        "kev_added": date_only(c.get("cisaExploitAdd")),
        "kev_due": date_only(c.get("cisaActionDue")),
        "ransomware": "",
        "vendor": vendor,
        "product": product,
        "cwe": ", ".join(cwes),
        "status": c.get("vulnStatus", ""),
        "watch": "",
        "first_seen": iso(now),
        "desc": re.sub(r"\s+", " ", desc).strip(),
        "ref_patch": ref_patch,
        "exploit_ref": exploit_ref,
        "source": source,
    }


def fetch_kev(http: Http) -> dict:
    last = None
    for url in KEV_URLS:
        try:
            data = http.get_json(url, tries=2)
            if data.get("vulnerabilities"):
                log(f"CISA KEV : catalogue {data.get('catalogVersion')} ({len(data['vulnerabilities'])} entrées)")
                return data
        except Exception as e:  # noqa: BLE001
            last = e
            log(f"Source KEV indisponible ({url}) : {e}", "WARN")
    raise RuntimeError(f"Catalogue CISA KEV injoignable : {last}")


def fetch_epss(http: Http, ids: list[str]) -> dict:
    """Renvoie {cve: (epss, percentile)} ; paramètre cve= limité à 2000 caractères → lots de 100."""
    res, ids = {}, sorted(set(ids))
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        try:
            data = http.get_json(EPSS_URL, params={"cve": ",".join(batch), "limit": 100}, tries=3)
            for d in data.get("data", []) or []:
                res[d["cve"]] = (to_float(d.get("epss")), to_float(d.get("percentile")))
        except Exception as e:  # noqa: BLE001
            log(f"EPSS : lot ignoré ({e})", "WARN")
        time.sleep(0.25)
    log(f"EPSS : {len(res)}/{len(ids)} scores obtenus")
    return res


# --------------------------------------------------------------------------- notifications

class Notifier:
    """Canaux : ntfy (notification push iPhone/Android) et courriel SMTP."""

    def __init__(self, cfg: dict, http: Http):
        self.cfg, self.http = cfg, http

    def email_ok(self) -> bool:
        c = self.cfg
        return bool(c["smtp_user"] and c["smtp_pass"] and c["mail_to"])

    def quiet_now(self) -> bool:
        """Heures calmes (ex. QUIET_HOURS=22-7) : seules les alertes urgentes (niveau 5) sont poussées."""
        qh = self.cfg.get("quiet_hours") or ""
        m = re.match(r"^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$", qh)
        if not m:
            return False
        start, end = int(m.group(1)), int(m.group(2))
        h = dt.datetime.now(ZoneInfo(self.cfg["tz"]) if ZoneInfo else UTC).hour
        return (start <= h or h < end) if start > end else (start <= h < end)

    def channels(self) -> list[str]:
        out = []
        if self.cfg["webhook_url"]:
            out.append(f"Webhook ({self.cfg['webhook_type'] or 'auto'})")
        if self.cfg["ntfy_topic"]:
            out.append("ntfy")
        if self.email_ok():
            out.append("Courriel")
        return out

    def send_email(self, subject: str, text: str, html_body: str | None = None,
                   attachment: Path | None = None, urgent: bool = False) -> None:
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = c["mail_from"] or c["smtp_user"]
        msg["To"] = c["mail_to"]
        if urgent:
            msg["X-Priority"] = "1"
            msg["Importance"] = "High"
        msg.set_content(text)
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        if attachment and attachment.exists():
            msg.add_attachment(attachment.read_bytes(), maintype="application",
                               subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                               filename=attachment.name)
        ctx = ssl.create_default_context()
        if c["smtp_port"] == 465:
            with smtplib.SMTP_SSL(c["smtp_host"], 465, context=ctx, timeout=60) as s:
                s.login(c["smtp_user"], c["smtp_pass"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(c["smtp_host"], c["smtp_port"], timeout=60) as s:
                s.starttls(context=ctx)
                s.login(c["smtp_user"], c["smtp_pass"])
                s.send_message(msg)

    def _webhook(self, title, body, priority, url):
        c = self.cfg
        hook = c["webhook_url"]
        kind = c["webhook_type"] or ("discord" if "discord" in hook else "slack" if "hooks.slack.com" in hook
                                     else "teams" if ("logic.azure.com" in hook or "webhook.office.com" in hook
                                                      or "powerplatform" in hook) else "generic")
        icon = {5: "🔴", 4: "🟠", 3: "🔵"}.get(priority, "⚪")
        links = [x for x in ((url, "Fiche NVD"), (c["site_url"], "Console VulnWatch"),
                              (c["site_url"] + "VulnWatch.xlsx" if c["site_url"] else "", "Excel")) if x[0]]
        if kind == "teams":
            card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                    "body": [{"type": "TextBlock", "text": f"{icon} {title}", "weight": "Bolder", "size": "Medium", "wrap": True},
                             {"type": "TextBlock", "text": body.replace("\n", "\n\n"), "wrap": True}],
                    "actions": [{"type": "Action.OpenUrl", "title": t, "url": u} for u, t in links]}
            payload = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                           "content": card}]}
        elif kind == "slack":
            payload = {"text": f"{icon} *{title}*\n{body}\n" + " · ".join(f"<{u}|{t}>" for u, t in links)}
        elif kind == "discord":
            payload = {"content": (f"{icon} **{title}**\n{body}\n" + "\n".join(f"{t} : <{u}>" for u, t in links))[:1990]}
        else:
            payload = {"title": title, "message": body, "priority": priority, "url": url, "links": dict((t, u) for u, t in links)}
        self.http.post(hook, json=payload)

    def send(self, title: str, lines: list[str], priority: int = 3, url: str = "", tags=None) -> str:
        c, sent = self.cfg, []
        body = "\n".join(lines)
        if priority < 5 and self.quiet_now():
            return "(heures calmes : visible dans l'Excel)"
        if c["webhook_url"] and priority >= 3:
            try:
                self._webhook(title, body, priority, url)
                sent.append("Webhook")
            except Exception as e:  # noqa: BLE001
                log(f"Webhook : échec ({type(e).__name__})", "WARN")
        xlsx_url = (c["site_url"] + "VulnWatch.xlsx") if c["site_url"] else ""
        if c["ntfy_topic"]:
            try:
                payload = {"topic": c["ntfy_topic"], "title": title, "message": body[:3500],
                           "priority": priority, "tags": tags or []}
                if url:
                    payload["click"] = url
                actions = []
                if xlsx_url:
                    actions.append({"action": "view", "label": "Ouvrir l'Excel", "url": xlsx_url})
                if c["site_url"]:
                    actions.append({"action": "view", "label": "Tableau de bord", "url": c["site_url"]})
                if actions:
                    payload["actions"] = actions
                h = {"Authorization": f"Bearer {c['ntfy_token']}"} if c["ntfy_token"] else None
                self.http.post(c["ntfy_server"] + "/", json=payload, headers=h)
                sent.append("ntfy")
            except Exception as e:  # noqa: BLE001
                log(f"ntfy : échec ({type(e).__name__})", "WARN")
        if self.email_ok() and priority >= c["email_min_priority"]:
            try:
                links = [x for x in (url and f"Fiche NVD : {url}", xlsx_url and f"Excel : {xlsx_url}",
                                     c["site_url"] and f"Tableau de bord : {c['site_url']}") if x]
                self.send_email(f"[VulnWatch] {title}", body + "\n\n" + "\n".join(links), urgent=priority >= 5)
                sent.append("Courriel")
            except Exception as e:  # noqa: BLE001
                log(f"Courriel : échec ({type(e).__name__}: {e})", "WARN")
        return ", ".join(sent)


def daily_report_html(records: list[dict], kev_recent: list[dict], alerts: list[dict], cfg: dict) -> tuple[str, str]:
    """Rapport quotidien : synthèse 24 h en texte et HTML (le classeur est joint)."""
    now = dt.datetime.now(UTC)
    records = [enrich(dict(r), {"critical": cfg["critical"]}, now) for r in records]
    d1 = now - dt.timedelta(days=1)
    new = [r for r in records if (parse_dt(r["published"]) or now) >= d1]
    crit = [r for r in new if (r["score"] or 0) >= cfg["critical"]]
    kev1 = [k for k in kev_recent if (parse_dt(k.get("dateAdded")) or now) >= d1.replace(hour=0, minute=0, second=0)]
    al = [a for a in alerts if (parse_dt(a["date"]) or now) >= d1 and not str(a.get("channels", "")).startswith("(")]
    prio = sorted([r for r in records if is_priority(r) and (parse_dt(r["modified"]) or now) >= d1],
                  key=priority_key, reverse=True)[:15]
    text = (f"Dernières 24 h : {len(new)} nouvelles CVE, {len(crit)} critiques, {len(kev1)} ajouts KEV, "
            f"{len(al)} alertes envoyées.\nLe classeur Excel complet est en pièce jointe.\n"
            + (f"Tableau de bord : {cfg['site_url']}\n" if cfg["site_url"] else "")
            + "\nÀ traiter en priorité :\n"
            + "\n".join(f"- {r['id']} {r['severity']} {r['score'] or ''} {r['vendor']} {r['product']}" for r in prio))
    color = {"CRITIQUE": "#c00000", "ÉLEVÉE": "#ed7d31", "MOYENNE": "#bf8f00", "FAIBLE": "#548235"}
    rows = "".join(
        f'<tr><td style="white-space:nowrap"><a href="{NVD_DETAIL}{r["id"]}">{r["id"]}</a></td>'
        f'<td style="color:#fff;background:{color.get(r["severity"], "#7f7f7f")};padding:2px 6px">{html.escape(r["severity"])}</td>'
        f'<td>{r["score"] if r["score"] is not None else "—"}</td>'
        f'<td>{"Oui" if r["kev"] else ""}</td>'
        f'<td>{html.escape((r["vendor"] + " " + r["product"]).strip())}</td>'
        f'<td>{html.escape(r["desc"][:160])}</td></tr>' for r in prio)
    hb = f"""<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">
<h2 style="margin:0 0 8px">VulnWatch — rapport quotidien</h2>
<p><b>{len(new)}</b> nouvelles CVE · <b style="color:#c00000">{len(crit)}</b> critiques ·
<b style="color:#7f1d1d">{len(kev1)}</b> ajouts CISA KEV · <b>{len(al)}</b> alertes envoyées (24 h)</p>
<p>📎 Le classeur <b>VulnWatch.xlsx</b> complet est en pièce jointe.
{f'<br>🌐 <a href="{cfg["site_url"]}">Tableau de bord en ligne</a>' if cfg["site_url"] else ""}</p>
<h3>À traiter en priorité</h3>
<table cellspacing="0" cellpadding="4" style="border-collapse:collapse;font-size:13px">
<tr style="background:#1f3864;color:#fff"><th>CVE</th><th>Sévérité</th><th>CVSS</th><th>KEV</th><th>Produit</th><th>Description</th></tr>
{rows or '<tr><td colspan="6">Rien de prioritaire dans les dernières 24 h.</td></tr>'}</table>
<p style="color:#888;font-size:12px">Sources : NVD (NIST), CISA KEV, FIRST EPSS.</p></div>"""
    return text, hb


# --------------------------------------------------------------------------- sorties

from rapport_excel import DETAIL_COLS, build_xlsx, enrich, sev_from_score  # noqa: E402

PRIO_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def priority_key(r: dict):
    """Tri du plus urgent au moins urgent (après enrich)."""
    return (-PRIO_ORDER.get(r.get("priority"), 9), r.get("risk") or 0)


def is_priority(r: dict) -> bool:
    return r.get("priority") in ("P1", "P2")


PRIVATE_FIELDS = ("assets", "asset_versions", "asset_owner")
INTERNAL_FIELDS = ("epss_hist", "vr_checked", "severity_en", "cna_vendor", "cna_product")


def encrypt_xlsx(src: Path, dst: Path, password: str) -> None:
    """Chiffrement Office standard (AES, « Agile Encryption ») : Excel iPhone, PC et Mac demandent le mot de passe."""
    from msoffcrypto.format.ooxml import OOXMLFile
    with src.open("rb") as f, dst.open("wb") as o:
        OOXMLFile(f).encrypt(password, o)


def write_feed(path: Path, alerts: list[dict], cfg: dict) -> None:
    """Flux Atom des alertes importantes (lecteur RSS, Outlook, Teams, Slack…)."""
    from xml.sax.saxutils import escape as x
    base = cfg["site_url"] or "https://nvd.nist.gov/"
    items = [a for a in sorted(alerts, key=lambda a: a["date"], reverse=True)
             if a.get("priority", 0) >= 4 and not str(a.get("channels", "")).startswith("(référence")][:100]
    upd = items[0]["date"] if items else iso(dt.datetime.now(UTC))
    out = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">',
           "<title>VulnWatch — alertes de vulnérabilités</title>", f'<link href="{x(base)}"/>',
           f"<id>{x(base)}feed.xml</id>", f"<updated>{upd}</updated>"]
    for a in items:
        msg = re.sub(r"Actifs : [^|]*\|?", "", a.get("message", ""))  # jamais d'actifs dans un flux public
        out += ["<entry>", f"<title>{x(('🔴 ' if a['priority'] >= 5 else '🟠 ') + a['cve'] + ' — ' + a['reasons'])}</title>",
                f'<link href="{NVD_DETAIL}{x(a["cve"])}"/>', f"<id>urn:vulnwatch:{x(a['cve'])}:{x(a['date'])}</id>",
                f"<updated>{a['date']}</updated>", f"<summary>{x(msg.replace(' | ', ' — '))}</summary>", "</entry>"]
    out.append("</feed>")
    path.write_text("\n".join(out), encoding="utf-8")


def sanitize_alert(a: dict) -> dict:
    """Retire toute mention d'actif d'une alerte (pour les sorties et l'état publics)."""
    msg = re.sub(r"Actifs : [^|]*\| ?", "", a.get("message", ""))
    msg = re.sub(r"Touche ton parc : [^·|]*", "Touche ton parc ", msg)
    msg = re.sub(r"Elle concerne ton parc : [^|]*?\.(?= |\||$)", "Elle concerne ton parc.", msg)
    return {**a, "message": msg, "reasons": re.sub(r"Touche ton parc : [^·]*", "Touche ton parc ", a.get("reasons", "")).strip()}


def build_outputs(site: Path, records: list[dict], kev_recent: list[dict], alerts: list[dict],
                  cfg: dict, meta: dict) -> Path:
    """Écrit Excel, CSV, JSON et flux Atom. Renvoie le chemin du classeur complet (pour le courriel)."""
    site.mkdir(parents=True, exist_ok=True)
    tz = ZoneInfo(cfg["tz"]) if ZoneInfo else UTC
    now = dt.datetime.now(UTC)
    inventory = meta.get("inventory") or []
    xcfg = {"critical": cfg["critical"], "tz": cfg["tz"], "retention_days": cfg["retention_days"], "kev_days": cfg["kev_days"]}
    recs = [enrich(dict(r), xcfg, now) for r in records]
    recs.sort(key=lambda r: r["modified"], reverse=True)
    hide = bool(inventory) or cfg["hide_watch"]
    pub = []
    for r in recs:
        q = {k: v for k, v in r.items() if k not in INTERNAL_FIELDS}
        if hide:
            q["watch"] = "✓" if r.get("watch") else ""
            for k in PRIVATE_FIELDS:
                q[k] = ""
            q["justification"] = (r.get("justification") or "").replace(" — criticité haute", "")
            q["plain"] = explain.en_clair(q, show_assets=False)
        pub.append(q)
    d1, d7 = now - dt.timedelta(days=1), now - dt.timedelta(days=7)

    def pubdate(r):
        return parse_dt(r["published"]) or now

    kpi = {
        "updated": iso(now),
        "new_24h": sum(1 for r in recs if pubdate(r) >= d1),
        "new_7d": sum(1 for r in recs if pubdate(r) >= d7),
        "critical_7d": sum(1 for r in recs if pubdate(r) >= d7 and (r["score"] or 0) >= cfg["critical"]),
        "kev_7d": sum(1 for k in kev_recent if (parse_dt(k.get("dateAdded")) or now) >= d7.replace(hour=0, minute=0, second=0)),
        "watch_7d": sum(1 for r in recs if pubdate(r) >= d7 and r.get("watch")),
        "alerts_7d": sum(1 for a in alerts if (parse_dt(a["date"]) or now) >= d7 and a.get("channels") and not a["channels"].startswith("(")),
        "p1": sum(1 for r in recs if r["priority"] == "P1"),
        "p2": sum(1 for r in recs if r["priority"] == "P2"),
        "weapon": sum(1 for r in recs if r.get("msf")),
        "total": len(recs),
        "kev_version": meta.get("kev_version", ""),
        "critical_score": cfg["critical"],
        "health": meta.get("health", {}),
        "encrypted": bool(cfg["excel_password"]),
        "repo": cfg.get("gh_repo") or "",
        "settings": {
            "seuils": {"cvss_critique": cfg["critical"], "epss_alerte": cfg["epss_alert"], "cvss_min_parc": cfg["watch_min"]},
            "alertes": {"failles_exploitees": cfg["alert_kev"], "failles_critiques": cfg["alert_critical"],
                        "resume_horaire": cfg["digest"], "maximum_par_passage": cfg["max_alerts"],
                        "heures_calmes": cfg["quiet_hours"] or "", "rapport_quotidien": cfg["daily_report"],
                        "heure_du_rapport": cfg["daily_hour"], "courriel_niveau_minimum": cfg["email_min_priority"]},
            "historique": {"jours_de_cve": cfg["retention_days"], "jours_catalogue_cisa": cfg["kev_days"],
                           "jours_premier_passage": cfg["initial_days"]},
            "sources": {"exploits_publics": cfg["use_exploits"], "analyse_cisa": cfg["use_vulnrichment"],
                        "bibliotheques_open_source": cfg["use_ghsa"], "enrichissements_par_passage": cfg["enrich_max"]},
            "suivi": {"tickets": cfg["tickets"], "priorite_des_tickets": cfg["ticket_min_priority"]},
            "affichage": {"fuseau_horaire": cfg["tz"], "masquer_mots_cles": cfg["hide_watch"]},
            "mots_cles": [str(w) for w in (SETTINGS.get("mots_cles") or [])],
        },
        "channels": {"ntfy": bool(cfg["ntfy_topic"]), "courriel": bool(cfg["smtp_user"] and cfg["mail_to"]),
                     "webhook": bool(cfg["webhook_url"]), "inventaire": bool(inventory), "cle_nvd": bool(cfg["nvd_key"]),
                     "excel_chiffre": bool(cfg["excel_password"])},
    }
    kev_rows = sorted(kev_recent, key=lambda k: k.get("dateAdded", ""), reverse=True)
    alert_rows = sorted(alerts, key=lambda a: a["date"], reverse=True)[:1000]
    pub_alerts = [sanitize_alert(a) if hide else a for a in alert_rows]

    # ---- JSON (console web + API)
    from rapport_excel import EXPERT_QUERIES
    write_json(site / "data.json", {
        "kpi": kpi,
        "views": [{"name": n, "desc": d} for n, d, _ in EXPERT_QUERIES],
        "synthese": explain.synthese(pub, kpi, meta.get("stats"), show_assets=False),
        "glossaire": [{"terme": t, "def": d} for t, d in explain.GLOSSAIRE],
        "vulns": pub,
        "kev": [{k: v.get(k, "") for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                                            "shortDescription", "requiredAction", "dueDate",
                                            "knownRansomwareCampaignUse")} for v in kev_rows],
        "alerts": [{k: a.get(k) for k in ("date", "cve", "reasons", "priority", "channels")} for a in pub_alerts[:300]],
        "stats": meta.get("stats", [])[-90:],
    }, compact=True)

    # ---- CSV (source Power Query) : mêmes colonnes détaillées que l'Excel
    def local(s):
        d = parse_dt(s)
        return d.astimezone(tz).strftime("%Y-%m-%d %H:%M") if d else ""

    with (site / "vulns.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow([h for _, h, _, _ in DETAIL_COLS] + ["Lien NVD"])
        for r in sorted(pub, key=priority_key, reverse=True):
            row = []
            for k, _, _, kind in DETAIL_COLS:
                v = r.get(k)
                if kind == "yesno":
                    v = "Oui" if v else "Non"
                elif kind == "datetime":
                    v = local(v)
                elif v is None:
                    v = ""
                row.append(v)
            w.writerow(row + [NVD_DETAIL + r["id"]])
    with (site / "alertes.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Date", "CVE", "Motifs", "Niveau", "Canaux", "Détail", "Lien NVD"])
        for a in pub_alerts:
            w.writerow([local(a["date"]), a["cve"], a["reasons"], a["priority"], a["channels"], a["message"], NVD_DETAIL + a["cve"]])
    with (site / "kev.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["CVE", "Ajoutée le", "Fournisseur", "Produit", "Nom", "Description", "Action requise", "Échéance", "Rançongiciel"])
        for k in kev_rows:
            w.writerow([k.get("cveID"), k.get("dateAdded"), k.get("vendorProject"), k.get("product"),
                        k.get("vulnerabilityName"), k.get("shortDescription"), k.get("requiredAction"),
                        k.get("dueDate"), k.get("knownRansomwareCampaignUse")])
    write_feed(site / "feed.xml", pub_alerts, cfg)

    # ---- Classeurs Excel : complet (privé) et publié
    work = site.parent / (site.name + "_prive")
    work.mkdir(parents=True, exist_ok=True)
    private = work / "VulnWatch.xlsx"
    build_xlsx(private, recs, kev_rows, alert_rows, kpi, xcfg, tz, inventory, meta.get("stats"))
    if cfg["excel_password"]:
        encrypt_xlsx(private, site / "VulnWatch.xlsx", cfg["excel_password"])
        private_send = work / "VulnWatch-chiffre.xlsx"
        shutil.copy(site / "VulnWatch.xlsx", private_send)
        log("Excel publié chiffré (mot de passe requis à l'ouverture).")
    elif hide:
        build_xlsx(site / "VulnWatch.xlsx", pub, kev_rows, pub_alerts, kpi, xcfg, tz, None, meta.get("stats"))
        private_send = private
        log("Excel publié sans le détail de tes actifs (définis EXCEL_PASSWORD pour publier la version complète chiffrée).")
    else:
        shutil.copy(private, site / "VulnWatch.xlsx")
        private_send = private
    log(f"Sorties écrites dans {site}")
    return private_send


# --------------------------------------------------------------------------- moteur

RULES_VERSION = "3.1"
KEEP_ON_UPDATE = ("epss", "epss_pct", "epss_hist", "ssvc_exploitation", "ssvc_automatable", "ssvc_impact", "affected",
                  "versions", "ghsa", "packages", "pkg_ranges", "pkg_fixed", "ransomware", "kev_added", "kev_due",
                  "score", "vector", "cvss_version", "score_source", "severity", "severity_en")


def run(args) -> int:
    cfg = load_config()
    http = Http()
    notifier = Notifier(cfg, http)
    state_dir, site_dir = Path(args.state), Path(args.site)
    state_dir.mkdir(parents=True, exist_ok=True)

    if args.test_notification:
        ch = notifier.send("VulnWatch : test", ["Si tu lis ceci, les alertes fonctionnent. ✅"], 3,
                           "https://nvd.nist.gov/", ["white_check_mark"])
        log(f"Notification de test envoyée via : {ch or 'AUCUN CANAL CONFIGURÉ'}")
        if not ch:
            return 1

    now = dt.datetime.now(UTC)
    state = read_json(state_dir / "state.json", {})
    first_run = not state.get("first_run_done")
    db: dict[str, dict] = {r["id"]: r for r in read_json(state_dir / "vulns.json", [])}
    alerts: list[dict] = read_json(state_dir / "alerts.json", [])
    kev_seen: set[str] = set(read_json(state_dir / "kev_seen.json", []))
    health = state.get("health", {})
    prev_scores = {k: v.get("score") for k, v in db.items()}
    log(f"Démarrage — {len(db)} CVE en base, canaux : {', '.join(notifier.channels()) or 'aucun'}")

    def mark(source: str, ok: bool, err: str = ""):
        h = health.setdefault(source, {"fails": 0})
        if ok:
            h.update(fails=0, last_ok=iso(now), last_error="")
        else:
            h["fails"] = h.get("fails", 0) + 1
            h["last_error"] = err[:200]

    # 1. NVD
    new_ids, touched = [], []
    since = parse_dt(state.get("last_nvd_ok"))
    since = (since - dt.timedelta(minutes=15)) if since else now - dt.timedelta(days=cfg["initial_days"])
    keep_from = now - dt.timedelta(days=cfg["retention_days"])
    nvd_ok = False
    try:
        items = fetch_nvd(http, since, now, cfg["nvd_key"])
        skipped = 0
        for it in items:
            rec = parse_nvd(it, now)
            if not rec["id"]:
                continue
            p = parse_dt(rec["published"])
            if not rec["kev"] and p and p < keep_from and rec["id"] not in db:
                skipped += 1  # vieille CVE simplement retouchée
                continue
            old = db.get(rec["id"])
            if old:
                rec["first_seen"] = old.get("first_seen", rec["first_seen"])
                for k in KEEP_ON_UPDATE:
                    if k in old and k not in ("score", "vector", "cvss_version", "score_source", "severity", "severity_en"):
                        rec.setdefault(k, old[k])
                if rec["score"] is None and old.get("score_source") not in (None, "", "NVD") and old.get("score") is not None:
                    for k in ("score", "vector", "cvss_version", "score_source", "severity", "severity_en"):
                        rec[k] = old.get(k)
                rec.pop("vr_checked", None)  # la CVE a changé : on ré-enrichira
            else:
                new_ids.append(rec["id"])
            db[rec["id"]] = rec
            touched.append(rec["id"])
        nvd_ok = True
        mark("NVD", True)
        if NVD_KEY_REJECTED:
            health["NVD"]["last_error"] = "Clé API refusée : passage sans clé (plus lent). Vérifie le secret NVD_API_KEY."
            if not state.get("nvd_key_warned"):
                notifier.send("VulnWatch : clé NVD refusée", ["La NVD refuse la clé du secret NVD_API_KEY (copie incomplète ou clé non activée ?).",
                              "La veille continue sans clé, plus lentement. Recopie la clé reçue par courriel de la NVD."], 3, "", ["warning"])
                state["nvd_key_warned"] = True
        else:
            state.pop("nvd_key_warned", None)
        log(f"NVD : {len(touched)} CVE traitées, {len(new_ids)} nouvelles, {skipped} anciennes ignorées")
    except Exception as e:  # noqa: BLE001
        mark("NVD", False, str(e))
        log(f"NVD indisponible : {e}", "ERREUR")

    # 2. CISA KEV
    kev_recent, new_kev, kev_version = [], [], state.get("kev_version", "")
    try:
        kev = fetch_kev(http)
        kev_version = kev.get("catalogVersion", "")
        idx = {k["cveID"]: k for k in kev["vulnerabilities"]}
        for cid, r in db.items():
            k = idx.get(cid)
            if k:
                r.update(kev=True, kev_added=date_only(k.get("dateAdded")), kev_due=date_only(k.get("dueDate")),
                         ransomware=k.get("knownRansomwareCampaignUse", ""))
                r["vendor"] = r["vendor"] or k.get("vendorProject", "")
                r["product"] = r["product"] or k.get("product", "")
        cut = (now - dt.timedelta(days=cfg["kev_days"])).date()
        kev_recent = [k for k in kev["vulnerabilities"] if (parse_dt(k.get("dateAdded")) or now).date() >= cut]
        if kev_seen:
            new_kev = [k for k in kev["vulnerabilities"] if k["cveID"] not in kev_seen]
        kev_seen = set(idx)
        mark("CISA KEV", True)
        if new_kev:
            log(f"CISA KEV : {len(new_kev)} nouvel(s) ajout(s)")
    except Exception as e:  # noqa: BLE001
        mark("CISA KEV", False, str(e))
        kev_recent = state.get("kev_recent_cache", [])
        log(f"CISA KEV indisponible : {e}", "ERREUR")

    # 3. Rétention (date de publication ; les CVE exploitées restent)
    for cid in [c for c, r in db.items() if not r["kev"] and (parse_dt(r["published"]) or now) < keep_from]:
        del db[cid]
    today = now.strftime("%Y-%m-%d")

    # 4. Exploits publics (Metasploit, Nuclei, Exploit-DB) — cache quotidien
    if cfg["use_exploits"]:
        cache_path = state_dir / "exploits.json"
        cache = read_json(cache_path, {})
        try:
            intel_data, ih = intel.load_exploit_intel(http, cache, today)
            for src, (ok, err) in ih.items():
                mark(src, ok, err)
            write_json(cache_path, cache, compact=True)
        except Exception as e:  # noqa: BLE001
            intel_data = (cache or {}).get("data", {})
            log(f"Exploits publics indisponibles : {e}", "WARN")
        for r in db.values():
            intel.apply_exploit_intel(r, intel_data)

    # 5. CISA Vulnrichment / CVE.org : SSVC, versions affectées, score CNA si la NVD n'a pas encore analysé
    if cfg["use_vulnrichment"]:
        def _urgency(kv):  # d'abord : exploitées, sans score NVD, puis les plus graves, puis les plus récentes
            r = kv[1]
            return (0 if r.get("kev") else 1 if r.get("score") is None else 2 if (r.get("score") or 0) >= 7 else 3,
                    -(r.get("score") or 0), r.get("modified", "") and -int(re.sub(r"\D", "", r["modified"])[:12] or 0))
        todo = [cid for cid, r in sorted(db.items(), key=_urgency)
                if not r.get("vr_checked") or (r.get("score") is None and (parse_dt(r["vr_checked"]) or now) < now - dt.timedelta(hours=12))]
        todo = todo[: cfg["enrich_max"]]
        found = 0
        for cid in todo:
            rec5 = intel.fetch_cve5(http, cid)
            db[cid]["vr_checked"] = iso(now)
            if rec5:
                try:
                    intel.apply_cve5(db[cid], intel.parse_cve5(rec5))
                    found += 1
                except Exception as e:  # noqa: BLE001
                    log(f"Vulnrichment {cid} : format inattendu ({e})", "WARN")
        if todo:
            mark("CISA Vulnrichment", found > 0 or len(todo) < 5, "aucun enregistrement trouvé")
            log(f"CISA Vulnrichment / CVE.org : {found}/{len(todo)} CVE enrichies")

    # 6. GitHub Security Advisories (paquets open source)
    if cfg["use_ghsa"]:
        g_since = parse_dt(state.get("last_ghsa_ok")) or now - dt.timedelta(days=cfg["initial_days"])
        try:
            gh = intel.fetch_ghsa(http, g_since - dt.timedelta(days=1), cfg["gh_token"])
            for cid, g in gh.items():
                if cid in db:
                    intel.apply_ghsa(db[cid], g)
            state["last_ghsa_ok"] = iso(now)
            mark("GitHub Advisories", True)
        except Exception as e:  # noqa: BLE001
            mark("GitHub Advisories", False, str(e))
            log(f"GitHub Advisories indisponible : {e}", "WARN")

    # 7. EPSS (toutes une fois par jour, sinon seulement les modifiées) + historique 8 jours
    ids = list(db) if state.get("epss_full_date") != today else [t for t in touched if t in db]
    if ids:
        try:
            scores = fetch_epss(http, ids)
            for cid, (e, p) in scores.items():
                if cid in db:
                    db[cid]["epss"], db[cid]["epss_pct"] = e, p
                    h = db[cid].setdefault("epss_hist", {})
                    h[today] = e
                    for k in sorted(h)[:-8]:
                        del h[k]
            if state.get("epss_full_date") != today and scores:
                state["epss_full_date"] = today
            mark("EPSS", True)
        except Exception as e:  # noqa: BLE001
            mark("EPSS", False, str(e))

    # 8. Classification experte + inventaire d'actifs
    inventory = classify.parse_inventory(cfg["inventory_csv"])
    if inventory:
        log(f"Inventaire : {len(inventory)} actifs")
    for r in db.values():
        if r.get("severity") in (None, "", "NON ÉVALUÉE") and r.get("score") is not None:
            r["severity"] = sev_from_score(r["score"])
        classify.classify(r)
        classify.apply_inventory(r, classify.match_inventory(r, inventory), cfg["watchlist"])

    # 9. Vue enrichie (priorité P1-P4, justification, risque)
    xcfg = {"critical": cfg["critical"]}
    view = {cid: enrich(dict(r), xcfg, now) for cid, r in db.items()}

    # 10. Tickets GitHub (suivi des corrections)
    tickets_map = {}
    if cfg["tickets"] and cfg["gh_token"] and cfg["gh_repo"]:
        try:
            tickets_map = tickets.list_tickets(http, cfg["gh_token"], cfg["gh_repo"])
            want = ("P1",) if cfg["ticket_min_priority"] == "P1" else ("P1", "P2")
            created = 0
            if not (first_run and cfg["silent_first"]):
                for cid, v in sorted(view.items(), key=lambda kv: priority_key(kv[1]), reverse=True):
                    if v["priority"] in want and cid not in tickets_map and created < 15:
                        tickets_map[cid] = tickets.create_ticket(http, cfg["gh_token"], cfg["gh_repo"], v)
                        created += 1
            mark("Tickets GitHub", True)
            log(f"Tickets : {len(tickets_map)} suivis, {created} créés")
        except Exception as e:  # noqa: BLE001
            mark("Tickets GitHub", False, str(e))
            log(f"Tickets GitHub : échec ({e})", "WARN")
    for cid, t in tickets_map.items():
        if cid in db:
            db[cid]["ticket_status"], db[cid]["ticket_url"] = t["status"], t["url"]
            view[cid]["ticket_status"], view[cid]["ticket_url"] = t["status"], t["url"]

    # 11. Alertes
    sent_keys = {k for a in alerts for k in a.get("keys", [])}
    cand: dict[str, dict] = {}

    def add(cid, key, reason, prio, kev=None):
        if key in sent_keys:
            return
        c = cand.setdefault(cid, {"reasons": [], "keys": [], "prio": 1, "kev": kev})
        if reason not in c["reasons"]:
            c["reasons"].append(reason)
        c["keys"].append(key)
        c["prio"] = max(c["prio"], prio)
        c["kev"] = c["kev"] or kev

    if cfg["alert_kev"]:
        for k in new_kev:
            why = "Ajoutée au catalogue CISA KEV (exploitée activement)"
            if k.get("knownRansomwareCampaignUse") == "Known":
                why += ", utilisée par des rançongiciels"
            add(k["cveID"], "KEV:" + k["cveID"], why, 5, k)
    for cid, v in view.items():
        s_, e_ = v.get("score"), v.get("epss")
        if v["priority"] == "P1":
            add(cid, "P1:" + cid, "Passée en priorité P1", 5)
        if cfg["alert_critical"] and s_ is not None and s_ >= cfg["critical"]:
            prev = prev_scores.get(cid)
            if prev is None or prev < cfg["critical"]:
                add(cid, "CRIT:" + cid, f"Critique (CVSS {s_:.1f})", 5)
        if v.get("ssvc_exploitation") == "Active" and not v.get("kev"):
            add(cid, "SSVC:" + cid, "Exploitation active signalée par la CISA (SSVC)", 5)
        if v.get("msf") and (s_ or 0) >= 7:
            add(cid, "ARME:" + cid, "Module Metasploit public disponible", 4)
        if e_ is not None and e_ >= cfg["epss_alert"]:
            add(cid, "EPSS:" + cid, f"EPSS élevé ({e_:.0%})", 4)
        if v.get("watch") and s_ is not None and s_ >= cfg["watch_min"]:
            add(cid, "PARC:" + cid, "Touche ton parc : " + v["watch"], 4)

    silent = args.no_alerts or (first_run and cfg["silent_first"])
    # Nouvelle version des règles de priorité : les P1 existantes servent de référence (pas d'avalanche)
    if state.get("rules_version") != RULES_VERSION and not silent:
        for cid in list(cand):
            c = cand[cid]
            if c["keys"] == ["P1:" + cid]:
                alerts.append({"date": iso(now), "cve": cid, "reasons": c["reasons"][0], "priority": c["prio"],
                               "channels": "(référence nouvelles règles, non envoyée)", "message": "", "keys": c["keys"]})
                del cand[cid]
            elif "P1:" + cid in c["keys"]:
                c["keys"].remove("P1:" + cid)
                c["reasons"] = [x for x in c["reasons"] if x != "Passée en priorité P1"]
                alerts.append({"date": iso(now), "cve": cid, "reasons": "Passée en priorité P1", "priority": 5,
                               "channels": "(référence nouvelles règles, non envoyée)", "message": "", "keys": ["P1:" + cid]})
    state["rules_version"] = RULES_VERSION
    ordered = sorted(cand.items(), key=lambda kv: (kv[1]["prio"], (view.get(kv[0]) or {}).get("risk") or 0), reverse=True)
    sent_n, overflow = 0, []
    for cid, c in ordered:
        v, k = view.get(cid) or {}, c["kev"] or {}
        vendor = v.get("vendor") or k.get("vendorProject", "")
        product = v.get("product") or k.get("product", "")
        desc = v.get("desc") or k.get("shortDescription", "")
        if len(desc) > 300:
            desc = desc[:297] + "…"
        title = (f"[{v['priority']}] " if v.get("priority") else "") + cid + (f" — {vendor} {product}".rstrip() if (vendor or product) else "")
        lines = []
        if v.get("plain"):
            lines.append(v["plain"])
        if v.get("todo"):
            lines.append("👉 " + v["todo"])
        lines.append("Motif de l'alerte : " + " · ".join(c["reasons"]))
        if v.get("justification"):
            lines.append(f"Pourquoi : {v['justification']}")
        if v.get("score") is not None:
            lines.append(f"Sévérité : {v['severity']} ({v['score']:.1f}{' · ' + v['score_source'] if v.get('score_source') not in (None, '', 'NVD') else ''})"
                         + (f" · EPSS {v['epss']:.1%}" if v.get("epss") is not None else ""))
        if v.get("assets"):
            lines.append(f"Actifs : {v['assets']}" + (f" (versions : {v['asset_versions']})" if v.get("asset_versions") else ""))
        if v.get("versions") or v.get("pkg_ranges"):
            lines.append(f"Versions affectées : {v.get('versions') or v.get('pkg_ranges')}")
        if v.get("pkg_fixed"):
            lines.append(f"Version corrigée : {v['pkg_fixed']}")
        if k.get("dueDate") or v.get("kev_due"):
            lines.append("Échéance CISA : " + date_only(k.get("dueDate") or v.get("kev_due")))
        if desc and not v.get("plain"):
            lines.append(desc)
        if v.get("ref_patch"):
            lines.append("Correctif : " + v["ref_patch"])
        tags = ["fire"] if (v.get("kev") or k) else (["rotating_light"] if c["prio"] >= 5 else ["warning"])
        if silent:
            channels = "(alertes désactivées)" if args.no_alerts else "(référence initiale, non envoyée)"
        elif sent_n < cfg["max_alerts"]:
            channels = notifier.send(title, lines, c["prio"], NVD_DETAIL + cid, tags) or "(aucun canal)"
            if not channels.startswith("("):
                sent_n += 1
        else:
            overflow.append(cid)
            channels = "(regroupée dans le résumé)"
        alerts.append({"date": iso(now), "cve": cid, "reasons": " · ".join(c["reasons"]), "priority": c["prio"],
                       "channels": channels, "message": " | ".join(lines), "keys": c["keys"]})

    if not silent:
        if overflow:
            notifier.send(f"VulnWatch : {len(overflow)} autres alertes",
                          ["Détail dans l'Excel (feuille « Journal des alertes »).", ", ".join(overflow[:40])], 4, "", ["warning"])
        if cfg["digest"] and new_ids:
            news = [view[i] for i in new_ids if i in view]
            cnt = Counter(v["priority"] for v in news)
            top = sorted(news, key=priority_key, reverse=True)[:5]
            lines = [f"P1 : {cnt.get('P1', 0)} · P2 : {cnt.get('P2', 0)} · P3 : {cnt.get('P3', 0)} · P4 : {cnt.get('P4', 0)}"]
            lines += [f"• [{v['priority']}] {v['id']} ({v['score'] if v['score'] is not None else '—'}) {v['vendor']} {v['product']}".rstrip() for v in top]
            notifier.send(f"VulnWatch : {len(news)} nouvelles CVE", lines, 2, "", ["bar_chart"])
    elif first_run and not args.no_alerts:
        notifier.send("VulnWatch est en marche ✅",
                      [f"Base initiale : {len(db)} CVE suivies, {sum(1 for v in view.values() if v['priority'] == 'P1')} en P1.",
                       "Les alertes commencent au prochain passage (environ 1 h)."], 3, "", ["white_check_mark"])

    # Alerte de panne : une source en échec 6 passages de suite (≈ 6 h), une seule fois
    for src, h in health.items():
        if h.get("fails", 0) == 6 and not silent:
            notifier.send(f"VulnWatch : source {src} injoignable",
                          [f"6 échecs consécutifs. Dernière erreur : {h.get('last_error', '')}",
                           "La veille continue avec les autres sources et rattrapera le retard."], 3, "", ["warning"])
    log(f"Alertes : {len(ordered)} candidate(s), {sent_n} envoyée(s){' (mode silencieux)' if silent else ''}")

    # 12. Statistiques quotidiennes (feuille « Tendances »)
    local_today = now.astimezone(ZoneInfo(cfg["tz"]) if ZoneInfo else UTC).strftime("%Y-%m-%d")
    stats = state.get("stats", [])
    day = next((x for x in stats if x["date"] == local_today), None)
    if not day:
        day = {"date": local_today, "new": 0, "critical": 0, "kev_added": 0, "alerts": 0}
        stats.append(day)
    day["new"] += len(new_ids)
    day["critical"] += sum(1 for i in new_ids if (view.get(i, {}).get("score") or 0) >= cfg["critical"])
    day["kev_added"] += len(new_kev)
    day["alerts"] += sent_n
    day["p1"] = sum(1 for v in view.values() if v["priority"] == "P1")
    day["p2"] = sum(1 for v in view.values() if v["priority"] == "P2")
    state["stats"] = stats[-120:]

    # 13. Sauvegarde de l'état
    if nvd_ok:
        state["last_nvd_ok"] = iso(now)
    state.update(first_run_done=True, kev_version=kev_version, health=health, last_run=iso(now),
                 kev_recent_cache=kev_recent if kev_recent else state.get("kev_recent_cache", []))
    # L'état est sauvegardé dans une branche publique : on n'y garde JAMAIS d'information sur tes actifs
    # (l'inventaire et la liste de surveillance sont relus depuis les secrets à chaque passage).
    priv = ("assets", "asset_versions", "asset_owner", "asset_crit", "asset_exposed", "watch")
    write_json(state_dir / "vulns.json", [{k: v for k, v in r.items() if k not in priv} for r in db.values()], compact=True)
    write_json(state_dir / "alerts.json", [sanitize_alert(a) for a in alerts[-5000:]], compact=True)
    write_json(state_dir / "kev_seen.json", sorted(kev_seen), compact=True)
    write_json(state_dir / "state.json", state)

    # 14. Publication
    meta = {"kev_version": kev_version, "health": health, "inventory": inventory, "stats": state["stats"]}
    private_xlsx = build_outputs(site_dir, list(db.values()), kev_recent, alerts, cfg, meta)
    tpl = Path(__file__).with_name("site") / "index.html"
    if tpl.exists():
        shutil.copy(tpl, site_dir / "index.html")

    # 15. Résumé quotidien : notification push + courriel avec l'Excel en pièce jointe
    local_now = now.astimezone(ZoneInfo(cfg["tz"])) if ZoneInfo else now
    due = args.daily_report_now or (local_now.hour >= cfg["daily_hour"] and state.get("daily_sent") != local_today)
    if cfg["daily_report"] and due and not args.no_alerts and not silent:
        p = Counter(v["priority"] for v in view.values())
        notifier.send(f"VulnWatch — point du {local_today}",
                      [f"P1 : {p.get('P1', 0)} · P2 : {p.get('P2', 0)} · exploitées : {sum(1 for v in view.values() if v.get('kev'))} · "
                       f"mon parc : {sum(1 for v in view.values() if v.get('watch'))}",
                       f"Nouvelles CVE hier : {next((x['new'] for x in stats if x['date'] < local_today), 0) if len(stats) > 1 else day['new']}",
                       "Ouvre l'Excel pour la liste « À traiter »."], 3, "", ["clipboard"])
        if notifier.email_ok():
            try:
                text, hb = daily_report_html(list(db.values()), kev_recent, alerts, cfg)
                notifier.send_email(f"[VulnWatch] Rapport du {local_today}", text, hb, private_xlsx)
                log("Rapport quotidien envoyé avec l'Excel en pièce jointe.")
            except Exception as e:  # noqa: BLE001
                log(f"Rapport quotidien : échec ({type(e).__name__}: {e})", "WARN")
        state["daily_sent"] = local_today
        write_json(state_dir / "state.json", state)
    log("Terminé.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="VulnWatch — veille des vulnérabilités")
    ap.add_argument("--state", default="state", help="dossier d'état persistant")
    ap.add_argument("--site", default="public", help="dossier de publication (Pages)")
    ap.add_argument("--test-notification", action="store_true", help="envoie une notification de test")
    ap.add_argument("--no-alerts", action="store_true", help="met à jour sans alerter")
    ap.add_argument("--daily-report-now", action="store_true", help="envoie le rapport quotidien tout de suite")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
