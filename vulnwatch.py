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

def _env(name: str, default=None):
    v = os.environ.get(name, "")
    v = v.strip() if isinstance(v, str) else v
    return v if v else default


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
        "watchlist": [w.strip() for w in re.split(r"[,;\n]", watch) if w.strip()],
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
    def __init__(self):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = f"VulnWatch/{VERSION} (+https://github.com)"

    def get_json(self, url, params=None, headers=None, tries=4, timeout=120):
        for i in range(1, tries + 1):
            try:
                r = self.s.get(url, params=params, headers=headers, timeout=timeout)
                if r.status_code in (403, 429) or r.status_code >= 500:
                    raise requests.HTTPError(f"HTTP {r.status_code}")
                r.raise_for_status()
                return r.json()
            except Exception as e:  # noqa: BLE001
                log(f"Requête en échec ({e}) tentative {i}/{tries} : {url}", "WARN")
                if i == tries:
                    raise
                time.sleep(min(60, 6 * i * i))

    def post(self, url, **kw):
        kw.setdefault("timeout", 30)
        r = self.s.post(url, **kw)
        r.raise_for_status()
        return r


# --------------------------------------------------------------------------- sources

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
            data = http.get_json(NVD_URL + "?noRejected", params=params, headers=headers)
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

    def channels(self) -> list[str]:
        out = []
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

    def send(self, title: str, lines: list[str], priority: int = 3, url: str = "", tags=None) -> str:
        c, sent = self.cfg, []
        body = "\n".join(lines)
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

from rapport_excel import DETAIL_COLS, build_xlsx, enrich  # noqa: E402

PRIO_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def priority_key(r: dict):
    """Tri du plus urgent au moins urgent (après enrich)."""
    return (-PRIO_ORDER.get(r.get("priority"), 9), r.get("risk") or 0)


def is_priority(r: dict) -> bool:
    return r.get("priority") in ("P1", "P2")


def build_outputs(site: Path, records: list[dict], kev_recent: list[dict], alerts: list[dict],
                  cfg: dict, meta: dict) -> None:
    site.mkdir(parents=True, exist_ok=True)
    tz = ZoneInfo(cfg["tz"]) if ZoneInfo else UTC
    now = dt.datetime.now(UTC)
    xcfg = {"critical": cfg["critical"], "tz": cfg["tz"], "retention_days": cfg["retention_days"], "kev_days": cfg["kev_days"]}
    recs = [enrich(dict(r), xcfg, now) for r in records]
    if cfg["hide_watch"]:
        for r in recs:
            r["watch"] = "✓" if r.get("watch") else ""
    recs.sort(key=lambda r: r["modified"], reverse=True)
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
        "total": len(recs),
        "kev_version": meta.get("kev_version", ""),
        "critical_score": cfg["critical"],
        "health": meta.get("health", {}),
    }
    kev_rows = sorted(kev_recent, key=lambda k: k.get("dateAdded", ""), reverse=True)
    alert_rows = sorted(alerts, key=lambda a: a["date"], reverse=True)[:1000]

    # ---- JSON pour le tableau de bord web
    write_json(site / "data.json", {
        "kpi": kpi,
        "vulns": recs,
        "kev": [{k: v.get(k, "") for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                                            "shortDescription", "requiredAction", "dueDate",
                                            "knownRansomwareCampaignUse")} for v in kev_rows],
        "alerts": alert_rows[:200],
    }, compact=True)

    # ---- CSV (source Power Query) : mêmes colonnes détaillées que l'Excel
    def local(s):
        d = parse_dt(s)
        return d.astimezone(tz).strftime("%Y-%m-%d %H:%M") if d else ""

    with (site / "vulns.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow([h for _, h, _, _ in DETAIL_COLS] + ["Lien NVD"])
        for r in sorted(recs, key=priority_key, reverse=True):
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
        for a in alert_rows:
            w.writerow([local(a["date"]), a["cve"], a["reasons"], a["priority"], a["channels"], a["message"], NVD_DETAIL + a["cve"]])
    with (site / "kev.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["CVE", "Ajoutée le", "Fournisseur", "Produit", "Nom", "Description", "Action requise", "Échéance", "Rançongiciel"])
        for k in kev_rows:
            w.writerow([k.get("cveID"), k.get("dateAdded"), k.get("vendorProject"), k.get("product"),
                        k.get("vulnerabilityName"), k.get("shortDescription"), k.get("requiredAction"),
                        k.get("dueDate"), k.get("knownRansomwareCampaignUse")])

    # ---- Classeur Excel détaillé
    build_xlsx(site / "VulnWatch.xlsx", recs, kev_rows, alert_rows, kpi, xcfg, tz)
    log(f"Sorties écrites dans {site}")


# --------------------------------------------------------------------------- moteur

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
                rec["epss"], rec["epss_pct"] = old.get("epss"), old.get("epss_pct")
            else:
                new_ids.append(rec["id"])
            db[rec["id"]] = rec
            touched.append(rec["id"])
        nvd_ok = True
        mark("NVD", True)
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

    # 3. Liste de surveillance
    wl = [w.lower() for w in cfg["watchlist"]]
    for r in db.values():
        hay = f"{r['vendor']} {r['product']} {r['desc']}".lower()
        r["watch"] = "; ".join(cfg["watchlist"][i] for i, w in enumerate(wl) if w in hay)

    # 4. Rétention (date de publication ; les CVE exploitées restent)
    for cid in [c for c, r in db.items() if not r["kev"] and (parse_dt(r["published"]) or now) < keep_from]:
        del db[cid]

    # 5. EPSS (toutes une fois par jour, sinon seulement les modifiées)
    today = now.strftime("%Y-%m-%d")
    ids = list(db) if state.get("epss_full_date") != today else [t for t in touched if t in db]
    if ids:
        try:
            scores = fetch_epss(http, ids)
            for cid, (e, p) in scores.items():
                if cid in db:
                    db[cid]["epss"], db[cid]["epss_pct"] = e, p
            if state.get("epss_full_date") != today and scores:
                state["epss_full_date"] = today
            mark("EPSS", True)
        except Exception as e:  # noqa: BLE001
            mark("EPSS", False, str(e))

    # 6. Alertes
    sent_keys = {k for a in alerts for k in a.get("keys", [])}
    cand: dict[str, dict] = {}

    def add(cid, key, reason, prio, rec=None, kev=None):
        if key in sent_keys:
            return
        c = cand.setdefault(cid, {"reasons": [], "keys": [], "prio": 1, "rec": rec, "kev": kev})
        c["reasons"].append(reason)
        c["keys"].append(key)
        c["prio"] = max(c["prio"], prio)
        c["rec"] = c["rec"] or rec
        c["kev"] = c["kev"] or kev

    if cfg["alert_kev"]:
        for k in new_kev:
            why = "Exploitée activement (CISA KEV)"
            if k.get("knownRansomwareCampaignUse") == "Known":
                why += ", utilisée par des rançongiciels"
            add(k["cveID"], "KEV:" + k["cveID"], why, 5, db.get(k["cveID"]), k)
    for cid, r in db.items():
        s, e = r["score"], r["epss"]
        if cfg["alert_critical"] and s is not None and s >= cfg["critical"]:
            prev = prev_scores.get(cid)
            if prev is None or prev < cfg["critical"]:
                add(cid, "CRIT:" + cid, f"Critique (CVSS {s:.1f})", 5, r)
        if e is not None and e >= cfg["epss_alert"]:
            add(cid, "EPSS:" + cid, f"EPSS élevé ({e:.0%})", 4, r)
        if r["watch"] and s is not None and s >= cfg["watch_min"]:
            add(cid, "PARC:" + cid, f"Parc surveillé : {r['watch']} (CVSS {s:.1f})", 4, r)

    silent = args.no_alerts or (first_run and cfg["silent_first"])
    ordered = sorted(cand.items(), key=lambda kv: (kv[1]["prio"], (kv[1]["rec"] or {}).get("score") or 0), reverse=True)
    sent_n, overflow = 0, []
    for cid, c in ordered:
        r, k = c["rec"] or {}, c["kev"] or {}
        vendor = r.get("vendor") or k.get("vendorProject", "")
        product = r.get("product") or k.get("product", "")
        desc = r.get("desc") or k.get("shortDescription", "")
        if len(desc) > 350:
            desc = desc[:347] + "…"
        title = cid + (f" — {vendor} {product}".rstrip() if (vendor or product) else "")
        lines = ["Motif : " + " · ".join(c["reasons"])]
        if r.get("score") is not None:
            lines.append(f"Sévérité : {r['severity']} ({r['score']:.1f})")
        if r.get("epss") is not None:
            lines.append(f"EPSS : {r['epss']:.1%}")
        if k.get("dueDate"):
            lines.append("Échéance CISA : " + date_only(k["dueDate"]))
        if k.get("requiredAction"):
            lines.append("Action : " + k["requiredAction"])
        if desc:
            lines.append(desc)
        tags = ["fire"] if any("KEV" in x for x in c["reasons"]) else (["rotating_light"] if c["prio"] >= 5 else ["warning"])
        if silent:
            channels = "(alertes désactivées)" if args.no_alerts else "(référence initiale, non envoyée)"
        elif sent_n < cfg["max_alerts"]:
            channels = notifier.send(title, lines, c["prio"], NVD_DETAIL + cid, tags) or "(aucun canal)"
            sent_n += 1
        else:
            overflow.append(cid)
            channels = "(regroupée dans le résumé)"
        alerts.append({"date": iso(now), "cve": cid, "reasons": " · ".join(c["reasons"]), "priority": c["prio"],
                       "channels": channels, "message": " | ".join(lines), "keys": c["keys"]})

    if not silent:
        if overflow:
            notifier.send(f"VulnWatch : {len(overflow)} autres alertes",
                          ["Détails dans le tableau de bord / Excel.", ", ".join(overflow[:40])], 4, "", ["warning"])
        if cfg["digest"] and new_ids:
            news = [db[i] for i in new_ids if i in db]
            cnt = {s: sum(1 for r in news if r["severity"] == s) for s in ("CRITIQUE", "ÉLEVÉE", "MOYENNE", "NON ÉVALUÉE")}
            top = sorted(news, key=lambda r: r["score"] or 0, reverse=True)[:5]
            lines = [f"Critiques : {cnt['CRITIQUE']} · Élevées : {cnt['ÉLEVÉE']} · Moyennes : {cnt['MOYENNE']} · "
                     f"Non évaluées : {cnt['NON ÉVALUÉE']}"]
            lines += [f"• {r['id']} ({r['score'] if r['score'] is not None else '—'}) {r['vendor']} {r['product']}".rstrip() for r in top]
            notifier.send(f"VulnWatch : {len(news)} nouvelles CVE", lines, 2, "", ["bar_chart"])
    elif first_run and not args.no_alerts:
        notifier.send("VulnWatch est en marche ✅",
                      [f"Base initiale : {len(db)} CVE suivies.",
                       "Les alertes commencent au prochain passage (environ 1 h)."], 3, "", ["white_check_mark"])

    # Alerte de panne : une source en échec 6 passages de suite (≈ 6 h), une seule fois
    for src, h in health.items():
        if h.get("fails", 0) == 6 and not silent:
            notifier.send(f"VulnWatch : source {src} injoignable",
                          [f"6 échecs consécutifs. Dernière erreur : {h.get('last_error', '')}",
                           "La veille continue avec les autres sources et rattrapera le retard."], 3, "", ["warning"])
    log(f"Alertes : {len(ordered)} candidate(s), {sent_n} envoyée(s){' (mode silencieux)' if silent else ''}")

    # 7. Sauvegarde de l'état
    if nvd_ok:
        state["last_nvd_ok"] = iso(now)
    state.update(first_run_done=True, kev_version=kev_version, health=health, last_run=iso(now),
                 kev_recent_cache=kev_recent if kev_recent else state.get("kev_recent_cache", []))
    write_json(state_dir / "vulns.json", list(db.values()), compact=True)
    write_json(state_dir / "alerts.json", alerts[-5000:], compact=True)
    write_json(state_dir / "kev_seen.json", sorted(kev_seen), compact=True)
    write_json(state_dir / "state.json", state)

    # 8. Publication
    meta = {"kev_version": kev_version, "health": health}
    build_outputs(site_dir, list(db.values()), kev_recent, alerts, cfg, meta)
    tpl = Path(__file__).with_name("site") / "index.html"
    if tpl.exists():
        shutil.copy(tpl, site_dir / "index.html")

    # 9. Rapport quotidien par courriel, avec le classeur Excel en pièce jointe
    if notifier.email_ok() and cfg["daily_report"] and not args.no_alerts:
        local_now = now.astimezone(ZoneInfo(cfg["tz"])) if ZoneInfo else now
        today_local = local_now.strftime("%Y-%m-%d")
        if (args.daily_report_now or (local_now.hour >= cfg["daily_hour"] and state.get("daily_sent") != today_local)):
            try:
                text, hb = daily_report_html(list(db.values()), kev_recent, alerts, cfg)
                notifier.send_email(f"[VulnWatch] Rapport du {today_local}", text, hb, site_dir / "VulnWatch.xlsx")
                state["daily_sent"] = today_local
                write_json(state_dir / "state.json", state)
                log("Rapport quotidien envoyé avec l'Excel en pièce jointe.")
            except Exception as e:  # noqa: BLE001
                log(f"Rapport quotidien : échec ({type(e).__name__}: {e})", "WARN")
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
