"""
Renseignement complémentaire pour VulnWatch.

  * Exploits publics  : modules Metasploit (rapid7), modèles Nuclei (projectdiscovery), Exploit-DB (OffSec)
                        -> rafraîchis une fois par jour, mis en cache dans l'état.
  * CISA Vulnrichment : enregistrement CVE 5 enrichi par la CISA -> décision SSVC (Exploitation,
                        Automatisable, Impact technique), produits et versions déclarés par l'éditeur (CNA),
                        score CVSS de l'éditeur ou de la CISA quand la NVD n'a pas encore analysé.
  * GitHub Advisories : paquets open source touchés (npm, PyPI, Maven, NuGet, Go…), plage vulnérable
                        et version corrigée.

Chaque source est indépendante : une panne n'empêche jamais le reste de fonctionner.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import re
import time

MSF_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
NUCLEI_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
EDB_URLS = [
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
]
VR_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{bucket}xxx/{cve}.json"
CVEORG_URL = "https://cveawg.mitre.org/api/cve/{cve}"
GHSA_URL = "https://api.github.com/advisories"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
MSF_RANK = {600: "Excellent", 500: "Great", 400: "Good", 300: "Normal", 200: "Average", 100: "Low", 0: "Manual"}


def _log(msg, level="INFO"):
    print(f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S}Z [{level}] {msg}", flush=True)


# --------------------------------------------------------------------------- exploits publics

def parse_msf(data: dict) -> dict:
    out: dict[str, list] = {}
    for m in data.values():
        if m.get("type") not in ("exploit", "auxiliary"):
            continue
        for ref in m.get("references") or []:
            if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                cid = ref.upper()
                out.setdefault(cid, []).append({
                    "module": m.get("fullname", ""),
                    "type": m.get("type", ""),
                    "rank": MSF_RANK.get(m.get("rank"), str(m.get("rank", ""))),
                })
    return out


def parse_nuclei(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json
            j = json.loads(line)
        except ValueError:
            continue
        cid = str(j.get("ID", "")).upper()
        if cid.startswith("CVE-"):
            out[cid] = j.get("file_path", "")
    return out


def parse_edb(text: str) -> dict:
    out: dict[str, list] = {}
    for row in csv.DictReader(io.StringIO(text)):
        codes = row.get("codes") or ""
        for cid in CVE_RE.findall(codes):
            out.setdefault(cid.upper(), []).append(row.get("id", ""))
    return out


def load_exploit_intel(http, cache: dict, today: str) -> tuple[dict, dict]:
    """Renvoie ({cve: {...}}, santé par source). Rafraîchi une fois par jour, sinon cache."""
    health = {}
    if cache.get("date") == today and cache.get("data"):
        return cache["data"], health
    data: dict[str, dict] = {}
    srcs = {}
    try:
        srcs["msf"] = parse_msf(http.get_json(MSF_URL, tries=2, timeout=180))
        health["Metasploit"] = (True, "")
    except Exception as e:  # noqa: BLE001
        health["Metasploit"] = (False, str(e))
    try:
        srcs["nuclei"] = parse_nuclei(http.get_text(NUCLEI_URL, tries=2, timeout=120))
        health["Nuclei"] = (True, "")
    except Exception as e:  # noqa: BLE001
        health["Nuclei"] = (False, str(e))
    edb_ok, last = False, "aucune source"
    for u in EDB_URLS:
        try:
            srcs["edb"] = parse_edb(http.get_text(u, tries=2, timeout=180))
            edb_ok = True
            break
        except Exception as e:  # noqa: BLE001
            last = str(e)
    health["Exploit-DB"] = (edb_ok, "" if edb_ok else last)

    old = (cache.get("data") or {})
    for key in ("msf", "nuclei", "edb"):
        if key not in srcs:  # source en panne : on garde l'ancienne donnée
            for cid, v in old.items():
                if key in v:
                    data.setdefault(cid, {})[key] = v[key]
    for cid, mods in srcs.get("msf", {}).items():
        data.setdefault(cid, {})["msf"] = mods[:5]
    for cid, path in srcs.get("nuclei", {}).items():
        data.setdefault(cid, {})["nuclei"] = path
    for cid, ids in srcs.get("edb", {}).items():
        data.setdefault(cid, {})["edb"] = ids[:10]
    cache.update(date=today, data=data)
    _log(f"Exploits publics : {sum(1 for v in data.values() if 'msf' in v)} CVE avec module Metasploit, "
         f"{sum(1 for v in data.values() if 'nuclei' in v)} avec modèle Nuclei, "
         f"{sum(1 for v in data.values() if 'edb' in v)} sur Exploit-DB")
    return data, health


def apply_exploit_intel(rec: dict, intel: dict) -> None:
    x = intel.get(rec["id"], {})
    msf = x.get("msf") or []
    rec["msf"] = "; ".join(f"{m['module']} ({m['rank']})" for m in msf)
    rec["nuclei"] = "Oui" if x.get("nuclei") else ""
    rec["edb"] = ", ".join(f"EDB-{i}" for i in (x.get("edb") or []))
    if msf:
        rec["exploit_maturity"] = "Arme (Metasploit)"
    elif x.get("edb") or rec.get("exploit_ref"):
        rec["exploit_maturity"] = "Preuve de concept publique"
    elif x.get("nuclei"):
        rec["exploit_maturity"] = "Détection publique (Nuclei)"
    else:
        rec["exploit_maturity"] = ""


# --------------------------------------------------------------------------- CISA Vulnrichment / CVE.org

def _versions_summary(versions: list) -> str:
    parts = []
    for v in versions or []:
        if v.get("status") != "affected":
            continue
        base = v.get("version", "")
        if v.get("lessThan"):
            parts.append(f"{base} → < {v['lessThan']}" if base not in ("", "0", "*") else f"< {v['lessThan']}")
        elif v.get("lessThanOrEqual"):
            parts.append(f"{base} → ≤ {v['lessThanOrEqual']}" if base not in ("", "0", "*") else f"≤ {v['lessThanOrEqual']}")
        elif base:
            parts.append(base)
    return ", ".join(parts[:8]) + (" …" if len(parts) > 8 else "")


def _cvss_from_metrics(metrics: list):
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for m in metrics or []:
            c = m.get(key)
            if c and c.get("baseScore") is not None:
                return float(c["baseScore"]), (c.get("baseSeverity") or "").upper(), c.get("vectorString", ""), key[5:].replace("_", ".")
    return None


def parse_cve5(rec5: dict) -> dict:
    """Extrait d'un enregistrement CVE 5 (Vulnrichment / CVE.org) ce qui est utile à l'analyste."""
    out = {"ssvc_exploitation": "", "ssvc_automatable": "", "ssvc_impact": "", "affected": "", "versions": "",
           "cna_score": None}
    cont = rec5.get("containers", {})
    cna = cont.get("cna", {})
    aff = cna.get("affected") or []
    prods, vers = [], []
    for a in aff[:10]:
        name = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x.lower() != "n/a")
        if name and name not in prods:
            prods.append(name)
        s = _versions_summary(a.get("versions"))
        if s:
            vers.append(f"{a.get('product', '')}: {s}" if len(aff) > 1 else s)
    out["affected"] = "; ".join(prods)
    out["versions"] = " | ".join(vers)[:600]
    if aff:
        out["cna_vendor"] = (aff[0].get("vendor") or "").strip()
        out["cna_product"] = (aff[0].get("product") or "").strip()
    sc = _cvss_from_metrics(cna.get("metrics"))
    src = "Éditeur (CNA)"
    for adp in cont.get("adp") or []:
        for m in adp.get("metrics") or []:
            o = m.get("other") or {}
            if o.get("type") == "ssvc":
                for opt in (o.get("content") or {}).get("options") or []:
                    for k, v in opt.items():
                        if k == "Exploitation":
                            out["ssvc_exploitation"] = v
                        elif k == "Automatable":
                            out["ssvc_automatable"] = v
                        elif k == "Technical Impact":
                            out["ssvc_impact"] = v
        if not sc:
            sc = _cvss_from_metrics(adp.get("metrics"))
            src = (adp.get("providerMetadata") or {}).get("shortName") or "ADP"
    if sc:
        out["cna_score"], out["cna_severity"], out["cna_vector"], out["cna_version"] = sc
        out["cna_score_source"] = src
    return out


def vr_url(cve: str) -> str:
    _, year, num = cve.split("-")
    return VR_URL.format(year=year, bucket=int(num) // 1000, cve=cve)


def fetch_cve5(http, cve: str):
    """Vulnrichment (GitHub) d'abord, puis l'API officielle CVE.org en secours."""
    for url in (vr_url(cve), CVEORG_URL.format(cve=cve)):
        try:
            return http.get_json(url, tries=1, timeout=30, quiet=True)
        except Exception:  # noqa: BLE001
            continue
    return None


SSVC_FR = {"active": "Active", "poc": "Preuve de concept", "none": "Aucune connue",
           "yes": "Oui", "no": "Non", "total": "Totale", "partial": "Partielle"}


def apply_cve5(rec: dict, info: dict) -> None:
    rec["ssvc_exploitation"] = SSVC_FR.get(info.get("ssvc_exploitation", ""), info.get("ssvc_exploitation", ""))
    rec["ssvc_automatable"] = SSVC_FR.get(info.get("ssvc_automatable", ""), info.get("ssvc_automatable", ""))
    rec["ssvc_impact"] = SSVC_FR.get(info.get("ssvc_impact", ""), info.get("ssvc_impact", ""))
    rec["affected"] = info.get("affected", "")
    rec["versions"] = info.get("versions", "")
    if not rec.get("vendor") and info.get("cna_vendor"):
        rec["vendor"] = info["cna_vendor"]
        rec["product"] = info.get("cna_product", "")
    # NVD pas encore analysée : on prend le score de l'éditeur (CNA) ou de la CISA
    if rec.get("score") is None and info.get("cna_score") is not None:
        rec["score"] = info["cna_score"]
        rec["score_source"] = info.get("cna_score_source", "CNA")
        rec["vector"] = rec.get("vector") or info.get("cna_vector", "")
        rec["cvss_version"] = rec.get("cvss_version") or info.get("cna_version", "")
        sev = info.get("cna_severity", "")
        rec["severity_en"] = sev


# --------------------------------------------------------------------------- GitHub Security Advisories

def fetch_ghsa(http, since: dt.datetime, token: str | None, max_pages: int = 10) -> dict:
    """Avis GitHub (revus) modifiés depuis `since`, indexés par CVE."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {"type": "reviewed", "per_page": 100, "modified": f">={since:%Y-%m-%d}", "sort": "updated", "direction": "desc"}
    out: dict[str, dict] = {}
    url = GHSA_URL
    for _ in range(max_pages):
        r = http.get_raw(url, params=params, headers=headers, timeout=60)
        for adv in r.json():
            cid = adv.get("cve_id")
            if not cid:
                continue
            pk, rng, fix = [], [], []
            for v in adv.get("vulnerabilities") or []:
                p = v.get("package") or {}
                name = f"{p.get('ecosystem', '')}:{p.get('name', '')}"
                if name not in pk:
                    pk.append(name)
                if v.get("vulnerable_version_range"):
                    rng.append(v["vulnerable_version_range"])
                fp = v.get("first_patched_version")
                if isinstance(fp, dict):
                    fp = fp.get("identifier")
                if fp:
                    fix.append(str(fp))
            out[cid.upper()] = {"ghsa": adv.get("ghsa_id", ""), "packages": ", ".join(pk[:6]),
                                "ranges": "; ".join(rng[:6]), "fixed": ", ".join(fix[:6]),
                                "url": adv.get("html_url", "")}
        nxt = r.links.get("next", {}).get("url") if hasattr(r, "links") else None
        if not nxt:
            break
        url, params = nxt, None
        time.sleep(0.5)
    _log(f"GitHub Advisories : {len(out)} avis avec CVE depuis {since:%Y-%m-%d}")
    return out


def apply_ghsa(rec: dict, g: dict) -> None:
    rec["ghsa"] = g.get("ghsa", "")
    rec["packages"] = g.get("packages", "")
    rec["pkg_ranges"] = g.get("ranges", "")
    rec["pkg_fixed"] = g.get("fixed", "")
