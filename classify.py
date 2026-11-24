"""
Classification experte des vulnérabilités et rapprochement avec l'inventaire d'actifs.

Tags d'impact      : RCE, Pré-authentification, Élévation de privilèges, Contournement d'authentification,
                     Injection SQL, XSS, SSRF, Traversée de répertoire, Désérialisation, Déni de service,
                     Fuite d'informations, Corruption mémoire, Identifiants codés en dur, Zero-click.
Familles d'actifs  : Périmétrique (VPN/pare-feu/passerelles), Navigateur, Système d'exploitation, OT/ICS,
                     Virtualisation/Cloud, Base de données, Messagerie/Collaboration, Serveur web/applicatif,
                     Bibliothèque open source, Mobile, Réseau (routeurs/commutateurs), CMS/plugins, Sécurité (EDR/AV).

Inventaire (secret INVENTAIRE, format CSV, séparateur ; ou ,) :
    Actif;Fournisseur;Produit;Version;Criticite;Expose;Proprietaire
    VPN principal;Fortinet;FortiOS;7.2.5;Haute;Oui;Équipe réseau
"""
from __future__ import annotations

import csv
import io
import re

# --------------------------------------------------------------------------- tags d'impact

CWE_TAGS = {
    "RCE": {"CWE-94", "CWE-95", "CWE-77", "CWE-78", "CWE-502", "CWE-434", "CWE-917", "CWE-1336"},
    "Corruption mémoire": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-415",
                           "CWE-190", "CWE-476", "CWE-843", "CWE-788"},
    "Injection SQL": {"CWE-89", "CWE-564"},
    "XSS": {"CWE-79", "CWE-80"},
    "SSRF": {"CWE-918"},
    "Traversée de répertoire": {"CWE-22", "CWE-23", "CWE-36", "CWE-59"},
    "Désérialisation": {"CWE-502"},
    "Contournement d'authentification": {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-1390", "CWE-305"},
    "Élévation de privilèges": {"CWE-269", "CWE-250", "CWE-266", "CWE-268", "CWE-274", "CWE-648"},
    "Contrôle d'accès défaillant": {"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-732", "CWE-276"},
    "Déni de service": {"CWE-400", "CWE-770", "CWE-674", "CWE-835", "CWE-1333", "CWE-404"},
    "Fuite d'informations": {"CWE-200", "CWE-209", "CWE-532", "CWE-312", "CWE-319", "CWE-359", "CWE-497"},
    "Identifiants codés en dur": {"CWE-798", "CWE-259", "CWE-321"},
    "CSRF": {"CWE-352"},
    "XXE": {"CWE-611"},
}
KW_TAGS = [
    ("RCE", r"remote code execution|execute arbitrary code|arbitrary code execution|command injection|code injection|\bRCE\b|execute arbitrary commands|os command"),
    ("Élévation de privilèges", r"privilege escalation|escalate privileges|elevation of privilege|gain (root|system|administrator)"),
    ("Contournement d'authentification", r"authentication bypass|bypass authentication|unauthenticated access|without authentication"),
    ("Injection SQL", r"sql injection"),
    ("XSS", r"cross[- ]site scripting|\bxss\b"),
    ("SSRF", r"server[- ]side request forgery|\bssrf\b"),
    ("Traversée de répertoire", r"path traversal|directory traversal"),
    ("Désérialisation", r"deseriali[sz]ation"),
    ("Déni de service", r"denial of service|\bdos\b|crash|resource exhaustion"),
    ("Fuite d'informations", r"information disclosure|sensitive information|exposure of"),
    ("Corruption mémoire", r"buffer overflow|heap overflow|stack overflow|use[- ]after[- ]free|out[- ]of[- ]bounds|memory corruption|type confusion"),
    ("Zero-click", r"zero[- ]click|without (any )?user interaction"),
    ("Identifiants codés en dur", r"hard[- ]?coded (credential|password|key)"),
]

FAMILIES = [
    ("Périmétrique (VPN, pare-feu, passerelle)", r"fortios|fortigate|fortiweb|fortimanager|fortiproxy|fortisiem|pan-os|globalprotect|palo alto|"
     r"ivanti|pulse secure|connect secure|citrix|netscaler|f5 |big-ip|sonicwall|sonicos|juniper|junos|check ?point|"
     r"cisco asa|firepower|ftd|anyconnect|secure firewall|watchguard|sophos firewall|zyxel|barracuda|openvpn|"
     r"vpn|firewall|gateway|load balancer|waf\b|expressway"),
    ("Navigateur", r"\bchrome\b|chromium|firefox|safari|microsoft edge|webkit|\bv8\b|blink"),
    ("Système d'exploitation", r"windows|linux kernel|\bkernel\b|macos|ipados|freebsd|red hat enterprise|ubuntu|debian|suse"),
    ("OT / ICS", r"siemens|simatic|sinec|scalance|schneider|modicon|ecostruxure|rockwell|allen[- ]bradley|factorytalk|"
     r"mitsubishi electric|melsec|omron|abb |honeywell|emerson|yokogawa|ge vernova|moxa|phoenix contact|wago|"
     r"delta electronics|advantech|\bplc\b|\bhmi\b|\bscada\b|ics\b"),
    ("Virtualisation / Cloud / Conteneurs", r"vmware|esxi|vcenter|hyper-v|kubernetes|docker|containerd|openshift|proxmox|citrix hypervisor|aws|azure|google cloud"),
    ("Base de données", r"oracle database|mysql|mariadb|postgres|sql server|mongodb|redis|elasticsearch|cassandra"),
    ("Messagerie / Collaboration", r"exchange|outlook|sharepoint|teams|zimbra|roundcube|confluence|jira|gitlab|slack|zoom|webex"),
    ("Serveur web / applicatif", r"apache|tomcat|nginx|\biis\b|weblogic|websphere|jboss|wildfly|struts|spring|php|node\.js|log4j"),
    ("CMS / plugins", r"wordpress|drupal|joomla|magento|prestashop|plugin|\btheme\b"),
    ("Réseau (routeurs, commutateurs, Wi-Fi)", r"ios xe|ios xr|nx-os|router|switch|aruba|ubiquiti|mikrotik|routeros|tp-link|d-link|netgear|access point"),
    ("Sécurité (EDR, AV, IAM)", r"crowdstrike|defender|sentinelone|trend micro|sophos|kaspersky|bitdefender|okta|active directory|keycloak|cyberark"),
    ("Sauvegarde / Stockage", r"veeam|commvault|veritas|netapp|synology|qnap|nas\b"),
    ("Mobile", r"\bandroid\b|iphone|ipad|apple ios"),
]


def classify(rec: dict) -> None:
    cwes = {c.strip() for c in (rec.get("cwe") or "").split(",") if c.strip()}
    desc = (rec.get("desc") or "").lower()
    hay = " ".join([rec.get("vendor") or "", rec.get("product") or "", rec.get("affected") or "",
                    rec.get("packages") or "", desc]).lower()
    tags = []
    for tag, ids in CWE_TAGS.items():
        if cwes & ids:
            tags.append(tag)
    for tag, rx in KW_TAGS:
        if tag not in tags and re.search(rx, desc, re.I):
            tags.append(tag)
    vec = rec.get("vector") or ""
    pre_auth = "PR:N" in vec and "AV:N" in vec
    if pre_auth:
        tags.insert(0, "Pré-authentification à distance")
    if "UI:N" in vec and "AV:N" in vec and "PR:N" in vec and ("RCE" in tags or "Corruption mémoire" in tags):
        if "Zero-click" not in tags:
            tags.append("Zero-click")
    fams = [name for name, rx in FAMILIES if re.search(rx, hay, re.I)]
    if rec.get("packages"):
        fams.append("Bibliothèque open source")
    rec["tags"] = "; ".join(dict.fromkeys(tags))
    rec["family"] = "; ".join(dict.fromkeys(fams[:3]))
    rec["pre_auth_rce"] = "Oui" if pre_auth and ("RCE" in tags or "Corruption mémoire" in tags or "Contournement d'authentification" in tags) else ""


# --------------------------------------------------------------------------- inventaire

CRIT_RANK = {"haute": 3, "critique": 3, "élevée": 3, "elevee": 3, "high": 3, "moyenne": 2, "medium": 2,
             "basse": 1, "faible": 1, "low": 1}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def parse_inventory(text: str) -> list[dict]:
    if not text or not text.strip():
        return []
    sample = text[:2000]
    delim = ";" if sample.count(";") >= sample.count(",") else ","
    rows = []
    rdr = csv.DictReader(io.StringIO(text.strip()), delimiter=delim)
    for row in rdr:
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        g = lambda *ks: next((r[k] for k in ks if r.get(k)), "")  # noqa: E731
        item = {
            "asset": g("actif", "asset", "nom"),
            "vendor": g("fournisseur", "vendor", "editeur", "éditeur"),
            "product": g("produit", "product"),
            "version": g("version"),
            "criticity": g("criticite", "criticité", "criticality") or "Moyenne",
            "exposed": g("expose", "exposé", "exposed", "internet").lower() in ("oui", "yes", "o", "y", "1", "true", "vrai"),
            "owner": g("proprietaire", "propriétaire", "owner", "responsable"),
        }
        if item["product"] or item["vendor"]:
            item["asset"] = item["asset"] or f"{item['vendor']} {item['product']}".strip()
            rows.append(item)
    return rows


def match_inventory(rec: dict, inventory: list[dict]) -> list[dict]:
    if not inventory:
        return []
    hay_struct = _norm(" ".join([rec.get("vendor") or "", rec.get("product") or "", rec.get("affected") or "",
                                 rec.get("packages") or ""]))
    hay_desc = _norm(rec.get("desc") or "")
    hits = []
    for it in inventory:
        p, v = _norm(it["product"]), _norm(it["vendor"])
        if p:
            ok = (f" {p} " in f" {hay_struct} ") or (f" {p} " in f" {hay_desc} " and (not v or f" {v.split()[0]} " in f" {hay_struct} {hay_desc} "))
        else:
            ok = f" {v} " in f" {hay_struct} "
        if ok:
            hits.append(it)
    return hits


def apply_inventory(rec: dict, hits: list[dict], watch_terms: list[str]) -> None:
    hay = f"{rec.get('vendor', '')} {rec.get('product', '')} {rec.get('affected', '')} {rec.get('desc', '')}".lower()
    terms = [w for w in watch_terms if w.lower() in hay]
    rec["assets"] = "; ".join(h["asset"] for h in hits)
    rec["asset_versions"] = "; ".join(f"{h['asset']}: {h['version']}" for h in hits if h.get("version"))
    rec["asset_owner"] = "; ".join(dict.fromkeys(h["owner"] for h in hits if h.get("owner")))
    rec["asset_crit"] = max((CRIT_RANK.get(h["criticity"].lower(), 2) for h in hits), default=0)
    rec["asset_exposed"] = any(h["exposed"] for h in hits)
    names = [h["asset"] for h in hits] + terms
    rec["watch"] = "; ".join(dict.fromkeys(names))
