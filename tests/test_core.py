"""Tests hors ligne de VulnWatch (exécutés avant chaque passage par GitHub Actions)."""
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import classify  # noqa: E402
import intel  # noqa: E402
import rapport_excel as rx  # noqa: E402
import vulnwatch as vw  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
FIX = ROOT / "tests" / "fixtures"


def nvd_item(cid="CVE-2026-0001", score=9.8, sev="CRITICAL", vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             desc="Remote code execution in Fortinet FortiOS SSL-VPN.", cwe="CWE-787", kev=False):
    c = {"id": cid, "published": NOW.strftime("%Y-%m-%dT%H:%M:%S.000"), "lastModified": NOW.strftime("%Y-%m-%dT%H:%M:%S.000"),
         "vulnStatus": "Analyzed", "sourceIdentifier": "psirt@fortinet.com",
         "descriptions": [{"lang": "en", "value": desc}],
         "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": vec}}]} if score else {},
         "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
         "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}]}]}],
         "references": [{"url": "https://fortiguard.com/psirt/FG-IR-26-001", "tags": ["Vendor Advisory", "Patch"]},
                        {"url": "https://github.com/x/poc", "tags": ["Exploit"]}]}
    if kev:
        c["cisaExploitAdd"], c["cisaActionDue"] = "2026-11-18", "2026-12-09"
    return {"cve": c}


def test_parse_nvd_fields():
    r = vw.parse_nvd(nvd_item(), NOW)
    assert r["id"] == "CVE-2026-0001" and r["score"] == 9.8 and r["severity"] == "CRITIQUE"
    assert r["vendor"] == "fortinet" and r["product"] == "fortios"
    assert r["ref_patch"].startswith("https://fortiguard") and r["exploit_ref"]
    assert r["source"] == "fortinet.com"


def test_parse_cve5_vulnrichment():
    info = intel.parse_cve5(json.loads((FIX / "CVE-2024-3400.cve5.json").read_text()))
    assert info["ssvc_exploitation"] == "active" and info["ssvc_automatable"] == "yes"
    assert "PAN-OS" in info["affected"] and "10.2.9-h1" in info["versions"]
    assert info["cna_score"] == 10.0


def test_cna_score_when_nvd_missing():
    r = vw.parse_nvd(nvd_item(cid="CVE-2024-3400", score=None), NOW)
    assert r["score"] is None
    intel.apply_cve5(r, intel.parse_cve5(json.loads((FIX / "CVE-2024-3400.cve5.json").read_text())))
    assert r["score"] == 10.0 and r["score_source"] and r["ssvc_exploitation"] == "Active"


def test_exploit_sources_parsers():
    msf = intel.parse_msf({"x": {"type": "exploit", "fullname": "exploit/linux/http/demo", "rank": 600, "references": ["CVE-2026-0001", "URL-x"]}})
    assert msf["CVE-2026-0001"][0]["rank"] == "Excellent"
    nuc = intel.parse_nuclei('{"ID":"CVE-2026-0001","file_path":"http/cves/2026/CVE-2026-0001.yaml"}\n')
    assert "CVE-2026-0001" in nuc
    edb = intel.parse_edb("id,file,description,codes\n51234,x,y,CVE-2026-0001;OSVDB-1\n")
    assert edb["CVE-2026-0001"] == ["51234"]
    r = vw.parse_nvd(nvd_item(), NOW)
    intel.apply_exploit_intel(r, {"CVE-2026-0001": {"msf": msf["CVE-2026-0001"], "nuclei": "p", "edb": ["51234"]}})
    assert r["exploit_maturity"].startswith("Arme") and r["edb"] == "EDB-51234"


def test_classification_and_inventory():
    r = vw.parse_nvd(nvd_item(), NOW)
    classify.classify(r)
    assert "Pré-authentification à distance" in r["tags"] and "Périmétrique" in r["family"] and r["pre_auth_rce"] == "Oui"
    inv = classify.parse_inventory("Actif;Fournisseur;Produit;Version;Criticite;Expose;Proprietaire\n"
                                   "VPN;Fortinet;FortiOS;7.2.5;Haute;Oui;Réseau\nERP;SAP;NetWeaver;7.5;Moyenne;Non;ERP\n")
    assert len(inv) == 2 and inv[0]["exposed"]
    hits = classify.match_inventory(r, inv)
    assert [h["asset"] for h in hits] == ["VPN"]
    classify.apply_inventory(r, hits, [])
    assert r["asset_crit"] == 3 and r["asset_exposed"]


def test_cisco_ios_is_not_mobile():
    r = vw.parse_nvd(nvd_item(desc="Cisco IOS XE web UI privilege escalation"), NOW)
    r["vendor"], r["product"] = "cisco", "ios xe"
    classify.classify(r)
    assert "Mobile" not in r["family"]


def test_priority_rules():
    base = vw.parse_nvd(nvd_item(score=7.5, sev="HIGH", vec="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", desc="Local issue"), NOW)
    base["exploit_ref"] = ""
    assert rx.enrich(dict(base), {"critical": 9}, NOW)["priority"] == "P3"
    kev = dict(base, kev=True)
    e = rx.enrich(kev, {"critical": 9}, NOW)
    assert e["priority"] == "P1" and "KEV" in e["justification"] and 0 <= e["risk"] <= 100
    crit = vw.parse_nvd(nvd_item(score=9.8), NOW)
    classify.classify(crit)
    crit["exploit_ref"] = ""
    assert rx.enrich(dict(crit), {"critical": 9}, NOW)["priority"] == "P2"  # critique pré-auth sans exploit : P2
    assert rx.enrich(dict(crit, epss=0.2), {"critical": 9}, NOW)["priority"] == "P1"  # + EPSS ≥ 10 % : P1
    low = vw.parse_nvd(nvd_item(score=4.3, sev="MEDIUM", vec="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", desc="minor"), NOW)
    low["exploit_ref"] = ""
    assert rx.enrich(low, {"critical": 9}, NOW)["priority"] == "P4"


def test_excel_build_and_encryption(tmp_path):
    recs = []
    for i, sc in enumerate((9.8, 7.5, 5.0, None)):
        r = vw.parse_nvd(nvd_item(cid=f"CVE-2026-000{i}", score=sc, sev=None if sc is None else "HIGH"), NOW)
        classify.classify(r)
        recs.append(rx.enrich(r, {"critical": 9}, NOW))
    kpi = {"updated": vw.iso(NOW), "new_24h": 4, "new_7d": 4, "critical_7d": 1, "kev_7d": 0, "kev_version": "t"}
    hist = [{"date": "2026-11-23", "new": 3, "critical": 1, "kev_added": 0, "p1": 1, "p2": 1, "alerts": 2},
            {"date": "2026-11-24", "new": 4, "critical": 1, "kev_added": 1, "p1": 2, "p2": 1, "alerts": 1}]
    out = tmp_path / "v.xlsx"
    rx.build_xlsx(out, recs, [], [], kpi, {"critical": 9, "tz": "America/Toronto"}, dt.timezone.utc, [], hist)
    import openpyxl
    wb = openpyxl.load_workbook(out)
    assert "Vues expertes" in wb.sheetnames and "Tendances" in wb.sheetnames and "Comprendre" in wb.sheetnames
    assert wb.sheetnames[0] == "Synthèse"
    enc = tmp_path / "e.xlsx"
    vw.encrypt_xlsx(out, enc, "Mot-de-passe-1")
    import msoffcrypto
    assert msoffcrypto.OfficeFile(enc.open("rb")).is_encrypted()


def test_versions_summary():
    s = intel._versions_summary([{"status": "affected", "version": "0", "lessThan": "2.4.1"},
                                 {"status": "unaffected", "version": "3.0"}, {"status": "affected", "version": "1.2.3"}])
    assert s == "< 2.4.1, 1.2.3"


def test_plain_language():
    import explain
    r = vw.parse_nvd(nvd_item(kev=True), NOW)
    classify.classify(r)
    r["watch"], r["assets"] = "PareFeu-Siege-42", "PareFeu-Siege-42"
    e = rx.enrich(r, {"critical": 9}, NOW)
    assert "sans compte ni mot de passe" in e["plain"] and "vraies attaques" in e["plain"] and "PareFeu-Siege-42" in e["plain"]
    assert e["todo"].startswith("URGENT")
    assert "PareFeu-Siege-42" not in explain.en_clair(dict(e, assets=""), show_assets=False)
    txt = " ".join(explain.synthese([e], {"new_24h": 1, "critical_7d": 1, "kev_7d": 0}))
    assert "1 demandent une action urgente" in txt


def test_sanitize_alert_removes_assets():
    a = {"message": "Une faille… Elle concerne ton parc : VPN principal (version installée : 7.2). | Actifs : VPN principal | x",
         "reasons": "Touche ton parc : VPN principal"}
    out = vw.sanitize_alert(a)
    assert "VPN principal" not in out["message"] and "VPN principal" not in out["reasons"]


def test_settings_file():
    cfg = vw.load_config()
    assert cfg["critical"] == 9.0 and isinstance(cfg["watchlist"], list)


def test_control_characters_do_not_break_excel(tmp_path):
    r = vw.parse_nvd(nvd_item(desc="SolarWinds Serv-U\x0b was found\x01 to be affected"), NOW)
    assert "\x0b" not in r["desc"]
    r["desc"] = "Texte avec caractère interdit \x0b ici"   # même si une source en introduit un plus tard
    r["vendor"] = "Ven\x02dor"
    classify.classify(r)
    rec = rx.enrich(r, {"critical": 9}, NOW)
    kpi = {"updated": vw.iso(NOW), "new_24h": 1, "new_7d": 1, "critical_7d": 0, "kev_7d": 0, "kev_version": "t"}
    rx.build_xlsx(tmp_path / "x.xlsx", [rec], [{"cveID": "CVE-1", "shortDescription": "a\x0bb"}],
                  [{"date": vw.iso(NOW), "cve": "CVE-1", "reasons": "x\x0b", "priority": 5, "channels": "ntfy", "message": "m\x0b"}],
                  kpi, {"critical": 9, "tz": "America/Toronto"}, dt.timezone.utc, [], [])
    assert (tmp_path / "x.xlsx").exists()
