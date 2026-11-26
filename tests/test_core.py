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


def test_mitigations_only_apply_to_parc():
    mits = classify.parse_mitigations(
        "CVE;Actif;Statut;Date;Responsable;Preuve;Expiration\n"
        "CVE-2026-0001;Tout le parc;Corrigée;2026-11-20;SSI;Patch appliqué;\n"
        "CVE-2026-0002;VPN;Risque accepté;2026-11-01;SSI;Isolé;2026-11-15\n"
    )
    # Sans actif du parc touché (hits=[]), une mitigation ne s'applique jamais
    rem, full, matched = classify.filter_mitigated("CVE-2026-0001", [], mits, today="2026-11-24")
    assert rem == [] and not full and matched == []
    # Avec un actif du parc touché, la mitigation active s'applique
    vpn = {"asset": "VPN", "vendor": "Fortinet", "product": "FortiOS"}
    rem, full, matched = classify.filter_mitigated("CVE-2026-0001", [vpn], mits, today="2026-11-24")
    assert rem == [] and full and len(matched) == 1
    # Une mitigation expirée ne bloque plus l'actif touché
    rem, full, matched = classify.filter_mitigated("CVE-2026-0002", [vpn], mits, today="2026-11-24")
    assert rem == [vpn] and not full and matched == []



def test_version_status():
    rg = [["Fortinet FortiOS", "7.2.0", "<", "7.2.8"], ["Fortinet FortiOS", "7.4.0", "<=", "7.4.3"], ["Fortinet FortiProxy", "7.0.0", "<", "7.0.15"]]
    assert classify.version_status("7.2.5", rg, "FortiOS") == "touchée"
    assert classify.version_status("7.2.8", rg, "FortiOS") == "non touchée"
    assert classify.version_status("7.4.3", rg, "FortiOS") == "touchée"
    assert classify.version_status("7.6.0", rg, "FortiOS") == "non touchée"
    assert classify.version_status("", rg, "FortiOS") == "à vérifier"
    assert classify.version_status("7.2.5", [], "FortiOS") == "à vérifier"
    assert classify.version_status("10.2.9-h1", [["Palo Alto Networks PAN-OS", "10.2.0", "<", "10.2.9-h1"]], "PAN-OS") == "non touchée"
    assert classify.version_status("10.2.7", [["Palo Alto Networks PAN-OS", "10.2.0", "<", "10.2.9-h1"]], "PAN-OS") == "touchée"
    assert classify.version_status("3.1", [["X Y", "0", "<", "*"]], "Y") == "à vérifier"


def test_version_check_removes_patched_assets():
    import json
    r = vw.parse_nvd(nvd_item(cid="CVE-2024-3400", score=None), NOW)
    intel.apply_cve5(r, intel.parse_cve5(json.loads((FIX / "CVE-2024-3400.cve5.json").read_text())))
    assert r["ranges"], "plages structurées attendues"
    inv = classify.parse_inventory("Actif;Fournisseur;Produit;Version;Criticite;Expose\n"
                                   "FW-ancien;Palo Alto Networks;PAN-OS;10.2.5;Haute;Oui\n"
                                   "FW-corrigé;Palo Alto Networks;PAN-OS;10.2.9-h1;Haute;Oui\n"
                                   "FW-inconnu;Palo Alto Networks;PAN-OS;;Haute;Oui\n")
    kept = classify.apply_version_check(r, classify.match_inventory(r, inv))
    assert [h["asset"] for h in kept] == ["FW-ancien", "FW-inconnu"]
    assert "FW-corrigé : non touchée" in r["version_check"]


def test_version_format_mismatch_is_never_hidden():
    rg = [["Microsoft Exchange Server 2019", "15.02.0", "<", "15.02.1544.014"]]
    assert classify.version_status("2019 CU14", rg, "Exchange Server") == "à vérifier"
    assert classify.version_status("23H2", [["Microsoft Windows 11 Version 23H2", "10.0.22631.0", "<", "10.0.22631.4460"]], "Windows 11") == "à vérifier"


CCCS_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Alertes</title>
<item><title>Bulletin de sécurité Fortinet (AV26-0812)</title><link>https://www.cyber.gc.ca/fr/x/av26-0812</link>
<pubDate>Tue, 25 Nov 2026 14:12:00 GMT</pubDate><description>&lt;p&gt;Mises à jour FortiOS (CVE-2026-12345, cve-2026-2345).&lt;/p&gt;</description></item>
<item><title>[Systèmes de contrôle] Bulletin de sécurité Siemens (AV26-0813)</title><link>https://www.cyber.gc.ca/fr/x/av26-0813</link>
<pubDate>Tue, 25 Nov 2026 16:00:00 -0500</pubDate><description>SIMATIC</description></item>
</channel></rss>"""

CCCS_ATOM = """<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Bulletin de sécurité d'Apple (AV26-0900)</title>
<link href="https://www.cyber.gc.ca/fr/x/av26-0900"/><updated>2026-11-26T10:00:00Z</updated><summary>iOS</summary></entry></feed>"""


def test_cccs_parse_rss_and_atom():
    a = intel.parse_cccs_rss(CCCS_SAMPLE)
    assert [x["id"] for x in a] == ["AV26-0812", "AV26-0813"]
    assert a[0]["vendor"] == "Fortinet" and a[0]["cves"] == ["CVE-2026-12345", "CVE-2026-2345"]
    assert a[1]["ics"] and not a[0]["ics"] and a[1]["vendor"] == "Siemens"
    assert a[1]["date"] == "2026-11-25T21:00:00Z"
    b = intel.parse_cccs_rss(CCCS_ATOM)
    assert b[0]["id"] == "AV26-0900" and b[0]["vendor"] == "Apple" and b[0]["url"].endswith("av26-0900")


def test_cccs_bad_payload_fails_safely():
    import pytest
    with pytest.raises(Exception):
        intel.parse_cccs_rss("<html><body>maintenance</body>")  # mal formé : l'appelant marque la source en échec
    with pytest.raises(ValueError):
        intel.parse_cccs_rss('{"erreur": 1}')


def test_cccs_match_inventory():
    a = intel.parse_cccs_rss(CCCS_SAMPLE)
    inv = [{"asset": "FW", "vendor": "Fortinet", "product": "FortiGate"},
           {"asset": "PLC", "vendor": "Siemens AG", "product": "SIMATIC S7-1500"},
           {"asset": "PC", "vendor": "Microsoft", "product": "Windows"}]
    assert intel.match_advisory(a[0], inv) == ["FW"]
    assert intel.match_advisory(a[1], inv) == ["PLC"]
    assert intel.match_advisory(a[0], [], ["fortios"]) == ["fortios"]
