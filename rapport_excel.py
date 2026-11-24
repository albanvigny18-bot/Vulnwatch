"""
Classeur Excel détaillé de VulnWatch.

Feuilles (dans l'ordre) :
  1. Tableau de bord     indicateurs, graphiques, top priorités, dernières alertes
  2. À traiter (P1-P2)   ce qui demande une action, du plus urgent au moins urgent
  3. Exploitées (KEV)    CVE de la base présentes au catalogue CISA KEV
  4. Mon parc            CVE qui touchent la liste de surveillance
  5. Nouvelles 24 h      CVE apparues dans les dernières 24 h
  6. Toutes les CVE      la base complète (30 jours par défaut)
  7. Par fournisseur     synthèse par éditeur : volumes, sévérités, pire score
  8. Catalogue KEV       ajouts récents au catalogue CISA (90 jours)
  9. Journal des alertes chaque alerte envoyée, avec motif et canaux
 10. Guide               signification de chaque colonne et des niveaux de priorité
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from pathlib import Path

import explain
from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.formatting.rule import CellIsRule, ColorScaleRule, FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

UTC = dt.timezone.utc
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"

# --------------------------------------------------------------------------- référentiels

CWE_FR = {
    "CWE-20": "Validation d'entrée incorrecte", "CWE-22": "Traversée de répertoire",
    "CWE-77": "Injection de commande", "CWE-78": "Injection de commande système (OS)",
    "CWE-79": "Cross-site scripting (XSS)", "CWE-89": "Injection SQL",
    "CWE-94": "Injection de code", "CWE-119": "Dépassement de tampon mémoire",
    "CWE-120": "Dépassement de tampon classique", "CWE-121": "Dépassement de pile",
    "CWE-122": "Dépassement de tas", "CWE-125": "Lecture hors limites",
    "CWE-190": "Dépassement d'entier", "CWE-200": "Divulgation d'informations",
    "CWE-269": "Gestion incorrecte des privilèges", "CWE-276": "Permissions par défaut incorrectes",
    "CWE-284": "Contrôle d'accès incorrect", "CWE-285": "Autorisation incorrecte",
    "CWE-287": "Authentification incorrecte", "CWE-288": "Contournement d'authentification",
    "CWE-295": "Validation de certificat incorrecte", "CWE-306": "Authentification manquante (fonction critique)",
    "CWE-307": "Tentatives d'authentification non limitées", "CWE-312": "Stockage en clair d'informations sensibles",
    "CWE-319": "Transmission en clair d'informations sensibles", "CWE-321": "Clé de chiffrement codée en dur",
    "CWE-345": "Vérification d'authenticité insuffisante", "CWE-352": "Falsification de requête (CSRF)",
    "CWE-362": "Condition de concurrence", "CWE-400": "Consommation de ressources non contrôlée (DoS)",
    "CWE-401": "Fuite de mémoire", "CWE-415": "Double libération",
    "CWE-416": "Utilisation après libération", "CWE-427": "Chemin de recherche non contrôlé",
    "CWE-434": "Téléversement de fichier dangereux", "CWE-476": "Déréférencement de pointeur nul",
    "CWE-502": "Désérialisation de données non fiables", "CWE-522": "Identifiants insuffisamment protégés",
    "CWE-532": "Informations sensibles dans les journaux", "CWE-601": "Redirection ouverte",
    "CWE-611": "Entités externes XML (XXE)", "CWE-639": "Contournement d'autorisation par clé (IDOR)",
    "CWE-668": "Exposition d'une ressource à la mauvaise sphère", "CWE-669": "Transfert de ressource incorrect",
    "CWE-693": "Défaillance d'un mécanisme de protection", "CWE-732": "Permissions incorrectes sur une ressource critique",
    "CWE-770": "Allocation de ressources sans limite", "CWE-787": "Écriture hors limites",
    "CWE-798": "Identifiants codés en dur", "CWE-862": "Autorisation manquante",
    "CWE-863": "Autorisation incorrecte", "CWE-918": "Falsification de requête côté serveur (SSRF)",
    "CWE-1021": "Superposition d'interface (clickjacking)", "CWE-1321": "Pollution de prototype",
}

VEC = {
    "AV": ("Vecteur d'attaque", {"N": "Réseau (à distance)", "A": "Réseau adjacent", "L": "Local", "P": "Physique"}),
    "AC": ("Complexité", {"L": "Faible", "H": "Élevée"}),
    "AT": ("Prérequis d'attaque", {"N": "Aucun", "P": "Présents"}),
    "PR": ("Privilèges requis", {"N": "Aucun", "L": "Faibles", "H": "Élevés"}),
    "UI": ("Interaction utilisateur", {"N": "Aucune", "R": "Requise", "P": "Passive", "A": "Active"}),
}
CIA = {"H": "Élevé", "L": "Faible", "N": "Aucun"}

PRIORITY_ACTION = {
    "P1": "Corriger immédiatement (sous 48 h)",
    "P2": "Corriger sous 7 jours",
    "P3": "Planifier sous 30 jours",
    "P4": "Surveiller",
}

# --------------------------------------------------------------------------- enrichissement


def _dt(v):
    if not v:
        return None
    s = str(v).strip().replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = dt.datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC)


def parse_vector(vector: str) -> dict:
    out = {"av": "", "ac": "", "pr": "", "ui": "", "cia": ""}
    if not vector:
        return out
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    for k, key in (("AV", "av"), ("AC", "ac"), ("PR", "pr"), ("UI", "ui")):
        if k in parts:
            out[key] = VEC[k][1].get(parts[k], parts[k])
    c = parts.get("VC", parts.get("C"))
    i = parts.get("VI", parts.get("I"))
    a = parts.get("VA", parts.get("A"))
    if c or i or a:
        out["cia"] = f"C:{CIA.get(c, c or '?')} / I:{CIA.get(i, i or '?')} / D:{CIA.get(a, a or '?')}"
    return out


def _soon(r, days):
    d = _dt(r.get("kev_due"))
    return bool(d) and d <= dt.datetime.now(UTC) + dt.timedelta(days=days)


EXPERT_QUERIES = [
    ("RCE pré-auth", "Exécution de code ou prise de contrôle à distance sans authentification (CVSS ≥ 7)",
     lambda r: r.get("pre_auth_rce") == "Oui" and (r.get("score") or 0) >= 7),
    ("Exploitées activement", "Au catalogue CISA KEV ou SSVC « Exploitation : Active »",
     lambda r: bool(r.get("kev")) or r.get("ssvc_exploitation") == "Active"),
    ("Arme Metasploit", "Un module Metasploit public existe : exploitation à la portée de tous",
     lambda r: bool(r.get("msf"))),
    ("PoC public", "Preuve de concept publique (Exploit-DB, référence NVD « Exploit » ou SSVC « PoC »)",
     lambda r: (r.get("exploit_maturity") or "").startswith("Preuve") or r.get("ssvc_exploitation") == "Preuve de concept"),
    ("Rançongiciels", "Failles utilisées dans des campagnes de rançongiciel (CISA)",
     lambda r: r.get("ransomware") == "Known"),
    ("Échéance CISA ≤ 7 j", "Failles KEV dont l'échéance de correction CISA est dépassée ou dans moins de 7 jours",
     lambda r: bool(r.get("kev")) and _soon(r, 7)),
    ("Périmétrique", "VPN, pare-feu, passerelles, équilibreurs : la porte d'entrée favorite des attaquants (CVSS ≥ 7)",
     lambda r: "Périmétrique" in (r.get("family") or "") and (r.get("score") or 0) >= 7),
    ("OT / ICS", "Automates, SCADA, IHM, équipements industriels",
     lambda r: "OT / ICS" in (r.get("family") or "")),
    ("Microsoft", "Produits Microsoft (Windows, Exchange, Office, Edge…) — utile au Patch Tuesday",
     lambda r: "microsoft" in (r.get("vendor") or "").lower()),
    ("Navigateurs", "Chrome, Firefox, Safari, Edge, moteurs JavaScript",
     lambda r: "Navigateur" in (r.get("family") or "")),
    ("Virtualisation / Cloud", "Hyperviseurs, vCenter, conteneurs, Kubernetes, cloud",
     lambda r: "Virtualisation" in (r.get("family") or "")),
    ("Messagerie / Collab.", "Exchange, SharePoint, Confluence, GitLab, Zimbra…",
     lambda r: "Messagerie" in (r.get("family") or "")),
    ("Open source (GHSA)", "Bibliothèques et paquets (npm, PyPI, Maven, NuGet, Go…) avec version corrigée",
     lambda r: bool(r.get("packages"))),
    ("Zero-click", "Exploitable sans aucune interaction de l'utilisateur, à distance",
     lambda r: "Zero-click" in (r.get("tags") or "")),
    ("Contournement d'auth.", "Contournement d'authentification (CVSS ≥ 7)",
     lambda r: "Contournement d'authentification" in (r.get("tags") or "") and (r.get("score") or 0) >= 7),
    ("Élévation de privilèges", "Élévation de privilèges : maillon clé des chaînes d'attaque",
     lambda r: "Élévation de privilèges" in (r.get("tags") or "")),
    ("EPSS en hausse", "Probabilité d'exploitation en hausse d'au moins 5 points sur 7 jours",
     lambda r: (r.get("epss_delta") or 0) >= 0.05),
    ("EPSS ≥ 10 %", "Probabilité d'exploitation à 30 jours d'au moins 10 % (top ~ 3 % des CVE)",
     lambda r: (r.get("epss") or 0) >= 0.1),
    ("Critiques sans correctif", "CVSS ≥ 9 sans correctif ni version corrigée référencés : mesures de contournement à prévoir",
     lambda r: (r.get("score") or 0) >= 9 and not (r.get("ref_patch") or r.get("pkg_fixed"))),
    ("Nouvelles critiques 24 h", "Critiques détectées dans les dernières 24 heures",
     lambda r: r.get("new") == "Oui" and (r.get("score") or 0) >= 9),
]


SEV_FROM_EN = {"CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉE", "MEDIUM": "MOYENNE", "LOW": "FAIBLE", "NONE": "AUCUNE"}
CRIT_LABEL = {3: "Haute", 2: "Moyenne", 1: "Basse", 0: ""}


def sev_from_score(s):
    if s is None:
        return "NON ÉVALUÉE"
    return "CRITIQUE" if s >= 9 else "ÉLEVÉE" if s >= 7 else "MOYENNE" if s >= 4 else "FAIBLE" if s > 0 else "AUCUNE"


def enrich(r: dict, cfg: dict, now: dt.datetime) -> dict:
    """Priorité P1-P4 justifiée, action, score de risque, décodage CVSS, CWE en clair, ancienneté, tendance EPSS."""
    s, e = r.get("score"), r.get("epss")
    if r.get("severity") in (None, "", "NON ÉVALUÉE") and s is not None:
        r["severity"] = SEV_FROM_EN.get((r.get("severity_en") or "").upper()) or sev_from_score(s)
    crit = cfg.get("critical", 9.0)
    s0 = s or 0
    exploited = bool(r.get("kev")) or r.get("ssvc_exploitation") == "Active"
    weapon = bool(r.get("msf"))
    poc = bool(r.get("edb") or r.get("exploit_ref")) or r.get("ssvc_exploitation") == "Preuve de concept"
    asset = bool(r.get("watch"))
    acrit = r.get("asset_crit") or (2 if asset else 0)
    exposed = bool(r.get("asset_exposed"))
    preauth = r.get("pre_auth_rce") == "Oui"
    autom = r.get("ssvc_automatable") == "Oui" and r.get("ssvc_impact") == "Totale"

    why = []
    if r.get("kev"):
        why.append("Exploitée activement (CISA KEV)")
    elif r.get("ssvc_exploitation") == "Active":
        why.append("Exploitation active (CISA SSVC)")
    if r.get("ransomware") == "Known":
        why.append("Utilisée par des rançongiciels")
    if weapon:
        why.append("Module Metasploit public")
    elif poc:
        why.append("Exploit public (PoC)")
    if preauth:
        why.append("Exploitable à distance sans authentification")
    if autom:
        why.append("Automatisable, impact total (SSVC)")
    if asset:
        why.append("Touche ton parc" + (" (actif exposé Internet)" if exposed else "") + (" — criticité haute" if acrit >= 3 else ""))
    if s is not None and s >= crit:
        why.append(f"CVSS critique {s:.1f}")
    elif s is not None and s >= 7:
        why.append(f"CVSS élevé {s:.1f}")
    if (e or 0) >= 0.1:
        why.append(f"EPSS {e:.0%}")

    if exploited or (weapon and s0 >= 7) or (s0 >= crit and ((e or 0) >= 0.1 or poc)) \
            or (asset and s0 >= crit and (preauth or exposed or poc)) \
            or (asset and exposed and s0 >= 7 and (poc or preauth or weapon)):
        p = "P1"
    elif s0 >= crit or (e or 0) >= 0.5 or (poc and s0 >= 7) or (asset and s0 >= 7) or (autom and s0 >= 7):
        p = "P2"
    elif s0 >= 7 or (e or 0) >= 0.1 or asset or poc or weapon:
        p = "P3"
    else:
        p = "P4"
    risk = (s if s is not None else 5.0) * 6 + (e or 0) * 20 + (15 if exploited else 0) \
        + (10 if weapon else 5 if poc else 0) + (5 if r.get("ransomware") == "Known" else 0) \
        + acrit * 3 + (5 if exposed else 0) + (5 if preauth else 0)
    pub = _dt(r.get("published"))
    first = _dt(r.get("first_seen"))
    cwes = [c.strip() for c in (r.get("cwe") or "").split(",") if c.strip()]
    hist = r.get("epss_hist") or {}
    delta = None
    if e is not None and hist:
        old_keys = sorted(k for k in hist if k <= (now - dt.timedelta(days=6)).strftime("%Y-%m-%d")) or sorted(hist)
        ref = hist.get(old_keys[-1]) if old_keys else None
        if ref is not None:
            delta = e - ref
    r.update(parse_vector(r.get("vector", "")))
    r.update(
        priority=p,
        action=PRIORITY_ACTION[p],
        justification=" · ".join(why) or "Aucun facteur aggravant connu",
        risk=int(round(min(100, risk))),
        age_days=(now - pub).days if pub else None,
        new="Oui" if first and first >= now - dt.timedelta(days=1) else "",
        cwe_name="; ".join(CWE_FR.get(c, c) for c in cwes),
        epss_delta=delta,
        asset_crit_label=CRIT_LABEL.get(r.get("asset_crit") or 0, ""),
        asset_exposed_label="Oui" if exposed else ("Non" if asset else ""),
        score_source=r.get("score_source") or ("NVD" if s is not None else ""),
        patch_available="Oui" if (r.get("ref_patch") or r.get("pkg_fixed")) else "",
    )
    r["views"] = "; ".join(name for name, _, f in EXPERT_QUERIES if f(r))
    r["plain"] = explain.en_clair(r, show_assets=True)
    r["todo"] = explain.que_faire(r)
    return r


# --------------------------------------------------------------------------- colonnes

# (clé, en-tête, largeur, type)   type : txt | num1 | pct | int | date | datetime | yesno | link
DETAIL_COLS = [
    # --- décider
    ("id", "CVE", 17, "link"),
    ("priority", "Priorité", 9, "txt"),
    ("plain", "En clair (pour tous)", 70, "wrap"),
    ("todo", "Que faire", 55, "wrap"),
    ("action", "Délai", 30, "txt"),
    ("justification", "Pourquoi cette priorité", 50, "txt"),
    ("risk", "Score de risque (0-100)", 11, "int"),
    ("severity", "Sévérité", 13, "txt"),
    ("score", "CVSS", 7, "num1"),
    ("score_source", "Source du score", 12, "txt"),
    ("epss", "EPSS (proba. 30 j)", 10, "pct"),
    ("epss_delta", "Δ EPSS 7 j", 9, "pctd"),
    ("epss_pct", "Percentile EPSS", 10, "pct"),
    ("kev", "Exploitée (KEV)", 10, "yesno"),
    ("ssvc_exploitation", "Exploitation (SSVC)", 14, "txt"),
    ("exploit_maturity", "Maturité de l'exploit", 22, "txt"),
    ("ransomware", "Rançongiciel", 11, "txt"),
    ("patch_available", "Correctif disponible", 10, "txt"),
    # --- mon parc
    ("watch", "Mon parc (actifs)", 24, "txt"),
    ("asset_crit_label", "Criticité actif", 10, "txt"),
    ("asset_exposed_label", "Actif exposé Internet", 10, "txt"),
    ("asset_versions", "Version installée", 22, "txt"),
    ("asset_owner", "Responsable", 18, "txt"),
    ("new", "Nouveau (24 h)", 9, "txt"),
    # --- contexte
    ("tags", "Type d'impact", 36, "txt"),
    ("family", "Famille de produit", 30, "txt"),
    ("views", "Vues expertes", 36, "txt"),
    ("vendor", "Fournisseur", 18, "txt"),
    ("product", "Produit", 22, "txt"),
    ("versions", "Versions affectées (éditeur)", 40, "txt"),
    ("packages", "Paquets open source", 28, "txt"),
    ("pkg_ranges", "Versions vulnérables (paquet)", 24, "txt"),
    ("pkg_fixed", "Version corrigée (paquet)", 16, "txt"),
    ("cwe_name", "Type de faiblesse", 32, "txt"),
    ("desc", "Description", 90, "txt"),
    # --- technique
    ("av", "Vecteur d'attaque", 18, "txt"),
    ("ac", "Complexité", 10, "txt"),
    ("pr", "Privilèges requis", 11, "txt"),
    ("ui", "Interaction utilisateur", 12, "txt"),
    ("cia", "Impact C / I / D", 30, "txt"),
    ("ssvc_automatable", "Automatisable (SSVC)", 11, "txt"),
    ("ssvc_impact", "Impact technique (SSVC)", 11, "txt"),
    ("msf", "Modules Metasploit", 40, "txt"),
    ("nuclei", "Modèle Nuclei", 9, "txt"),
    ("edb", "Exploit-DB", 16, "txt"),
    # --- suivi
    ("ticket_status", "Suivi (ticket)", 14, "txt"),
    ("ticket_url", "Lien du ticket", 14, "url"),
    ("published", "Publiée le", 16, "datetime"),
    ("modified", "Modifiée le", 16, "datetime"),
    ("age_days", "Âge (jours)", 8, "int"),
    ("kev_due", "Échéance CISA", 12, "date"),
    ("ref_patch", "Correctif / avis éditeur", 40, "url"),
    ("ghsa", "Avis GitHub (GHSA)", 22, "txt"),
    ("cwe", "CWE", 12, "txt"),
    ("status", "Statut NVD", 16, "txt"),
    ("source", "Émetteur (CNA)", 22, "txt"),
    ("cvss_version", "Version CVSS", 8, "txt"),
    ("vector", "Vecteur CVSS", 44, "txt"),
]

GUIDE = [
    ("Priorité", "P1 (sous 48 h) : exploitée activement (KEV ou SSVC « Active »), OU module Metasploit et CVSS ≥ 7, OU critique avec EPSS ≥ 10 % "
                 "ou exploit public, OU critique sur ton parc (pré-auth, exposé ou exploit public), OU CVSS ≥ 7 avec exploit/pré-auth sur un actif exposé. "
                 "P2 (7 j) : critique, OU EPSS ≥ 50 %, OU exploit public et CVSS ≥ 7, OU CVSS ≥ 7 sur ton parc, OU SSVC automatisable à impact total. "
                 "P3 (30 j) : CVSS ≥ 7, EPSS ≥ 10 %, ton parc, ou exploit public. P4 : surveiller."),
    ("En clair / Que faire", "Explication en français simple (ce qui est touché, ce qu'un pirate peut faire, s'il y a de vraies attaques) "
                             "et l'action concrète à mener, compréhensibles sans connaissance technique."),
    ("Pourquoi cette priorité", "Les facteurs qui ont conduit au niveau de priorité, pour justifier la décision auprès des équipes."),
    ("Score de risque", "Indicateur 0-100 pour trier : CVSS × 6 + EPSS × 20 + 15 si exploitée + 10 si Metasploit (5 si PoC) + 5 si rançongiciel "
                        "+ 3 × criticité de l'actif (1-3) + 5 si actif exposé + 5 si pré-authentification à distance."),
    ("Sévérité / CVSS / Source", "Gravité technique (CVSS 4.0 → 3.1 → 3.0 → 2). Si la NVD n'a pas encore analysé la CVE, VulnWatch reprend le score "
                                 "de l'éditeur (CNA) ou de la CISA : la colonne « Source du score » l'indique."),
    ("EPSS / Δ EPSS", "Probabilité (FIRST) d'exploitation dans les 30 jours, et son évolution sur 7 jours : une forte hausse signale un intérêt "
                      "croissant des attaquants."),
    ("Exploitée (KEV)", "Au catalogue CISA des vulnérabilités exploitées activement."),
    ("Exploitation (SSVC)", "Décision CISA (Vulnrichment) : Active = exploitée, Preuve de concept = code public, Aucune connue."),
    ("Maturité de l'exploit", "Arme (Metasploit) > Preuve de concept publique (Exploit-DB / référence NVD) > Détection publique (modèle Nuclei)."),
    ("Correctif disponible", "Oui si la NVD référence un correctif / avis éditeur, ou si une version corrigée du paquet existe."),
    ("Mon parc / Criticité / Exposition", "Actifs de ton inventaire (secret INVENTAIRE) ou mots de ta liste (secret WATCHLIST) concernés, "
                                          "avec leur criticité métier et leur exposition à Internet."),
    ("Version installée / Versions affectées", "Compare la version de ton actif aux versions déclarées vulnérables par l'éditeur."),
    ("Type d'impact", "Classification automatique : RCE, Pré-authentification à distance, Élévation de privilèges, Contournement "
                      "d'authentification, Injection SQL, XSS, SSRF, Corruption mémoire, Déni de service, Zero-click…"),
    ("Famille de produit", "Périmétrique (VPN, pare-feu), OT/ICS, Navigateur, Système d'exploitation, Virtualisation/Cloud, Messagerie, etc."),
    ("Paquets open source", "Avis GitHub (GHSA) : écosystème:paquet, plage de versions vulnérables et première version corrigée."),
    ("Vecteur / Complexité / Privilèges / Interaction", "Conditions d'attaque issues du vecteur CVSS (plus c'est « Réseau / Faible / Aucun », plus c'est grave)."),
    ("Automatisable / Impact technique (SSVC)", "Automatisable = l'attaque peut être industrialisée ; Impact total = contrôle complet du composant."),
    ("Suivi (ticket)", "Si les tickets GitHub sont activés : Ouvert, Corrigé (ticket fermé) ou Risque accepté (fermé « not planned »)."),
    ("Échéance CISA", "Date limite fixée par la CISA aux agences fédérales américaines : bon repère d'urgence."),
    ("Mise à jour", "Classeur régénéré toutes les heures. Pour ajouter tes propres colonnes de suivi, utilise un classeur connecté par "
                    "Power Query (voir LISEZMOI) : tes colonnes y sont conservées."),
    ("Sources", "NVD 2.0 (NIST) · CISA KEV · CISA Vulnrichment (SSVC) · FIRST EPSS · GitHub Security Advisories · Metasploit · Nuclei · Exploit-DB."),
]

# --------------------------------------------------------------------------- styles

C = {
    "red": "C00000", "orange": "ED7D31", "yellow": "FFD966", "green": "A9D08E", "grey": "A6A6A6",
    "blue": "BDD7EE", "navy": "1F3864", "kev": "7F1D1D", "teal": "DDEBF7", "p1": "C00000", "p2": "ED7D31",
    "p3": "FFD966", "p4": "E2EFDA",
}
FILL = {k: PatternFill("solid", fgColor=v) for k, v in C.items()}
WHITE_B = Font(color="FFFFFF", bold=True)
TITLE = Font(size=18, bold=True, color=C["navy"])
H2 = Font(size=13, bold=True, color=C["navy"])
THIN = Side(style="thin", color="D9D9D9")
BOX = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
LINK = Font(color="0563C1", underline="single")


def _cell_value(r: dict, key: str, kind: str, tz):
    v = r.get(key)
    if kind == "yesno":
        return "Oui" if v else "Non"
    if kind == "datetime":
        d = _dt(v)
        return d.astimezone(tz).replace(tzinfo=None) if d else None
    if kind == "date":
        d = _dt(v)
        return d.date() if d else None
    if v == "" or v is None:
        return None
    return v


def _write_table(ws, top: int, cols: list, rows: list[dict], name: str, tz, style="TableStyleMedium2",
                 empty_msg="Aucune donnée pour le moment.", freeze=True, wrap=True) -> int:
    """Écrit un tableau Excel (filtres, tri, styles) et renvoie la dernière ligne écrite."""
    has_wrap = wrap and any(c[3] == "wrap" for c in cols)
    for j, (_, head, width, _) in enumerate(cols, start=1):
        c = ws.cell(row=top, column=j, value=head)
        c.alignment = Alignment(wrap_text=True, vertical="center")
        if width and (ws.column_dimensions[get_column_letter(j)].width or 0) < width:
            ws.column_dimensions[get_column_letter(j)].width = width
    ws.row_dimensions[top].height = 32
    if not rows:
        ws.cell(row=top + 1, column=1, value=empty_msg).font = Font(italic=True, color="7F7F7F")
        return top + 1
    for i, r in enumerate(rows, start=top + 1):
        for j, (key, _, _, kind) in enumerate(cols, start=1):
            val = _cell_value(r, key, kind, tz)
            cell = ws.cell(row=i, column=j, value=val)
            if kind == "link" and val:
                cell.hyperlink = NVD_DETAIL + str(val)
                cell.font = LINK
            elif kind == "url" and val:
                cell.hyperlink = str(val)
                cell.font = LINK
            elif kind == "num1":
                cell.number_format = "0.0"
            elif kind == "pct":
                cell.number_format = "0.0%"
            elif kind == "wrap" and wrap:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
            if has_wrap and kind != "wrap":
                cell.alignment = Alignment(vertical="top")
            elif kind == "pctd":
                cell.number_format = "+0.0%;-0.0%;0.0%"
            elif kind == "datetime":
                cell.number_format = "yyyy-mm-dd hh:mm"
            elif kind == "date":
                cell.number_format = "yyyy-mm-dd"
    last = top + len(rows)
    ref = f"A{top}:{get_column_letter(len(cols))}{last}"
    t = Table(displayName=name, ref=ref)
    t.tableStyleInfo = TableStyleInfo(name=style, showRowStripes=True)
    ws.add_table(t)
    _conditional(ws, cols, top + 1, last)
    if freeze:
        ws.freeze_panes = ws.cell(row=top + 1, column=2)
    return last


def _conditional(ws, cols, first, last):
    for j, (key, head, _, kind) in enumerate(cols, start=1):
        col = get_column_letter(j)
        rng = f"{col}{first}:{col}{last}"
        if key == "severity":
            for txt, fill, font in (("CRITIQUE", "red", WHITE_B), ("ÉLEVÉE", "orange", WHITE_B),
                                    ("MOYENNE", "yellow", None), ("FAIBLE", "green", None), ("NON ÉVALUÉE", "grey", None)):
                ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=[f'"{txt}"'], fill=FILL[fill], font=font))
        elif key == "priority":
            for txt, fill, font in (("P1", "p1", WHITE_B), ("P2", "p2", WHITE_B), ("P3", "p3", None), ("P4", "p4", None)):
                ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=[f'"{txt}"'], fill=FILL[fill], font=font))
        elif key == "ssvc_exploitation":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Active"'], fill=FILL["kev"], font=WHITE_B))
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Preuve de concept"'], fill=FILL["orange"], font=WHITE_B))
        elif key == "exploit_maturity":
            ws.conditional_formatting.add(rng, FormulaRule(formula=[f'LEFT({col}{first},4)="Arme"'], fill=FILL["kev"], font=WHITE_B))
            ws.conditional_formatting.add(rng, FormulaRule(formula=[f'LEFT({col}{first},6)="Preuve"'], fill=FILL["orange"], font=WHITE_B))
        elif key in ("asset_exposed_label",):
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Oui"'], fill=FILL["red"], font=WHITE_B))
        elif key == "asset_crit_label":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Haute"'], fill=FILL["red"], font=WHITE_B))
        elif key == "patch_available":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Oui"'], fill=FILL["green"]))
        elif key == "epss_delta":
            ws.conditional_formatting.add(rng, CellIsRule(operator="greaterThanOrEqual", formula=["0.05"], font=Font(color=C["red"], bold=True)))
        elif key == "ticket_status":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Corrigé"'], fill=FILL["green"]))
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Ouvert"'], fill=FILL["yellow"]))
        elif key in ("kev", "exploit_ref"):
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Oui"'], fill=FILL["kev"], font=WHITE_B))
        elif key == "ransomware":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Known"'], fill=FILL["red"], font=WHITE_B))
        elif key in ("watch", "new"):
            ws.conditional_formatting.add(rng, FormulaRule(formula=[f'LEN({col}{first})>0'], fill=FILL["blue"], font=Font(bold=True)))
        elif key == "risk":
            ws.conditional_formatting.add(rng, ColorScaleRule(start_type="num", start_value=0, start_color="FFFFFF",
                                                              mid_type="num", mid_value=55, mid_color="FFD966",
                                                              end_type="num", end_value=100, end_color="F8696B"))
        elif key in ("score",):
            ws.conditional_formatting.add(rng, CellIsRule(operator="greaterThanOrEqual", formula=["9"], font=Font(color=C["red"], bold=True)))
        elif key == "epss":
            ws.conditional_formatting.add(rng, CellIsRule(operator="greaterThanOrEqual", formula=["0.1"], font=Font(color=C["red"], bold=True)))
        elif key == "av":
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Réseau (à distance)"'], font=Font(color=C["red"])))


def _sort_prio(rows):
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    return sorted(rows, key=lambda r: (order.get(r.get("priority"), 9), -(r.get("risk") or 0)))


def _sheet(wb, title, intro, tab_color=None):
    ws = wb.create_sheet(title)
    ws["A1"] = title
    ws["A1"].font = TITLE
    ws["A2"] = intro
    ws["A2"].font = Font(italic=True, color="595959")
    if tab_color:
        ws.sheet_properties.tabColor = tab_color
    ws.sheet_view.zoomScale = 90
    return ws


# --------------------------------------------------------------------------- classeur


def build_xlsx(path: Path, recs: list[dict], kev_rows: list[dict], alert_rows: list[dict],
               kpi: dict, cfg: dict, tz, inventory: list | None = None, history: list | None = None) -> None:
    now = dt.datetime.now(UTC)
    recs_p = _sort_prio(recs)
    d1 = now - dt.timedelta(days=1)
    wb = Workbook()

    # ===================================================== 0. Synthèse (en français simple)
    sy = wb.active
    sy.title = "Synthèse"
    sy.sheet_properties.tabColor = "00B050"
    sy.sheet_view.showGridLines = False
    sy.column_dimensions["A"].width = 17
    sy.column_dimensions["B"].width = 9
    sy.column_dimensions["C"].width = 70
    sy.column_dimensions["D"].width = 60
    sy["A1"] = "La situation en clair"
    sy["A1"].font = TITLE
    upd0 = _dt(kpi["updated"]).astimezone(tz)
    sy["A2"] = f"Mis à jour le {upd0:%Y-%m-%d à %H:%M} · cette page se lit en 1 minute · le détail est dans les feuilles suivantes"
    sy["A2"].font = Font(italic=True, color="595959")
    row = 4
    for para in explain.synthese(recs, kpi, history, show_assets=bool(inventory)):
        sy.merge_cells(start_row=row, start_column=1, end_row=row, end_column=4)
        c = sy.cell(row=row, column=1, value=para)
        c.alignment = Alignment(wrap_text=True, vertical="top")
        c.font = Font(size=12)
        sy.row_dimensions[row].height = max(20, 17 * (len(para) // 150 + 1))
        row += 1
    row += 1
    sy.cell(row=row, column=1, value="Les 10 urgences, expliquées simplement").font = H2
    cmap0 = {c[0]: c for c in DETAIL_COLS}
    scols = [cmap0["id"], cmap0["priority"], cmap0["plain"], cmap0["todo"]]
    urg = [r for r in recs_p if r["priority"] in ("P1", "P2")][:10]
    last = _write_table(sy, row + 1, scols, urg, "Urgences", tz, "TableStyleMedium3",
                        "Aucune urgence : rien ne demande d'action rapide pour le moment.", freeze=False)
    row = last + 2
    sy.cell(row=row, column=1, value="Comment lire les priorités").font = H2
    for i, (p, txt) in enumerate((("P1", "Urgent : agir sous 48 heures."), ("P2", "Important : agir cette semaine."),
                                  ("P3", "À planifier : dans le mois, avec les mises à jour habituelles."),
                                  ("P4", "À surveiller : pas d'action immédiate.")), start=row + 1):
        c = sy.cell(row=i, column=1, value=p)
        c.fill = FILL[p.lower()]
        c.font = WHITE_B if p in ("P1", "P2") else Font(bold=True)
        c.alignment = Alignment(horizontal="center")
        sy.merge_cells(start_row=i, start_column=2, end_row=i, end_column=3)
        sy.cell(row=i, column=2, value=txt)
    sy.cell(row=row + 6, column=1, value="Les mots techniques (CVE, CVSS, EPSS, KEV…) sont expliqués dans la feuille « Comprendre ».").font = Font(italic=True, color="595959")

    # ===================================================== 1. Tableau de bord
    ws = wb.create_sheet("Tableau de bord")
    ws.sheet_properties.tabColor = C["navy"]
    ws.sheet_view.showGridLines = False
    ws["A1"] = "VulnWatch — Veille des vulnérabilités"
    ws["A1"].font = TITLE
    upd = _dt(kpi["updated"]).astimezone(tz)
    ws["A2"] = f"Mis à jour le {upd:%Y-%m-%d à %H:%M} ({cfg['tz']}) · mise à jour automatique toutes les heures · sources : NVD, CISA KEV, FIRST EPSS"
    ws["A2"].font = Font(italic=True, color="595959")

    pc = Counter(r["priority"] for r in recs)
    # Largeurs fixes, alignées sur le tableau « Top 25 » (colonnes A à L)
    DASH_W = [17, 17, 30, 12, 13, 9, 11, 10, 22, 22, 22, 80]
    cards = [
        ("P1 — corriger sous 48 h", pc.get("P1", 0), "p1"), ("P2 — corriger sous 7 j", pc.get("P2", 0), "p2"),
        ("Exploitées activement (KEV)", sum(1 for r in recs if r.get("kev")), "kev"),
        ("Touchent mon parc", sum(1 for r in recs if r.get("watch")), "navy"),
        ("Nouvelles CVE (24 h)", kpi["new_24h"], "navy"), ("Exploit public (Metasploit / PoC)", sum(1 for r in recs if r.get("exploit_maturity", "").startswith(("Arme", "Preuve"))), "orange"),
        (f"Critiques publiées (7 j)", kpi["critical_7d"], "red"), ("Ajouts au catalogue KEV (7 j)", kpi["kev_7d"], "kev"),
    ]
    spans = [(1, 2), (3, 3), (4, 6), (7, 9)]
    for i, (label, val, color) in enumerate(cards):
        r0 = 4 if i < 4 else 7
        c0, c1 = spans[i % 4]
        ws.merge_cells(start_row=r0, start_column=c0, end_row=r0, end_column=c1)
        ws.merge_cells(start_row=r0 + 1, start_column=c0, end_row=r0 + 1, end_column=c1)
        v = ws.cell(row=r0, column=c0, value=val)
        v.font = Font(size=24, bold=True, color="FFFFFF")
        v.alignment = Alignment(horizontal="center", vertical="center")
        lab = ws.cell(row=r0 + 1, column=c0, value=label)
        lab.font = Font(size=10, bold=True, color="FFFFFF")
        lab.alignment = Alignment(horizontal="center", vertical="top", wrap_text=True)
        for rr in (r0, r0 + 1):
            for cc in range(c0, c1 + 1):
                ws.cell(row=rr, column=cc).fill = PatternFill("solid", fgColor=C[color])
    for rr, h in ((4, 38), (5, 22), (6, 6), (7, 38), (8, 22)):
        ws.row_dimensions[rr].height = h

    # Répartitions (sources des graphiques)
    sev_order = ["CRITIQUE", "ÉLEVÉE", "MOYENNE", "FAIBLE", "NON ÉVALUÉE"]
    sc = Counter(r["severity"] for r in recs)
    ws["A10"] = "Par sévérité"
    ws["D10"] = "Par priorité"
    ws["G10"] = "Nouvelles CVE par jour (14 j)"
    for c in ("A10", "D10", "G10"):
        ws[c].font = H2
    ws["A11"], ws["B11"] = "Sévérité", "CVE"
    for i, s_ in enumerate(sev_order, start=12):
        ws.cell(row=i, column=1, value=s_).fill = PatternFill("solid", fgColor={
            "CRITIQUE": C["red"], "ÉLEVÉE": C["orange"], "MOYENNE": C["yellow"], "FAIBLE": C["green"]}.get(s_, C["grey"]))
        ws.cell(row=i, column=2, value=sc.get(s_, 0))
    ws["D11"], ws["E11"] = "Priorité", "CVE"
    for i, p in enumerate(["P1", "P2", "P3", "P4"], start=12):
        ws.cell(row=i, column=4, value=p).fill = FILL[p.lower()]
        ws.cell(row=i, column=5, value=pc.get(p, 0))
    ws["G11"], ws["H11"], ws["I11"] = "Jour", "Toutes", "Critiques"
    days = [(now.astimezone(tz).date() - dt.timedelta(days=k)) for k in range(13, -1, -1)]
    per_day, crit_day = Counter(), Counter()
    for r in recs:
        d = _dt(r.get("published"))
        if d:
            dd = d.astimezone(tz).date()
            per_day[dd] += 1
            if (r.get("score") or 0) >= cfg.get("critical", 9):
                crit_day[dd] += 1
    for i, d in enumerate(days, start=12):
        ws.cell(row=i, column=7, value=d.strftime("%d/%m"))
        ws.cell(row=i, column=8, value=per_day.get(d, 0))
        ws.cell(row=i, column=9, value=crit_day.get(d, 0))
    for rng in ("A11:B11", "D11:E11", "G11:I11"):
        for row in ws[rng]:
            for c in row:
                c.font, c.fill = WHITE_B, FILL["navy"]

    def _bar(title, cats, data, anchor, colors, w, h=6.5):
        ch = BarChart()
        ch.type = "col"
        ch.title = title
        ch.style = 10
        ch.height, ch.width = h, w
        ch.add_data(data, titles_from_data=True)
        ch.set_categories(cats)
        if data.max_col == data.min_col:
            ch.legend = None
        else:
            ch.legend.position = "b"
        ch.dataLabels = DataLabelList()
        ch.dataLabels.showVal = True
        ch.dataLabels.showCatName = False
        ch.dataLabels.showSerName = False
        ch.dataLabels.showLegendKey = False
        ch.dataLabels.showPercent = False
        for sr, col in zip(ch.series, colors):
            sr.graphicalProperties.solidFill = col
            sr.graphicalProperties.line.solidFill = col
        ws.add_chart(ch, anchor)

    _bar("CVE par sévérité", Reference(ws, min_col=1, min_row=12, max_row=16),
         Reference(ws, min_col=2, min_row=11, max_row=16), "J10", ["1F3864"], 9.5)
    _bar("CVE par priorité", Reference(ws, min_col=4, min_row=12, max_row=15),
         Reference(ws, min_col=5, min_row=11, max_row=15), "L10", ["ED7D31"], 9)
    _bar("Nouvelles CVE publiées par jour", Reference(ws, min_col=7, min_row=12, max_row=25),
         Reference(ws, min_col=8, max_col=9, min_row=11, max_row=25), "J25", ["8EA9DB", "C00000"], 18)

    # Fournisseurs les plus touchés
    ws["A27"] = "Fournisseurs les plus touchés"
    ws["A27"].font = H2
    vend = Counter((r.get("vendor") or "(non renseigné)") for r in recs)
    p12 = Counter((r.get("vendor") or "(non renseigné)") for r in recs if r["priority"] in ("P1", "P2"))
    ws["A28"], ws["D28"], ws["E28"] = "Fournisseur", "CVE", "Dont P1-P2"
    ws.merge_cells("A28:C28")
    for c in ("A28", "D28", "E28"):
        ws[c].font, ws[c].fill = WHITE_B, FILL["navy"]
    for i, (v, n) in enumerate(vend.most_common(10), start=29):
        ws.merge_cells(start_row=i, start_column=1, end_row=i, end_column=3)
        ws.cell(row=i, column=1, value=v)
        ws.cell(row=i, column=4, value=n)
        c = ws.cell(row=i, column=5, value=p12.get(v, 0))
        if p12.get(v, 0):
            c.font = Font(color=C["red"], bold=True)

    # Top 25 priorités
    top = 43
    ws.cell(row=top - 1, column=1, value="Les 25 vulnérabilités à traiter en premier").font = H2
    top_keys = ["id", "priority", "action", "risk", "severity", "score", "epss", "kev", "exploit_maturity", "watch",
                "product", "justification"]
    cmap = {c[0]: c for c in DETAIL_COLS}
    top_cols = [cmap[k] for k in top_keys]
    last = _write_table(ws, top, top_cols, recs_p[:25], "Top25", tz, "TableStyleMedium3",
                        "Rien à signaler pour le moment.", freeze=False)

    # Dernières alertes
    a0 = last + 4
    ws.cell(row=a0 - 1, column=1, value="Dernières alertes (7 jours) — détail dans « Journal des alertes »").font = H2
    lim = now - dt.timedelta(days=7)
    al7 = [a for a in alert_rows if (_dt(a["date"]) or lim) > lim][:30]
    acols = [("date", "Date", 0, "datetime"), ("cve", "CVE", 0, "link"), ("reasons", "Motifs", 0, "txt"),
             ("priority", "Niveau (5 = urgent)", 0, "int"), ("channels", "Canaux", 0, "txt")]
    _write_table(ws, a0, acols, al7, "DernieresAlertes", tz, "TableStyleMedium4",
                 "Aucune alerte ces 7 derniers jours.", freeze=False)
    for j, wdt in enumerate(DASH_W, start=1):
        ws.column_dimensions[get_column_letter(j)].width = wdt
    ws.freeze_panes = "A4"

    # ===================================================== 2..5. Vues de travail
    views = [
        ("À traiter (P1-P2)", "Ta liste de travail : vulnérabilités demandant une action, de la plus urgente à la moins urgente.",
         [r for r in recs_p if r["priority"] in ("P1", "P2")], "Atraiter", C["red"]),
        ("Exploitées", "CVE exploitées activement (catalogue CISA KEV ou SSVC « Active »).",
         [r for r in recs_p if r.get("kev") or r.get("ssvc_exploitation") == "Active"], "Exploitees", C["kev"]),
        ("Mon parc", "CVE qui touchent les actifs de ton inventaire ou ta liste de surveillance.",
         [r for r in recs_p if r.get("watch")], "MonParc", "2F5597"),
        ("Nouvelles 24 h", "CVE détectées pour la première fois dans les dernières 24 heures.",
         [r for r in recs_p if r.get("new")], "Nouvelles", "00B0F0"),
    ]
    for title, intro, rows, tname, color in views:
        w = _sheet(wb, title, f"{intro} {len(rows)} CVE. Filtres et tri sur chaque en-tête.", color)
        _write_table(w, 4, DETAIL_COLS, rows, tname, tz, "TableStyleMedium2", "Aucune CVE dans cette catégorie pour le moment.")

    # ===================================================== 6. Vues expertes (requêtes prêtes à l'emploi)
    w = _sheet(wb, "Vues expertes", "Requêtes d'analyste prêtes à l'emploi. Pour la liste complète d'une vue : feuille « Toutes les CVE », "
                                    "filtre la colonne « Vues expertes » (Filtres textuels → Contient…).", "C65911")
    w.sheet_view.showGridLines = False
    cmap = {c[0]: c for c in DETAIL_COLS}
    qcols = [cmap[k] for k in ("id", "priority", "risk", "score", "epss", "exploit_maturity", "watch", "product", "justification")]
    w.cell(row=4, column=1, value="Sommaire").font = H2
    counts = [(name, desc, [r for r in recs_p if f(r)]) for name, desc, f in EXPERT_QUERIES]
    for j, h in enumerate(("Vue", "Description", "CVE", "dont P1"), start=1):
        c = w.cell(row=5, column=j, value=h)
        c.font, c.fill = WHITE_B, FILL["navy"]
    for i, (name, desc, rows) in enumerate(counts, start=6):
        w.cell(row=i, column=1, value=name).font = Font(bold=True)
        w.cell(row=i, column=2, value=desc)
        w.cell(row=i, column=3, value=len(rows))
        p1 = sum(1 for r in rows if r["priority"] == "P1")
        c = w.cell(row=i, column=4, value=p1)
        if p1:
            c.font = Font(color=C["red"], bold=True)
    row = 6 + len(counts) + 2
    for qi, (name, desc, rows) in enumerate(counts, start=1):
        w.cell(row=row, column=1, value=f"{name} — {len(rows)} CVE").font = H2
        w.cell(row=row + 1, column=1, value=desc + (" (15 plus prioritaires affichées)" if len(rows) > 15 else "")).font = Font(italic=True, color="595959")
        last = _write_table(w, row + 2, qcols, rows[:15], f"Q{qi:02d}", tz, "TableStyleLight9", "Aucune CVE pour cette vue.", freeze=False)
        row = last + 3
    for j, wdt in enumerate((24, 60, 9, 9, 9, 22, 22, 22, 70), start=1):
        w.column_dimensions[get_column_letter(j)].width = wdt
    w.freeze_panes = "A4"

    # ===================================================== 7. Exposition par actif (inventaire)
    if inventory:
        w = _sheet(wb, "Exposition par actif", "Pour chaque actif de ton inventaire : les vulnérabilités qui le concernent, "
                                               "de l'actif le plus à risque au moins à risque.", "2F5597")
        arows = []
        for it in inventory:
            hits = [r for r in recs_p if it["asset"] in (r.get("assets") or "").split("; ")]
            arows.append({
                "asset": it["asset"], "vendor": it["vendor"], "product": it["product"], "version": it["version"],
                "crit": it["criticity"], "exposed": "Oui" if it["exposed"] else "Non", "owner": it["owner"],
                "n": len(hits), "p1": sum(1 for r in hits if r["priority"] == "P1"),
                "p2": sum(1 for r in hits if r["priority"] == "P2"),
                "kev": sum(1 for r in hits if r.get("kev")),
                "max": max((r["score"] for r in hits if r.get("score") is not None), default=None),
                "risk": max((r["risk"] for r in hits), default=0),
                "cves": ", ".join(r["id"] for r in hits[:12]),
            })
        arows.sort(key=lambda x: (x["p1"], x["p2"], x["risk"]), reverse=True)
        icols = [("asset", "Actif", 26, "txt"), ("crit", "Criticité", 10, "txt"), ("exposed", "Exposé Internet", 10, "txt"),
                 ("vendor", "Fournisseur", 16, "txt"), ("product", "Produit", 20, "txt"), ("version", "Version", 12, "txt"),
                 ("owner", "Responsable", 18, "txt"), ("n", "CVE", 7, "int"), ("p1", "P1", 6, "int"), ("p2", "P2", 6, "int"),
                 ("kev", "Exploitées", 9, "int"), ("max", "Pire CVSS", 9, "num1"), ("risk", "Risque max", 9, "int"),
                 ("cves", "CVE (les plus prioritaires)", 100, "txt")]
        last = _write_table(w, 4, icols, arows, "ExpositionActifs", tz, "TableStyleMedium2")
        if arows:
            for col in ("I", "K"):
                w.conditional_formatting.add(f"{col}5:{col}{last}", CellIsRule(operator="greaterThan", formula=["0"], fill=FILL["red"], font=WHITE_B))
            w.conditional_formatting.add(f"J5:J{last}", CellIsRule(operator="greaterThan", formula=["0"], fill=FILL["orange"], font=WHITE_B))
            w.conditional_formatting.add(f"C5:C{last}", CellIsRule(operator="equal", formula=['"Oui"'], font=Font(color=C["red"], bold=True)))
            w.conditional_formatting.add(f"B5:B{last}", CellIsRule(operator="equal", formula=['"Haute"'], font=Font(color=C["red"], bold=True)))

    # ===================================================== 8. Toutes les CVE
    w = _sheet(wb, "Toutes les CVE", f"Base complète : CVE publiées dans les {cfg.get('retention_days', 30)} derniers jours + toutes "
                                     f"les CVE exploitées. {len(recs_p)} CVE, triées par priorité puis score de risque.", "7F7F7F")
    _write_table(w, 4, DETAIL_COLS, recs_p, "Toutes", tz, "TableStyleMedium2", "Aucune CVE pour le moment.", wrap=False)

    # ===================================================== 7. Par fournisseur
    w = _sheet(wb, "Par fournisseur", "Synthèse par éditeur sur la base suivie : volumes, gravité et urgence.", "548235")
    agg = defaultdict(lambda: {"n": 0, "P1": 0, "P2": 0, "crit": 0, "high": 0, "kev": 0, "max": None, "watch": "", "products": Counter()})
    for r in recs:
        v = r.get("vendor") or "(non renseigné)"
        a = agg[v]
        a["n"] += 1
        a[r["priority"]] = a.get(r["priority"], 0) + 1
        a["crit"] += r["severity"] == "CRITIQUE"
        a["high"] += r["severity"] == "ÉLEVÉE"
        a["kev"] += bool(r.get("kev"))
        if r.get("score") is not None:
            a["max"] = max(a["max"] or 0, r["score"])
        if r.get("watch"):
            a["watch"] = "Oui"
        if r.get("product"):
            a["products"][r["product"]] += 1
    vrows = [{"vendor": v, "n": a["n"], "p1": a["P1"], "p2": a["P2"], "crit": a["crit"], "high": a["high"],
              "kev": a["kev"], "max": a["max"], "watch": a["watch"],
              "products": ", ".join(p for p, _ in a["products"].most_common(5))}
             for v, a in agg.items()]
    vrows.sort(key=lambda x: (x["p1"], x["p2"], x["n"]), reverse=True)
    vcols = [("vendor", "Fournisseur", 26, "txt"), ("n", "CVE suivies", 10, "int"), ("p1", "P1", 7, "int"),
             ("p2", "P2", 7, "int"), ("crit", "Critiques", 9, "int"), ("high", "Élevées", 9, "int"),
             ("kev", "Exploitées (KEV)", 10, "int"), ("max", "Pire CVSS", 9, "num1"), ("watch", "Mon parc", 9, "txt"),
             ("products", "Produits concernés (top 5)", 70, "txt")]
    last = _write_table(w, 4, vcols, vrows, "ParFournisseur", tz, "TableStyleMedium7")
    if vrows:
        for col in ("C", "D", "G"):
            w.conditional_formatting.add(f"{col}5:{col}{last}", CellIsRule(operator="greaterThan", formula=["0"],
                                                                         fill=FILL["red"], font=WHITE_B))
        w.conditional_formatting.add(f"I5:I{last}", CellIsRule(operator="equal", formula=['"Oui"'], fill=FILL["blue"]))

    # ===================================================== Tendances
    if history:
        from openpyxl.chart import LineChart
        w = _sheet(wb, "Tendances", "Évolution quotidienne (jusqu'à 90 jours) : volume de CVE, critiques, ajouts KEV, P1 et alertes.", "4472C4")
        hcols = [("date", "Jour", 12, "txt"), ("new", "Nouvelles CVE", 12, "int"), ("critical", "Nouvelles critiques", 12, "int"),
                 ("kev_added", "Ajouts KEV", 10, "int"), ("p1", "P1 en base", 10, "int"), ("p2", "P2 en base", 10, "int"),
                 ("alerts", "Alertes envoyées", 12, "int")]
        hist = sorted(history, key=lambda h: h["date"])[-90:]
        last = _write_table(w, 4, hcols, hist, "Tendances", tz, "TableStyleLight9", freeze=False)
        if len(hist) >= 2:
            for title, cols_, anchor in (("Volume quotidien", (2, 3), "I4"), ("Urgences", (4, 5, 7), "I22")):
                ch = LineChart()
                ch.title, ch.height, ch.width, ch.style = title, 8, 20, 12
                for ci in cols_:
                    ch.add_data(Reference(w, min_col=ci, min_row=4, max_row=last), titles_from_data=True)
                ch.set_categories(Reference(w, min_col=1, min_row=5, max_row=last))
                ch.legend.position = "b"
                w.add_chart(ch, anchor)

    # ===================================================== 8. Catalogue KEV
    w = _sheet(wb, "Catalogue KEV", f"Ajouts au catalogue CISA KEV des {cfg.get('kev_days', 90)} derniers jours "
                                    f"(version {kpi.get('kev_version', '')}). Toutes ces failles sont exploitées activement.", C["kev"])
    krows = [{"id": k.get("cveID"), "added": k.get("dateAdded"), "vendor": k.get("vendorProject"), "product": k.get("product"),
              "name": k.get("vulnerabilityName"), "desc": k.get("shortDescription"), "action_req": k.get("requiredAction"),
              "due": k.get("dueDate"), "ransomware": k.get("knownRansomwareCampaignUse"), "cwe": ", ".join(k.get("cwes") or []),
              "notes": k.get("notes")} for k in kev_rows]
    kcols = [("id", "CVE", 17, "link"), ("added", "Ajoutée le", 11, "date"), ("due", "Échéance", 11, "date"),
             ("ransomware", "Rançongiciel", 12, "txt"), ("vendor", "Fournisseur", 18, "txt"), ("product", "Produit", 22, "txt"),
             ("name", "Nom", 45, "txt"), ("desc", "Description", 90, "txt"), ("action_req", "Action requise", 60, "txt"),
             ("cwe", "CWE", 12, "txt"), ("notes", "Références", 60, "txt")]
    _write_table(w, 4, kcols, krows, "CatalogueKEV", tz, "TableStyleMedium7", "Aucun ajout récent.")

    # ===================================================== 9. Journal des alertes
    w = _sheet(wb, "Journal des alertes", "Chaque alerte générée par VulnWatch, la plus récente en premier.", "7030A0")
    jcols = [("date", "Date", 16, "datetime"), ("cve", "CVE", 17, "link"), ("priority", "Niveau (5 = urgent)", 10, "int"),
             ("reasons", "Motifs", 60, "txt"), ("channels", "Canaux", 24, "txt"), ("message", "Détail", 110, "txt")]
    last = _write_table(w, 4, jcols, alert_rows, "Alertes", tz, "TableStyleMedium4", "Aucune alerte pour le moment.")
    if alert_rows:
        w.conditional_formatting.add(f"C5:C{last}", CellIsRule(operator="equal", formula=["5"], fill=FILL["red"], font=WHITE_B))
        w.conditional_formatting.add(f"C5:C{last}", CellIsRule(operator="equal", formula=["4"], fill=FILL["orange"], font=WHITE_B))

    # ===================================================== 10. Guide
    w = _sheet(wb, "Comprendre", "Les notions de base expliquées simplement, puis la signification de chaque colonne.", "A6A6A6")
    w.column_dimensions["A"].width = 30
    w.column_dimensions["B"].width = 120
    w.cell(row=4, column=1, value="Les notions de base").font = H2
    for i, (k, v) in enumerate(explain.GLOSSAIRE, start=5):
        a = w.cell(row=i, column=1, value=k)
        a.font = Font(bold=True)
        a.alignment = Alignment(vertical="top", wrap_text=True)
        b = w.cell(row=i, column=2, value=v)
        b.alignment = Alignment(wrap_text=True, vertical="top")
        w.row_dimensions[i].height = 32 if len(v) > 110 else 18
        a.border = b.border = BOX
    i0 = 5 + len(explain.GLOSSAIRE) + 1
    w.cell(row=i0, column=1, value="Les colonnes, une par une").font = H2
    for i, (k, v) in enumerate(GUIDE, start=i0 + 1):
        a = w.cell(row=i, column=1, value=k)
        a.font = Font(bold=True)
        a.alignment = Alignment(vertical="top")
        b = w.cell(row=i, column=2, value=v)
        b.alignment = Alignment(wrap_text=True, vertical="top")
        w.row_dimensions[i].height = 32 if len(v) > 110 else 18
        a.border = b.border = BOX
    i += 2
    w.cell(row=i, column=1, value="Feuilles").font = H2
    for j, (sheet, what) in enumerate([
        ("Synthèse", "La situation en français simple, lisible en 1 minute, et les 10 urgences expliquées."),
        ("Tableau de bord", "Vue d'ensemble : compteurs, graphiques, fournisseurs, top 25 avec justification, dernières alertes."),
        ("À traiter (P1-P2)", "Ta liste de travail : ce qui doit être corrigé en premier."),
        ("Exploitées", "Failles exploitées activement (KEV, SSVC)."),
        ("Mon parc", "Ce qui concerne tes actifs et technologies."),
        ("Nouvelles 24 h", "Ce qui est apparu depuis hier."),
        ("Vues expertes", "20 requêtes d'analyste prêtes à l'emploi (RCE pré-auth, Metasploit, périmétrique, OT, Patch Tuesday…)."),
        ("Exposition par actif", "Si un inventaire est fourni : le risque actif par actif."),
        ("Toutes les CVE", "La base complète, triée par priorité puis score de risque."),
        ("Par fournisseur", "Quels éditeurs concentrent le risque."),
        ("Tendances", "Évolution jour par jour, avec graphiques."),
        ("Catalogue KEV", "Les derniers ajouts officiels de la CISA, même hors de la base."),
        ("Journal des alertes", "Historique des alertes et des canaux utilisés."),
    ], start=i + 1):
        w.cell(row=j, column=1, value=sheet).font = Font(bold=True)
        w.cell(row=j, column=2, value=what)

    wb.active = 0
    tmp = path.with_suffix(".tmp.xlsx")
    wb.save(tmp)
    tmp.replace(path)
