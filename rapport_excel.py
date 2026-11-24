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


def enrich(r: dict, cfg: dict, now: dt.datetime) -> dict:
    """Ajoute priorité, action recommandée, score de risque, décodage CVSS, CWE en clair, ancienneté."""
    s, e = r.get("score"), r.get("epss")
    kev, watch = bool(r.get("kev")), bool(r.get("watch"))
    crit = cfg.get("critical", 9.0)
    if kev or (s is not None and s >= crit and (e or 0) >= 0.1) or (watch and (s or 0) >= crit):
        p = "P1"
    elif (s is not None and s >= crit) or (e or 0) >= 0.5 or (watch and (s or 0) >= 7):
        p = "P2"
    elif (s is not None and s >= 7) or (e or 0) >= 0.1 or watch:
        p = "P3"
    else:
        p = "P4"
    risk = (s if s is not None else 5.0) * 6 + (e or 0) * 25 + (15 if kev else 0) \
        + (10 if r.get("ransomware") == "Known" else 0) + (5 if watch else 0) + (5 if r.get("exploit_ref") else 0)
    pub = _dt(r.get("published"))
    first = _dt(r.get("first_seen"))
    cwes = [c.strip() for c in (r.get("cwe") or "").split(",") if c.strip()]
    r.update(parse_vector(r.get("vector", "")))
    r.update(
        priority=p,
        action=PRIORITY_ACTION[p],
        risk=int(round(min(100, risk))),
        age_days=(now - pub).days if pub else None,
        new="Oui" if first and first >= now - dt.timedelta(days=1) else "",
        cwe_name="; ".join(CWE_FR.get(c, c) for c in cwes),
    )
    return r


# --------------------------------------------------------------------------- colonnes

# (clé, en-tête, largeur, type)   type : txt | num1 | pct | int | date | datetime | yesno | link
DETAIL_COLS = [
    ("id", "CVE", 17, "link"),
    ("priority", "Priorité", 9, "txt"),
    ("action", "Action recommandée", 30, "txt"),
    ("risk", "Score de risque (0-100)", 12, "int"),
    ("severity", "Sévérité", 13, "txt"),
    ("score", "CVSS", 7, "num1"),
    ("epss", "EPSS (proba. 30 j)", 11, "pct"),
    ("epss_pct", "Percentile EPSS", 10, "pct"),
    ("kev", "Exploitée (KEV)", 10, "yesno"),
    ("exploit_ref", "Exploit public", 10, "yesno"),
    ("ransomware", "Rançongiciel", 12, "txt"),
    ("watch", "Mon parc", 16, "txt"),
    ("new", "Nouveau (24 h)", 10, "txt"),
    ("vendor", "Fournisseur", 18, "txt"),
    ("product", "Produit", 22, "txt"),
    ("cwe_name", "Type de faiblesse", 32, "txt"),
    ("desc", "Description", 90, "txt"),
    ("av", "Vecteur d'attaque", 18, "txt"),
    ("ac", "Complexité", 10, "txt"),
    ("pr", "Privilèges requis", 11, "txt"),
    ("ui", "Interaction utilisateur", 12, "txt"),
    ("cia", "Impact C / I / D", 30, "txt"),
    ("published", "Publiée le", 16, "datetime"),
    ("modified", "Modifiée le", 16, "datetime"),
    ("age_days", "Âge (jours)", 8, "int"),
    ("kev_due", "Échéance CISA", 12, "date"),
    ("ref_patch", "Correctif / avis éditeur", 40, "url"),
    ("cwe", "CWE", 12, "txt"),
    ("status", "Statut NVD", 16, "txt"),
    ("source", "Émetteur (CNA)", 22, "txt"),
    ("cvss_version", "Version CVSS", 8, "txt"),
    ("vector", "Vecteur CVSS", 44, "txt"),
]

GUIDE = [
    ("Priorité", "P1 : exploitée (KEV) OU critique avec EPSS ≥ 10 % OU critique sur ton parc. "
                 "P2 : critique, OU EPSS ≥ 50 %, OU CVSS ≥ 7 sur ton parc. P3 : CVSS ≥ 7, OU EPSS ≥ 10 %, OU ton parc. P4 : le reste."),
    ("Action recommandée", "Délai de traitement suggéré selon la priorité (P1 sous 48 h, P2 sous 7 jours, P3 sous 30 jours, P4 surveiller)."),
    ("Score de risque", "Indicateur synthétique 0-100 pour trier : CVSS × 6 + EPSS × 25 + 15 si KEV + 10 si rançongiciel + 5 si ton parc + 5 si exploit public."),
    ("Sévérité / CVSS", "Gravité technique selon la NVD (CVSS 4.0, 3.1, 3.0 ou 2). CRITIQUE ≥ 9, ÉLEVÉE ≥ 7, MOYENNE ≥ 4, FAIBLE < 4. "
                        "NON ÉVALUÉE : la NVD n'a pas encore attribué de score."),
    ("EPSS", "Probabilité (FIRST) que la vulnérabilité soit exploitée dans les 30 prochains jours. Le percentile la situe par rapport à toutes les CVE."),
    ("Exploitée (KEV)", "Présente au catalogue CISA des vulnérabilités exploitées activement : priorité absolue."),
    ("Exploit public", "La NVD référence un code d'exploitation public (référence marquée « Exploit »)."),
    ("Rançongiciel", "« Known » : la CISA sait que la faille est utilisée dans des campagnes de rançongiciel."),
    ("Mon parc", "Mots de ta liste de surveillance (secret WATCHLIST) trouvés dans le fournisseur, le produit ou la description."),
    ("Nouveau (24 h)", "CVE détectée par VulnWatch pour la première fois il y a moins de 24 h."),
    ("Type de faiblesse / CWE", "Catégorie de défaut (ex. CWE-79 = XSS, CWE-89 = injection SQL)."),
    ("Vecteur d'attaque", "Réseau = exploitable à distance ; Adjacent = même réseau local ; Local = accès à la machine ; Physique = accès matériel."),
    ("Complexité / Privilèges / Interaction", "Conditions nécessaires à l'attaque : plus c'est « Faible / Aucun / Aucune », plus c'est facile à exploiter."),
    ("Impact C / I / D", "Impact sur la Confidentialité, l'Intégrité et la Disponibilité."),
    ("Échéance CISA", "Date limite de correction fixée par la CISA pour les agences fédérales américaines : bon repère d'urgence."),
    ("Correctif / avis éditeur", "Premier lien NVD marqué « Patch » ou « Vendor Advisory »."),
    ("Statut NVD", "Received / Awaiting Analysis / Analyzed / Modified : avancement de l'analyse par la NVD."),
    ("Émetteur (CNA)", "Organisation qui a publié la CVE (éditeur, CERT, MITRE…)."),
    ("Mise à jour", "Classeur régénéré automatiquement toutes les heures. Pour suivre tes propres actions (statut, responsable), "
                    "utilise un classeur connecté par Power Query (voir LISEZMOI) : tes colonnes ajoutées y sont conservées."),
    ("Sources", "NVD 2.0 (NIST) · CISA Known Exploited Vulnerabilities · FIRST EPSS."),
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
                 empty_msg="Aucune donnée pour le moment.", freeze=True) -> int:
    """Écrit un tableau Excel (filtres, tri, styles) et renvoie la dernière ligne écrite."""
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
               kpi: dict, cfg: dict, tz) -> None:
    now = dt.datetime.now(UTC)
    recs_p = _sort_prio(recs)
    d1 = now - dt.timedelta(days=1)
    wb = Workbook()

    # ===================================================== 1. Tableau de bord
    ws = wb.active
    ws.title = "Tableau de bord"
    ws.sheet_properties.tabColor = C["navy"]
    ws.sheet_view.showGridLines = False
    ws["A1"] = "VulnWatch — Veille des vulnérabilités"
    ws["A1"].font = TITLE
    upd = _dt(kpi["updated"]).astimezone(tz)
    ws["A2"] = f"Mis à jour le {upd:%Y-%m-%d à %H:%M} ({cfg['tz']}) · mise à jour automatique toutes les heures · sources : NVD, CISA KEV, FIRST EPSS"
    ws["A2"].font = Font(italic=True, color="595959")

    pc = Counter(r["priority"] for r in recs)
    # Largeurs fixes, alignées sur le tableau « Top 25 » (colonnes A à L)
    DASH_W = [17, 17, 30, 12, 13, 9, 11, 10, 16, 18, 22, 80]
    cards = [
        ("P1 — corriger sous 48 h", pc.get("P1", 0), "p1"), ("P2 — corriger sous 7 j", pc.get("P2", 0), "p2"),
        ("Exploitées activement (KEV)", sum(1 for r in recs if r.get("kev")), "kev"),
        ("Touchent mon parc", sum(1 for r in recs if r.get("watch")), "navy"),
        ("Nouvelles CVE (24 h)", kpi["new_24h"], "navy"), ("Nouvelles CVE (7 j)", kpi["new_7d"], "navy"),
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
    top_cols = [c for c in DETAIL_COLS if c[0] in ("id", "priority", "action", "risk", "severity", "score", "epss",
                                                   "kev", "watch", "vendor", "product", "desc")]
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

    # ===================================================== 2..6. Vues de CVE
    views = [
        ("À traiter (P1-P2)", "Vulnérabilités demandant une action, de la plus urgente à la moins urgente.",
         [r for r in recs_p if r["priority"] in ("P1", "P2")], "Atraiter", C["red"]),
        ("Exploitées (KEV)", "CVE suivies qui figurent au catalogue CISA des vulnérabilités exploitées activement.",
         [r for r in recs_p if r.get("kev")], "Exploitees", C["kev"]),
        ("Mon parc", "CVE qui mentionnent un fournisseur ou un produit de ta liste de surveillance.",
         [r for r in recs_p if r.get("watch")], "MonParc", "2F5597"),
        ("Nouvelles 24 h", "CVE détectées pour la première fois dans les dernières 24 heures.",
         [r for r in recs_p if r.get("new")], "Nouvelles", "00B0F0"),
        ("Toutes les CVE", f"Base complète : CVE publiées dans les {cfg.get('retention_days', 30)} derniers jours + toutes les CVE exploitées.",
         recs_p, "Toutes", "7F7F7F"),
    ]
    for title, intro, rows, tname, color in views:
        w = _sheet(wb, title, f"{intro} {len(rows)} CVE. Filtres et tri disponibles sur chaque en-tête.", color)
        _write_table(w, 4, DETAIL_COLS, rows, tname, tz, "TableStyleMedium2", "Aucune CVE dans cette catégorie pour le moment.")

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
    w = _sheet(wb, "Guide", "Comment lire ce classeur.", "A6A6A6")
    w.column_dimensions["A"].width = 30
    w.column_dimensions["B"].width = 120
    for i, (k, v) in enumerate(GUIDE, start=4):
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
        ("Tableau de bord", "Vue d'ensemble : compteurs, graphiques, fournisseurs, top 25, dernières alertes."),
        ("À traiter (P1-P2)", "Ta liste de travail : ce qui doit être corrigé en premier."),
        ("Exploitées (KEV)", "Failles exploitées activement présentes dans la base."),
        ("Mon parc", "Ce qui concerne tes technologies."),
        ("Nouvelles 24 h", "Ce qui est apparu depuis hier."),
        ("Toutes les CVE", "La base complète, triée par priorité puis score de risque."),
        ("Par fournisseur", "Quels éditeurs concentrent le risque."),
        ("Catalogue KEV", "Les derniers ajouts officiels de la CISA, même hors de la base."),
        ("Journal des alertes", "Historique des alertes et des canaux utilisés."),
    ], start=i + 1):
        w.cell(row=j, column=1, value=sheet).font = Font(bold=True)
        w.cell(row=j, column=2, value=what)

    wb.active = 0
    tmp = path.with_suffix(".tmp.xlsx")
    wb.save(tmp)
    tmp.replace(path)
