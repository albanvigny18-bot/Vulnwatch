"""
Explications en langage clair, compréhensibles par tous (direction, équipes IT, utilisateurs).

  * en_clair(r)  -> 2 à 4 phrases : ce qui est touché, ce qu'un pirate peut faire, comment, s'il y a de vraies attaques
  * que_faire(r) -> l'action concrète à mener, avec le délai
  * synthese(...) -> un résumé rédigé de la situation, pour la direction
  * GLOSSAIRE    -> les notions de base expliquées simplement
"""
from __future__ import annotations

FAMILY_PLAIN = [
    ("Périmétrique", "un équipement de sécurité réseau (VPN, pare-feu ou passerelle) placé à l'entrée du réseau"),
    ("OT / ICS", "un équipement industriel (automate, supervision, écran d'atelier)"),
    ("Navigateur", "un navigateur web"),
    ("Système d'exploitation", "un système d'exploitation (le logiciel de base d'un ordinateur ou d'un serveur)"),
    ("Virtualisation", "une plateforme de virtualisation ou de cloud (qui fait tourner de nombreux serveurs)"),
    ("Messagerie", "un outil de messagerie ou de travail collaboratif"),
    ("Base de données", "une base de données"),
    ("CMS", "un site web (CMS ou extension)"),
    ("Serveur web", "un serveur web ou applicatif"),
    ("Réseau", "un équipement réseau (routeur, commutateur, borne Wi-Fi)"),
    ("Sécurité", "un outil de sécurité ou de gestion des identités"),
    ("Sauvegarde", "un système de sauvegarde ou de stockage"),
    ("Mobile", "un téléphone ou une tablette"),
    ("Bibliothèque open source", "une bibliothèque logicielle (une « brique » utilisée à l'intérieur d'autres applications)"),
]

IMPACT_PLAIN = [
    ("RCE", "prendre le contrôle de l'appareil ou du logiciel"),
    ("Contournement d'authentification", "entrer sans connaître le mot de passe"),
    ("Élévation de privilèges", "obtenir des droits d'administrateur"),
    ("Identifiants codés en dur", "se connecter avec un mot de passe caché dans le produit"),
    ("Injection SQL", "lire ou modifier les données de la base de données"),
    ("Désérialisation", "faire exécuter du code malveillant"),
    ("Traversée de répertoire", "lire des fichiers qui devraient être protégés"),
    ("XXE", "lire des fichiers du serveur"),
    ("SSRF", "se servir du serveur pour attaquer d'autres systèmes internes"),
    ("XSS", "piéger les utilisateurs du site (vol de session, fausses pages)"),
    ("CSRF", "faire réaliser des actions à un utilisateur connecté, à son insu"),
    ("Fuite d'informations", "voler des informations"),
    ("Corruption mémoire", "faire planter le logiciel, et parfois en prendre le contrôle"),
    ("Contrôle d'accès défaillant", "accéder à des fonctions ou des données sans en avoir le droit"),
    ("Déni de service", "rendre le service indisponible"),
]


def _product(r: dict) -> str:
    """Nom lisible : celui déclaré par l'éditeur (bien orthographié) en priorité, sinon celui de la NVD."""
    if r.get("affected"):
        return r["affected"].split(";")[0].strip()
    v, p = (r.get("vendor") or "").strip(), (r.get("product") or "").strip()
    if v and p and p.lower().startswith(v.lower()):
        v = ""
    name = " ".join(w for w in ((v[:1].upper() + v[1:]) if v else "", (p[:1].upper() + p[1:]) if p else "") if w)
    return name or "un logiciel"


def _family(r: dict) -> str:
    fam = r.get("family") or ""
    for key, txt in FAMILY_PLAIN:
        if key in fam:
            return txt
    return ""


def _impact(r: dict) -> str:
    tags = r.get("tags") or ""
    for key, txt in IMPACT_PLAIN:
        if key in tags:
            return txt
    cia = r.get("cia") or ""
    if "C:Élevé" in cia and "I:Élevé" in cia:
        return "accéder aux données et les modifier"
    if "C:Élevé" in cia:
        return "accéder à des données confidentielles"
    if "I:Élevé" in cia:
        return "modifier des données ou le fonctionnement du système"
    if "D:Élevé" in cia:
        return "rendre le service indisponible"
    return "compromettre la sécurité du système"


def _how(r: dict) -> str:
    vec = r.get("vector") or ""
    parts = dict(p.split(":", 1) for p in vec.split("/") if ":" in p)
    av, pr, ui = parts.get("AV"), parts.get("PR"), parts.get("UI")
    if not av:
        return ""
    if av == "N":
        who = {"N": "depuis Internet, sans compte ni mot de passe", "L": "à distance, avec un simple compte utilisateur",
               "H": "à distance, mais seulement avec un compte administrateur"}.get(pr, "à distance")
    elif av == "A":
        who = "depuis le même réseau local"
    elif av == "L":
        who = "en ayant déjà un accès à la machine"
    else:
        who = "avec un accès physique à l'appareil"
    if ui in ("R", "A", "P"):
        who += ", si une victime clique sur un lien ou ouvre un fichier piégé"
    return who


def _gravity(r: dict) -> str:
    s = r.get("score")
    if s is None:
        return "Gravité pas encore évaluée."
    word = "très élevée" if s >= 9 else "élevée" if s >= 7 else "moyenne" if s >= 4 else "faible"
    return f"Gravité {word} ({s:.1f}/10)."


def _threat(r: dict) -> str:
    if r.get("kev") or r.get("ssvc_exploitation") == "Active":
        t = "⚠️ Des pirates l'utilisent déjà dans de vraies attaques"
        if r.get("ransomware") == "Known":
            t += ", y compris des groupes de rançongiciels"
        return t + "."
    if r.get("msf"):
        return "Un outil d'attaque prêt à l'emploi est disponible publiquement : l'attaque est à la portée de tous."
    if (r.get("exploit_maturity") or "").startswith("Preuve") or r.get("ssvc_exploitation") == "Preuve de concept":
        return "Du code d'attaque a été publié : une exploitation est probable."
    e = r.get("epss")
    if e is not None and e >= 0.1:
        return f"Le risque qu'elle soit utilisée par des pirates dans le mois est élevé ({e:.0%})."
    return "Aucune attaque connue à ce jour."


def en_clair(r: dict, show_assets: bool = True) -> str:
    fam = _family(r)
    what = f"Une faille dans {_product(r)}" + (f", {fam}," if fam else "")
    impact = _impact(r)
    how = _how(r)
    if "mot de passe" in impact and how.startswith("depuis Internet, sans compte"):
        how = "depuis Internet" + how[len("depuis Internet, sans compte ni mot de passe"):]
    de = "d'" if impact[:1].lower() in "aeiouyéèêàâîôû" else "de "
    s1 = f"{what} permet à un pirate {de}{impact}" + (f" {how}" if how else "") + "."
    out = [s1.replace(",,", ","), _gravity(r), _threat(r)]
    if r.get("watch"):
        if show_assets and r.get("assets"):
            vers = dict(x.split(": ", 1) for x in (r.get("asset_versions") or "").split("; ") if ": " in x)
            names = [f"{a} (version installée {vers[a]})" if vers.get(a) else a for a in r["assets"].split("; ")]
            out.append("Elle concerne ton parc : " + ", ".join(names) + ".")
        else:
            out.append("Elle concerne des technologies de ton parc.")
    return " ".join(out)


def que_faire(r: dict) -> str:
    p = r.get("priority", "P4")
    head = {"P1": "URGENT — sous 48 h :", "P2": "IMPORTANT — cette semaine :", "P3": "À planifier — sous 30 jours :",
            "P4": "Pas d'action immédiate :"}[p]
    if p == "P4":
        return f"{head} rester informé ; la correction se fera avec les mises à jour habituelles."
    if r.get("pkg_fixed"):
        act = f"mettre à jour {r.get('packages') or 'le paquet'} vers la version {r['pkg_fixed']} ou plus récente"
    elif r.get("ref_patch") or r.get("patch_available") == "Oui":
        act = "installer la mise à jour de sécurité de l'éditeur (lien « Correctif »)"
    else:
        act = "appliquer les mesures de contournement de l'éditeur, car aucun correctif n'est encore référencé"
    extra = ""
    if p == "P1":
        extra = " Si c'est impossible tout de suite : isoler l'équipement, couper l'accès depuis Internet ou désactiver la fonction touchée, puis surveiller les journaux."
        if r.get("kev") or r.get("ssvc_exploitation") == "Active":
            extra += " Vérifier aussi qu'il n'y a pas déjà eu d'intrusion."
    if r.get("kev_due"):
        extra += f" Échéance recommandée par la CISA : {r['kev_due']}."
    return f"{head} {act}.{extra}"


def synthese(recs: list[dict], kpi: dict, stats: list | None = None, show_assets: bool = True) -> list[str]:
    """Paragraphes rédigés, pour la direction ou un point d'équipe."""
    p1 = [r for r in recs if r.get("priority") == "P1"]
    p2 = [r for r in recs if r.get("priority") == "P2"]
    expl = [r for r in recs if r.get("kev") or r.get("ssvc_exploitation") == "Active"]
    parc = [r for r in recs if r.get("watch")]
    parc_urg = [r for r in parc if r.get("priority") in ("P1", "P2")]
    out = []
    out.append(f"VulnWatch suit {len(recs)} vulnérabilités publiées récemment ou exploitées. "
               f"{len(p1)} demandent une action urgente (P1, sous 48 h) et {len(p2)} sont importantes (P2, cette semaine). "
               f"{len(expl)} sont déjà utilisées par des pirates dans de vraies attaques.")
    if parc:
        out.append(f"Ton parc est concerné par {len(parc)} d'entre elles, dont {len(parc_urg)} urgentes ou importantes. "
                   "Elles sont détaillées dans la feuille « Mon parc ».")
    else:
        out.append("Pour savoir lesquelles te concernent vraiment, ajoute tes équipements et logiciels dans l'onglet "
                   "« Mon parc » de la console : c'est gratuit, sans compte, et ta liste reste sur ton appareil.")
    out.append(f"Dernières 24 h : {kpi.get('new_24h', 0)} nouvelles vulnérabilités, {kpi.get('critical_7d', 0)} critiques sur 7 jours, "
               f"{kpi.get('kev_7d', 0)} ajoutées à la liste des failles exploitées (CISA) sur 7 jours.")
    if p1:
        top = sorted(p1, key=lambda r: -(r.get("risk") or 0))[:5]
        out.append("À traiter en premier : " + " ; ".join(
            f"{r['id']} ({_product(r)}" + (", exploitée" if r.get("kev") else "") + (", ton parc" if r.get("watch") else "") + ")"
            for r in top) + ".")
    return out


GLOSSAIRE = [
    ("Vulnérabilité (faille)", "Une erreur dans un logiciel ou un équipement qu'un pirate peut utiliser pour l'attaquer. On la corrige en installant la mise à jour (le « correctif ») de l'éditeur."),
    ("CVE", "Le numéro d'identification unique d'une faille, comme une plaque d'immatriculation (ex. CVE-2024-3400). Tout le monde utilise ce numéro pour parler de la même faille."),
    ("Priorité P1 à P4", "Le niveau d'urgence calculé par VulnWatch pour TON contexte. P1 = urgent (48 h), P2 = cette semaine, P3 = dans le mois, P4 = rester informé. La colonne « Pourquoi » explique le choix."),
    ("Gravité (CVSS)", "Note de 0 à 10 qui mesure les dégâts possibles si la faille est utilisée. 9 à 10 = très grave. Elle ne dit pas si des pirates l'utilisent vraiment : c'est le rôle de KEV et EPSS."),
    ("Exploitée (KEV)", "La faille figure sur la liste officielle de l'agence américaine de cybersécurité (CISA) des failles déjà utilisées par des pirates. C'est le signal d'alarme le plus fort."),
    ("EPSS", "La probabilité, en %, que la faille soit utilisée par des pirates dans les 30 prochains jours. La plupart des failles sont sous 1 % ; au-dessus de 10 %, c'est préoccupant."),
    ("Exploit / Metasploit / PoC", "Un « exploit » est un programme qui utilise la faille. Une « preuve de concept » (PoC) montre que c'est possible ; un module Metasploit est une arme prête à l'emploi, utilisable par presque n'importe qui."),
    ("SSVC", "L'avis de la CISA sur chaque faille : est-elle exploitée (Active), du code d'attaque existe-t-il (PoC), l'attaque peut-elle être automatisée, l'impact est-il total."),
    ("Pré-authentification / à distance", "Le pirate n'a besoin ni de compte ni de mot de passe, et peut attaquer depuis Internet. C'est la situation la plus dangereuse."),
    ("Périmétrique", "Les équipements à l'entrée du réseau (VPN, pare-feu, passerelles). Ce sont les cibles préférées des pirates car ils sont exposés à Internet."),
    ("OT / ICS", "Les systèmes industriels : automates, supervision (SCADA), écrans d'atelier. Une attaque peut arrêter une production ou créer un danger physique."),
    ("Correctif / mesure de contournement", "Le correctif est la mise à jour qui supprime la faille. Quand il n'existe pas encore, l'éditeur propose souvent une mesure de contournement (désactiver une fonction, bloquer un accès)."),
    ("Score de risque", "Un score de 0 à 100 calculé par VulnWatch qui combine gravité, attaques réelles, outils d'attaque disponibles et importance de l'actif touché. Sert à trier."),
    ("Inventaire / Mon parc", "La liste de tes équipements et logiciels. Grâce à elle, VulnWatch sait quelles failles te concernent vraiment et augmente leur priorité."),
]
