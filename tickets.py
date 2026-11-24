"""
Suivi des corrections par tickets GitHub Issues (option TICKETS=true).

  * Un ticket est ouvert automatiquement pour chaque nouvelle CVE P1 (ou P2 si TICKET_PRIORITY=P2).
  * Tu peux l'assigner, le commenter, et le fermer quand la correction est déployée :
        fermé « Completed »    -> statut « Corrigé »
        fermé « Not planned »  -> statut « Risque accepté »
        ouvert                 -> statut « Ouvert »
  * Le statut remonte dans l'Excel (colonnes « Suivi (ticket) » et « Lien du ticket »).

Le dépôt étant public, les tickets ne mentionnent jamais tes actifs : seulement la CVE et ses données publiques.
"""
from __future__ import annotations

import re

import explain

API = "https://api.github.com"
CVE_IN_TITLE = re.compile(r"(CVE-\d{4}-\d{4,})")
STATUS = {"open": "Ouvert", "completed": "Corrigé", "not_planned": "Risque accepté"}


def _headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def list_tickets(http, token: str, repo: str, max_pages: int = 20) -> dict:
    out, url = {}, f"{API}/repos/{repo}/issues"
    params = {"labels": "vulnwatch", "state": "all", "per_page": 100}
    for _ in range(max_pages):
        r = http.get_raw(url, params=params, headers=_headers(token), timeout=60)
        for it in r.json():
            if "pull_request" in it:
                continue
            m = CVE_IN_TITLE.search(it.get("title", ""))
            if not m:
                continue
            state = "open" if it.get("state") == "open" else (it.get("state_reason") or "completed")
            out[m.group(1)] = {"number": it["number"], "status": STATUS.get(state, "Fermé"), "url": it.get("html_url", "")}
        nxt = r.links.get("next", {}).get("url")
        if not nxt:
            break
        url, params = nxt, None
    return out


def _public_reasons(text: str) -> str:
    return " · ".join(p for p in (text or "").split(" · ") if not p.startswith("Touche ton parc"))


def create_ticket(http, token: str, repo: str, r: dict) -> dict:
    title = f"[{r['priority']}] {r['id']} — {(r.get('vendor') or '').strip()} {(r.get('product') or '').strip()}".strip(" —")
    lines = [
        f"**Priorité : {r['priority']} — {r.get('action', '')}**", "",
        f"**En clair :** {explain.en_clair(r, show_assets=False)}", "",
        f"**Que faire :** {r.get('todo', '')}", "",
        f"**Pourquoi :** {_public_reasons(r.get('justification'))}", "",
        "| Élément | Valeur |", "|---|---|",
        f"| Sévérité | {r.get('severity', '')} ({r.get('score') if r.get('score') is not None else '—'}) |",
        f"| EPSS | {('%.1f %%' % (r['epss'] * 100)) if r.get('epss') is not None else '—'} |",
        f"| Exploitée (KEV) | {'Oui' if r.get('kev') else 'Non'} |",
        f"| Maturité de l'exploit | {r.get('exploit_maturity') or '—'} |",
        f"| Type d'impact | {r.get('tags') or '—'} |",
        f"| Versions affectées | {r.get('versions') or r.get('pkg_ranges') or '—'} |",
        f"| Version corrigée (paquet) | {r.get('pkg_fixed') or '—'} |",
        f"| Échéance CISA | {r.get('kev_due') or '—'} |", "",
        f"**Description :** {r.get('desc', '')}", "",
        f"- Fiche NVD : https://nvd.nist.gov/vuln/detail/{r['id']}",
    ]
    if r.get("ref_patch"):
        lines.append(f"- Correctif / avis éditeur : {r['ref_patch']}")
    lines += ["", "---", "_Ferme ce ticket comme **Completed** une fois corrigé, ou **Not planned** si le risque est accepté. "
                     "Le statut remontera dans l'Excel VulnWatch._"]
    labels = ["vulnwatch", r["priority"]] + (["KEV"] if r.get("kev") else []) + (["Metasploit"] if r.get("msf") else [])
    resp = http.post(f"{API}/repos/{repo}/issues", headers=_headers(token),
                     json={"title": title[:250], "body": "\n".join(lines), "labels": labels})
    it = resp.json()
    return {"number": it.get("number"), "status": "Ouvert", "url": it.get("html_url", "")}
