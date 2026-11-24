# VulnWatch : guide de l'analyste

VulnWatch est un outil de veille des vulnérabilités pensé pour les équipes de cybersécurité (SOC, gestion des vulnérabilités, RSSI, OT). Il tourne **toutes les heures sur GitHub Actions**, gratuitement, même quand ton ordinateur est éteint.

À chaque passage, il :
- collecte et croise **8 sources** ;
- calcule une **priorité justifiée** pour chaque CVE ;
- la rapproche de **ton inventaire d'actifs** ;
- publie un **Excel professionnel** et une **console web** ;
- alerte **là où tu travailles**.

---

## 1. Ce que fait l'outil

### Sources croisées

| Source | Apport pour l'analyste |
|---|---|
| **NVD 2.0** (NIST) | CVE, CVSS, CWE, produits (CPE), références, correctifs |
| **CISA KEV** | Vulnérabilités **exploitées activement**, usage par des rançongiciels, échéance de correction |
| **CISA Vulnrichment** | Décision **SSVC** (Exploitation : active / PoC / aucune ; Automatisable ; Impact technique), produits et **versions affectées déclarés par l'éditeur**, score de l'éditeur (CNA) ou de la CISA quand la NVD n'a pas encore analysé. Ce dernier point est très utile vu l'arriéré de la NVD. |
| **FIRST EPSS** | Probabilité d'exploitation à 30 jours, percentile et **tendance sur 7 jours** |
| **GitHub Advisories** | Bibliothèques open source (npm, PyPI, Maven, NuGet, Go, RubyGems…) : plage vulnérable et **version corrigée** |
| **Metasploit** | Module d'exploitation public (exploit « armé », avec son niveau de fiabilité) |
| **Exploit-DB** | Preuves de concept publiques |
| **Nuclei** | Modèle de détection public : la faille est scannée à grande échelle |

### Priorisation P1 à P4, justifiée

| Priorité | Délai | Règle |
|---|---|---|
| **P1** | 48 h | **Au moins un** de ces cas :<br>• exploitée (KEV ou SSVC « Active ») ;<br>• module Metasploit et CVSS ≥ 7 ;<br>• critique, avec EPSS ≥ 10 % ou un exploit public ;<br>• critique sur ton parc, si elle est exploitable sans authentification, exposée ou dotée d'un exploit public ;<br>• CVSS ≥ 7 avec un exploit ou sans authentification, sur un actif exposé à Internet. |
| **P2** | 7 jours | **Au moins un** de ces cas :<br>• critique ;<br>• EPSS ≥ 50 % ;<br>• exploit public et CVSS ≥ 7 ;<br>• CVSS ≥ 7 sur ton parc ;<br>• SSVC « automatisable, impact total ». |
| **P3** | 30 jours | CVSS ≥ 7, OU EPSS ≥ 10 %, OU touche ton parc, OU exploit public. |
| **P4** | surveiller | Tout le reste. |

Chaque CVE comporte en plus :
- une colonne **« Pourquoi cette priorité »**, qui liste les facteurs retenus (pratique pour justifier une décision en comité) ;
- un **score de risque de 0 à 100**, pour trier.

### Classification experte, automatique
- **Type d'impact** : RCE, pré-authentification à distance, zero-click, élévation de privilèges, contournement d'authentification, injection SQL, XSS, SSRF, désérialisation, corruption mémoire, déni de service, fuite d'informations…
- **Famille de produit** : périmétrique (VPN, pare-feu, passerelles), OT/ICS, navigateur, système d'exploitation, virtualisation/cloud, messagerie et collaboration, base de données, CMS, sauvegarde, sécurité, open source…

### 20 vues expertes prêtes à l'emploi
- RCE pré-auth
- Exploitées activement
- Arme Metasploit
- PoC public
- Rançongiciels
- Échéance CISA dans 7 jours ou moins
- Périmétrique
- OT / ICS
- Microsoft (Patch Tuesday)
- Navigateurs
- Virtualisation / Cloud
- Messagerie / Collaboration
- Open source
- Zero-click
- Contournement d'authentification
- Élévation de privilèges
- EPSS en hausse
- EPSS ≥ 10 %
- Critiques sans correctif
- Nouvelles critiques 24 h

---

## 2. L'Excel

Il est publié à l'adresse `https://albanvigny18-bot.github.io/Vulnwatch/VulnWatch.xlsx`, mis à jour chaque heure. Sur iPhone, ouvre-le avec le bouton **Ouvrir l'Excel** des notifications. Si tu actives le rapport quotidien, tu le reçois aussi chaque matin par courriel.

| Feuille | Contenu |
|---|---|
| **Tableau de bord** | Compteurs (P1, P2, exploitées, exploits publics, parc…), graphiques, fournisseurs les plus touchés, **les 25 CVE à traiter en premier avec leur justification**, dernières alertes |
| **À traiter (P1-P2)** | La liste de travail |
| **Exploitées** | KEV et SSVC « Active » |
| **Mon parc** | CVE qui touchent tes actifs, avec criticité, exposition, **version installée et versions affectées** côte à côte, et responsable |
| **Nouvelles 24 h** | Ce qui est apparu depuis hier |
| **Vues expertes** | Sommaire des 20 requêtes et top 15 de chacune |
| **Exposition par actif** | Pour chaque actif de l'inventaire : nombre de CVE, P1, P2, exploitées, pire CVSS, risque maximal |
| **Toutes les CVE** | La base complète, triée par priorité puis par risque |
| **Par fournisseur** | Volumes, urgences et pire score par éditeur |
| **Tendances** | Évolution jour par jour, avec graphiques |
| **Catalogue KEV** | Les ajouts récents de la CISA, avec l'action requise et l'échéance |
| **Journal des alertes** | Toutes les alertes envoyées |
| **Guide** | La signification de chaque colonne |

Chaque CVE est détaillée sur **56 colonnes**, regroupées en cinq blocs :
1. **Décider** : priorité, action, justification, risque, CVSS et sa source, EPSS et sa tendance, KEV, SSVC, maturité de l'exploit, rançongiciel, correctif disponible.
2. **Mon parc** : actifs, criticité, exposition, version installée, responsable.
3. **Contexte** : type d'impact, famille, vues expertes, fournisseur, produit, versions affectées, paquets, faiblesse (CWE en français), description.
4. **Technique** : vecteur d'attaque, complexité, privilèges, interaction, impact C/I/D, SSVC, modules Metasploit, modèle Nuclei, Exploit-DB.
5. **Suivi** : ticket, dates, ancienneté, échéance CISA, lien vers le correctif, avis GHSA, statut NVD, émetteur.

**Ajouter tes propres colonnes (statut, commentaire…).** Le fichier publié est régénéré chaque heure, donc tes modifications y seraient perdues. Crée plutôt ton propre classeur connecté :
1. Dans Excel, va dans **Données → À partir du Web** et colle `https://albanvigny18-bot.github.io/Vulnwatch/vulns.csv`.
2. Dans les propriétés de la requête, coche **Actualiser toutes les 60 minutes** et **Actualiser à l'ouverture du fichier**.

Les colonnes que tu ajoutes à côté de la table sont conservées à chaque actualisation.

---

## 3. La console web (requêtes professionnelles)

Adresse : `https://albanvigny18-bot.github.io/Vulnwatch/`. Sur iPhone, utilise **Partager → Sur l'écran d'accueil** pour l'ouvrir comme une application.

Tape une requête dans la barre. Les critères se combinent :

```
p:P1,P2 famille:périmétrique -kev:oui
cvss>=9 exploit:metasploit
fournisseur:microsoft age<=2 tri:risque
vue:"RCE pré-auth" parc:oui
epss>=10% correctif:non
tag:"élévation de privilèges" av:local
paquet:npm cvss>=7
source:cna,cisa            (CVE notées par l'éditeur ou la CISA, pas encore par la NVD)
```

Voici la syntaxe complète. Le bouton **?** de la console l'affiche aussi.

| Critère | Effet |
|---|---|
| `p:` | priorité |
| `cvss` `epss` `risque` `age` avec `> >= < <= =` | comparaison numérique |
| `kev:` `parc:` `nouveau:` `correctif:` `ransomware:` | oui / non |
| `exploit:` | metasploit, poc, nuclei, aucun |
| `ssvc:` | active, preuve… |
| `fournisseur:` `produit:` `cve:` `cwe:` | recherche par éditeur, produit, identifiant ou CWE |
| `tag:` `famille:` `vue:` | classification experte |
| `av:` `pr:` `ui:` `auto:` | conditions d'attaque |
| `paquet:` `sev:` `source:` | paquet open source, sévérité, source du score |

Règles d'écriture :
- un `-` devant un critère l'exclut ;
- une virgule signifie « OU » (`p:P1,P2`) ;
- les guillemets entourent les valeurs avec des espaces ;
- `tri:risque|cvss|epss|date|age` change l'ordre d'affichage.

Le reste de la console :
- des **requêtes enregistrées**, accessibles d'un seul geste ;
- des **compteurs cliquables** ;
- un **export CSV** du résultat ;
- un lien partageable : l'adresse de la page contient la requête ;
- une **API** de lecture : `data.json`, `vulns.csv`, `kev.csv`, `alertes.csv` ;
- un flux **RSS** : `feed.xml`.

---

## 4. Les alertes

| Déclencheur | Niveau |
|---|---|
| Ajout au catalogue CISA KEV | 🔴 urgent |
| CVE qui passe en **P1** | 🔴 urgent |
| CVE qui devient critique | 🔴 urgent |
| Exploitation active signalée par la CISA (SSVC) | 🔴 urgent |
| Module Metasploit publié (CVSS ≥ 7) | 🟠 haut |
| EPSS ≥ 50 % | 🟠 haut |
| Ton parc touché (CVSS ≥ 7) | 🟠 haut |
| Résumé horaire des nouvelles CVE | ⚪ silencieux |
| Point quotidien | 🔵 information |
| Source injoignable depuis environ 6 h | 🔵 information |

Chaque alerte contient :
- la priorité et l'action à mener ;
- la justification ;
- tes actifs touchés et leur version ;
- les versions affectées et la version corrigée ;
- l'échéance CISA ;
- le lien vers le correctif ;
- les boutons **Ouvrir l'Excel** et **Console**.

Les garde-fous :
- une même alerte n'est jamais envoyée deux fois ;
- au-delà de 10 alertes en un passage, les suivantes sont regroupées en un seul message ;
- le premier passage sert de référence et n'envoie rien.

| Canal | Mise en place |
|---|---|
| **Notifications iPhone / Android (ntfy)** | Secret `NTFY_TOPIC` = `vulnwatch-znt9v74nr9xdj2`, et abonnement à ce même sujet dans l'application ntfy |
| **Microsoft Teams** | Dans un canal : **Workflows → « Publier dans un canal lorsqu'une demande webhook est reçue »**. Copie l'URL dans le secret `WEBHOOK_URL`. |
| **Slack / Discord** | URL du webhook entrant dans le secret `WEBHOOK_URL` (le type est détecté automatiquement) |
| **Courriel + rapport quotidien avec l'Excel joint** | Secrets `SMTP_USER`, `SMTP_PASSWORD` (mot de passe d'application Gmail) et `MAIL_TO` |
| **Flux RSS** | `…/feed.xml` dans Outlook, Feedly ou un connecteur RSS Teams / Slack |

**Heures calmes** : la variable `QUIET_HOURS` (par exemple `22-7`) bloque les alertes non urgentes la nuit. Elles restent visibles dans l'Excel.

---

## 5. Ton inventaire d'actifs (recommandé)

1. Copie `inventaire-modele.csv` et adapte-le avec tes actifs, en gardant le séparateur `;`.
   - **Criticite** : Haute, Moyenne ou Basse.
   - **Expose** : Oui si l'actif est accessible depuis Internet.
2. Colle **tout le contenu** du fichier dans un secret nommé `INVENTAIRE`. Supprime ensuite l'exemple du dépôt, ou laisse-le tel quel : il ne contient que des données fictives.

Ce que fait VulnWatch avec l'inventaire :
- il rapproche chaque CVE de tes actifs, à partir du fournisseur, du produit, des produits déclarés par l'éditeur, des paquets et de la description ;
- il en tient compte dans la priorité et le risque ;
- il remplit les feuilles **Mon parc** et **Exposition par actif**.

Pour une simple liste de mots-clés, le secret `WATCHLIST` suffit (par exemple `Fortinet, Citrix, Siemens`).

### Confidentialité
Le dépôt et le site sont publics, donc VulnWatch **ne publie jamais le nom de tes actifs** :
- ni sur le site ;
- ni dans les CSV ou le flux RSS ;
- ni dans l'état sauvegardé ;
- ni dans les tickets.

Pour lire le détail par actif, crée le secret **`EXCEL_PASSWORD`** :
- l'Excel publié devient alors la **version complète, chiffrée en AES** ;
- Excel (iPhone, PC, Mac) demande le mot de passe à l'ouverture.

Sans ce secret, l'Excel publié masque tes actifs, mais la version complète arrive par courriel si tu l'as activé.

---

## 6. Suivi des corrections (tickets)

Pour l'activer, crée la variable `TICKETS` = `true`. Pour inclure aussi les P2, ajoute `TICKET_PRIORITY` = `P2`.

Fonctionnement :
- chaque nouvelle CVE P1 ouvre un **ticket GitHub** avec toutes ses données publiques ;
- tu peux l'assigner, le commenter et le fermer ;
- le statut remonte dans l'Excel (colonne « Suivi ») : **Corrigé** si tu le fermes en « Completed », **Risque accepté** si tu le fermes en « Not planned ».

> Attention : sur un dépôt public, les tickets sont visibles de tous. Ils ne mentionnent aucun de tes actifs, mais la liste des CVE que tu suis l'est.

---

## 7. Installation

Ce qui reste à faire une seule fois :
1. **Settings → Pages → Source : GitHub Actions**.
2. **Settings → Secrets and variables → Actions** : crée au minimum `NTFY_TOPIC`.
   - Recommandés : `NVD_API_KEY` (clé gratuite : <https://nvd.nist.gov/developers/request-an-api-key>), `INVENTAIRE` ou `WATCHLIST`, `EXCEL_PASSWORD`.
   - Facultatifs : `WEBHOOK_URL`, les secrets SMTP.
3. **Actions → VulnWatch → Run workflow**, avec la case de test cochée.

### Variables facultatives (onglet « Variables »)

| Variable | Défaut | Rôle |
|---|---|---|
| `CRITICAL_SCORE` | `9.0` | seuil « critique » |
| `EPSS_ALERT` | `0.5` | seuil EPSS d'alerte |
| `WATCHLIST_MIN_SCORE` | `7.0` | CVSS minimal pour alerter sur ton parc |
| `MAX_ALERTS_PER_RUN` | `10` | au-delà, regroupement |
| `SEND_DIGEST` | `true` | résumé horaire |
| `DAILY_REPORT` / `DAILY_REPORT_HOUR` | `true` / `7` | point quotidien (push + courriel) |
| `QUIET_HOURS` | vide | ex. `22-7` |
| `TICKETS` / `TICKET_PRIORITY` | `false` / `P1` | tickets de suivi |
| `WEBHOOK_TYPE` | auto | `teams`, `slack`, `discord` ou `generic` |
| `RETENTION_DAYS` / `KEV_HISTORY_DAYS` | `30` / `90` | historique |
| `INITIAL_DAYS` | `7` | profondeur du premier passage |
| `ENRICH_MAX_PER_RUN` | `600` | CVE enrichies par passage (Vulnrichment) |
| `USE_EXPLOIT_SOURCES` / `USE_VULNRICHMENT` / `USE_GITHUB_ADVISORIES` | `true` | activer ou couper une source |
| `HIDE_WATCHLIST` | `false` | masquer aussi les mots-clés `WATCHLIST` en public |
| `TIMEZONE` | `America/Toronto` | fuseau horaire |

---

## 8. Fiabilité

- **Tests automatiques.** Avant chaque passage, une série de tests vérifie la lecture des sources, la priorisation, l'Excel et le chiffrement. En cas de régression, rien n'est publié et GitHub t'envoie un courriel.
- **Sources indépendantes.** Une source en panne n'arrête jamais les autres. Ses dernières données connues restent utilisées, et une alerte part au bout d'environ 6 h d'échec. L'état des sources est affiché dans la console.
- **Aucun trou.** Chaque passage reprend là où le précédent s'est arrêté, avec un chevauchement de 15 minutes. Une CVE modifiée est automatiquement ré-enrichie.
- **Ponctualité.** GitHub peut décaler un passage planifié de quelques minutes.
- **Arriéré de la NVD.** Une CVE pas encore notée par la NVD reçoit le score de l'éditeur ou de la CISA (colonne « Source du score »), puis celui de la NVD quand il arrive.

## Dépannage

| Symptôme | Solution |
|---|---|
| Pas de notification | Le sujet ntfy doit être identique dans l'application et dans le secret. Vérifie aussi que les notifications de ntfy sont autorisées dans Réglages iOS. |
| Erreur `Pages` | Settings → Pages → Source = **GitHub Actions**. |
| L'étape « Tests » échoue | Ouvre le journal de l'exécution et signale l'erreur. Rien n'a été publié, donc il n'y a aucun risque de données fausses. |
| NVD lente ou erreurs 403 | Ajoute `NVD_API_KEY`. |
| Excel « fichier corrompu » sur iPhone | Il est chiffré : ouvre-le avec l'application **Excel**, pas l'aperçu d'iOS. |
| Repartir de zéro | Supprime la branche `data`. |
