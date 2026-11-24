# VulnWatch : veille des vulnérabilités gratuite, 24 h/24, dans le cloud

VulnWatch tourne **toutes les heures sur les serveurs de GitHub**, même quand ton PC est éteint. C'est gratuit et sans limite d'utilisation pour un dépôt public.

À chaque passage, VulnWatch :
1. récupère les nouvelles CVE et les CVE modifiées auprès de la **NVD (NIST)** ;
2. vérifie le catalogue **CISA KEV** (vulnérabilités exploitées activement, y compris par des rançongiciels) ;
3. ajoute le score **FIRST EPSS** (probabilité d'exploitation dans les 30 jours) ;
4. repère les CVE qui touchent **ton parc** (ta liste de fournisseurs et produits) ;
5. publie un **tableau de bord web** (fait pour iPhone), un **classeur Excel** et des **CSV** pour Power Query ;
6. t'envoie les **alertes** sur Telegram, ntfy ou par courriel.

| Déclencheur d'alerte | Priorité |
|---|---|
| Nouvelle entrée au catalogue CISA KEV | 🔴 urgente |
| CVE qui devient critique (CVSS ≥ 9) | 🔴 urgente |
| EPSS ≥ 50 % | 🟠 haute |
| CVE de ton parc avec un CVSS ≥ 7 | 🟠 haute |
| Résumé des nouvelles CVE de l'heure | ⚪ silencieuse |
| Une source injoignable depuis environ 6 h | 🔵 information |

Une même alerte n'est jamais envoyée deux fois. Au-delà de 10 alertes en un passage, les suivantes sont regroupées en un seul message. Le premier passage sert de référence et n'envoie rien.

---

## Installation (environ 15 minutes, une seule fois)

### 1. Créer le dépôt GitHub
1. Crée un compte gratuit sur <https://github.com> si tu n'en as pas.
2. Clique sur **New repository**. Nom : `vulnwatch`. Visibilité : **Public** (c'est ce qui rend GitHub Actions illimité et gratuit). Coche **Add a README**, puis clique sur **Create**.
3. Clique sur **Add file → Upload files** et dépose le **contenu** du dossier décompressé : `vulnwatch.py`, `requirements.txt`, `.gitignore`, `LISEZMOI.md` et le dossier `site`. Clique sur **Commit changes**.
4. Crée le fichier du workflow. Le dossier `.github` est souvent masqué par l'explorateur de fichiers, alors le plus simple est de le créer directement dans GitHub :
   - clique sur **Add file → Create new file** ;
   - comme nom, tape exactement `.github/workflows/vulnwatch.yml` ;
   - colle le contenu du fichier `vulnwatch.yml` fourni (une copie se trouve aussi dans le dossier `workflow-a-copier`) ;
   - clique sur **Commit changes**.

### 2. Activer le tableau de bord (GitHub Pages)
Va dans **Settings → Pages → Build and deployment → Source** et choisis **GitHub Actions**.

### 3. Créer le bot Telegram (canal recommandé : gratuit, fiable, instantané sur iPhone)
1. Dans Telegram, écris à **@BotFather**, envoie `/newbot` et choisis un nom. BotFather te donne un **jeton** qui ressemble à `123456:ABC…`.
2. Ouvre la conversation avec ton nouveau bot et envoie-lui « bonjour ».
3. Dans un navigateur, ouvre `https://api.telegram.org/bot<TON_JETON>/getUpdates`. Repère `"chat":{"id":123456789` : ce nombre est ton **Chat ID**.

> Tu peux utiliser **ntfy** à la place de Telegram, ou en plus : installe l'application ntfy, abonne-toi à un sujet au nom long et imprévisible, puis renseigne le secret `NTFY_TOPIC`.

### 4. Ajouter les secrets
Va dans **Settings → Secrets and variables → Actions → New repository secret** et ajoute :

| Secret | Valeur | Obligatoire ? |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | le jeton fourni par BotFather | oui, si tu utilises Telegram |
| `TELEGRAM_CHAT_ID` | ton Chat ID | oui, si tu utilises Telegram |
| `NVD_API_KEY` | ta clé gratuite : <https://nvd.nist.gov/developers/request-an-api-key> | **fortement recommandé** |
| `WATCHLIST` | ton parc, séparé par des virgules, ex. `Fortinet, FortiOS, Cisco, Palo Alto, VMware, Citrix, Ivanti, Microsoft Exchange, Siemens, Mitsubishi Electric, Schneider Electric, Rockwell` | conseillé |
| `NTFY_TOPIC` / `NTFY_TOKEN` | ton sujet ntfy (et un jeton, si tu as un compte) | facultatif |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`, `MAIL_TO` | pour recevoir les alertes par courriel (ex. Gmail avec un mot de passe d'application) | facultatif |

La liste de surveillance est un **secret** : elle n'apparaît pas dans le code public.

### 5. Démarrer
1. Ouvre l'onglet **Actions**. Si GitHub le demande, clique sur **I understand… enable them**.
2. Choisis **VulnWatch → Run workflow**, coche **Envoyer une notification de test**, puis clique sur **Run**.
3. Au bout de 1 à 3 minutes, tu reçois le test et le message « VulnWatch est en marche ». Ensuite, tout est automatique, toutes les heures.

---

## Utiliser les résultats

Le **tableau de bord** est à l'adresse `https://<ton-utilisateur>.github.io/vulnwatch/`. Sur iPhone, ouvre-le dans Safari, touche **Partager → Sur l'écran d'accueil** : il s'ouvre ensuite comme une application. Il propose quatre onglets (Priorités, Toutes les CVE, CISA KEV, Alertes), une recherche et des filtres (Critiques, Exploitées, Mon parc, EPSS).

Le **classeur Excel** est à l'adresse `…/VulnWatch.xlsx`. Il est régénéré à chaque heure et contient quatre feuilles :
- **Tableau de bord** : indicateurs et 25 CVE à traiter en priorité ;
- **Vulnérabilités** : toutes les CVE suivies, avec couleurs et liens NVD ;
- **CISA KEV** : les ajouts récents au catalogue ;
- **Journal des alertes**.

**Excel connecté, qui se met à jour tout seul (PC ou Mac) :**
1. Dans Excel, va dans **Données → À partir du Web** et colle `https://<ton-utilisateur>.github.io/vulnwatch/vulns.csv`. Clique sur **Charger**.
2. Fais un clic droit sur la table, puis **Actualiser → Propriétés de connexion**. Coche **Actualiser toutes les 60 minutes** et **Actualiser les données lors de l'ouverture du fichier**.
3. Recommence avec `kev.csv` dans une autre feuille.

Ce classeur est le tien : tu peux y ajouter tes colonnes, tes graphiques et tes tableaux croisés dynamiques.

---

## Réglages facultatifs (Settings → Secrets and variables → Actions → onglet **Variables**)

| Variable | Défaut | Rôle |
|---|---|---|
| `CRITICAL_SCORE` | `9.0` | seuil CVSS des alertes critiques |
| `EPSS_ALERT` | `0.5` | seuil EPSS (0,5 = 50 %) |
| `WATCHLIST_MIN_SCORE` | `7.0` | CVSS minimal pour alerter sur ton parc |
| `SEND_DIGEST` | `true` | résumé horaire des nouvelles CVE (`false` pour le couper) |
| `MAX_ALERTS_PER_RUN` | `10` | au-delà, les alertes sont regroupées |
| `RETENTION_DAYS` | `30` | historique de CVE conservé |
| `KEV_HISTORY_DAYS` | `90` | historique KEV affiché |
| `HIDE_WATCHLIST` | `false` | `true` remplace le nom de tes produits par ✓ sur le site public |
| `TIMEZONE` | `America/Toronto` | fuseau des dates dans l'Excel |

Pour changer la fréquence, modifie la ligne `cron` du workflow : `"7 * * * *"` correspond à toutes les heures, `"*/30 * * * *"` à toutes les 30 minutes.

---

## Fiabilité : ce qu'il faut savoir

- **Coût** : GitHub Actions est gratuit et illimité pour un dépôt public, tout comme GitHub Pages. Telegram, ntfy et la clé NVD sont aussi gratuits.
- **Ponctualité** : GitHub lance les tâches planifiées « au mieux ». Un retard de quelques minutes est courant, parfois plus aux heures de pointe. Aucune donnée n'est perdue : chaque passage reprend là où le dernier s'est arrêté, avec un chevauchement de 15 minutes.
- **Panne d'une source** : VulnWatch continue avec les autres sources et rattrape le retard ensuite. Tu reçois une alerte si une source reste injoignable environ 6 h. Le site affiche un avertissement si les données ont plus de 3 h. Si le catalogue de la CISA ne répond pas, un miroir officiel sur GitHub prend le relais.
- **Échec d'exécution** : GitHub t'envoie automatiquement un courriel quand un workflow planifié échoue.
- **Pas de mise en veille** : l'état est enregistré à chaque heure dans la branche `data`. Cette activité continue empêche GitHub de désactiver les tâches planifiées.
- **Délai de la NVD** : beaucoup de CVE sont publiées sans score CVSS, le temps que la NVD les analyse. Elles apparaissent comme « NON ÉVALUÉE », puis déclenchent une alerte dès qu'elles reçoivent un score critique.
- **Confidentialité** : le dépôt et le site sont publics. Les données de vulnérabilités le sont de toute façon, et les secrets (jetons, liste de surveillance) restent chiffrés chez GitHub. Seules les correspondances avec ton parc sont visibles sur le site, et tu peux les masquer avec `HIDE_WATCHLIST=true`.

## Dépannage

| Symptôme | Solution |
|---|---|
| Aucune notification | Relance avec le test. Vérifie le nom exact des secrets et que tu as bien écrit au bot en premier. |
| Erreur `github-pages` / `Pages` | Settings → Pages → Source = **GitHub Actions**. |
| Le workflow n'apparaît pas | Le fichier doit être exactement à `.github/workflows/vulnwatch.yml`. |
| NVD lente ou erreurs 403 | Ajoute le secret `NVD_API_KEY`. |
| Tout réinitialiser | Supprime la branche `data` (onglet Branches). |
