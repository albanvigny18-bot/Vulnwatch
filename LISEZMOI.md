# VulnWatch : veille des vulnérabilités gratuite, 24 h/24, dans Excel

VulnWatch tourne **toutes les heures sur les serveurs de GitHub**, même quand ton PC est éteint. C'est gratuit et sans limite d'utilisation pour un dépôt public.

À chaque passage, VulnWatch :
1. récupère les nouvelles CVE et les CVE modifiées auprès de la **NVD (NIST)** ;
2. vérifie le catalogue **CISA KEV** (vulnérabilités exploitées activement, y compris par des rançongiciels) ;
3. ajoute le score **FIRST EPSS** (probabilité d'exploitation dans les 30 jours) ;
4. repère les CVE qui touchent **ton parc** (ta liste de fournisseurs et produits) ;
5. met à jour le **classeur Excel**, les **CSV** pour Power Query et un **tableau de bord web** ;
6. t'envoie les **alertes**.

## Où tu reçois les alertes

| Canal | Ce que tu reçois |
|---|---|
| 📊 **Excel** | Feuille *Tableau de bord* avec les priorités et les dernières alertes, colonne *Nouveau (24 h)* surlignée, feuille *Journal des alertes* |
| 📱 **Notification push sur iPhone** (application gratuite **ntfy**, sans compte) | Une alerte instantanée pour chaque vulnérabilité importante, avec les boutons **Ouvrir l'Excel** et **Tableau de bord** |
| ✉️ **Courriel** (Gmail, gratuit) | Les alertes urgentes et importantes, plus **chaque matin un rapport avec le fichier Excel en pièce jointe** |

Ce qui déclenche une alerte :

| Déclencheur | Priorité |
|---|---|
| Nouvelle entrée au catalogue CISA KEV | 🔴 urgente |
| CVE qui devient critique (CVSS ≥ 9) | 🔴 urgente |
| EPSS ≥ 50 % | 🟠 haute |
| CVE de ton parc avec un CVSS ≥ 7 | 🟠 haute |
| Résumé des nouvelles CVE de l'heure | ⚪ silencieuse, par ntfy seulement |
| Une source injoignable depuis environ 6 h | 🔵 information |

Une même alerte n'est jamais envoyée deux fois. Au-delà de 10 alertes en un passage, les suivantes sont regroupées en un seul message. Le premier passage sert de référence et n'envoie rien.

---

## Installation (environ 15 minutes, une seule fois)

### 1. Créer le dépôt GitHub
1. Crée un compte gratuit sur <https://github.com> si tu n'en as pas.
2. Clique sur **New repository**. Nom : `vulnwatch`. Visibilité : **Public** (c'est ce qui rend GitHub Actions illimité et gratuit). Coche **Add a README**, puis clique sur **Create**.
3. Clique sur **Add file → Upload files** et dépose `vulnwatch.py`, `requirements.txt`, `.gitignore`, `LISEZMOI.md` et le dossier `site`. Clique sur **Commit changes**.
4. Crée le fichier du workflow :
   - clique sur **Add file → Create new file** ;
   - comme nom, tape exactement `.github/workflows/vulnwatch.yml` ;
   - colle le contenu de `workflow-a-copier/vulnwatch.yml` ;
   - clique sur **Commit changes**.

### 2. Activer la publication (GitHub Pages)
Va dans **Settings → Pages → Build and deployment → Source** et choisis **GitHub Actions**.

GitHub Pages sert à héberger le fichier Excel, les CSV et le tableau de bord à une adresse fixe.

### 3. Notifications push sur iPhone avec ntfy (gratuit, sans compte)
1. Installe **ntfy** depuis l'App Store et autorise les notifications.
2. Touche **+** et invente un nom de sujet **long et imprévisible**, par exemple `vulnwatch-k7q2m9xt4wz8`. Ce nom fonctionne comme un mot de passe.
3. Garde ce nom : c'est le secret `NTFY_TOPIC` de l'étape 5.

### 4. Courriels et rapport quotidien avec Gmail
1. Sur ton compte Google, active la **validation en deux étapes**. Va ensuite sur <https://myaccount.google.com/apppasswords>, crée un **mot de passe d'application** nommé « VulnWatch » et copie les 16 caractères.
2. Conseil : crée une adresse Gmail dédiée à l'envoi, et envoie les courriels vers ton adresse habituelle.

> Tu utilises Outlook / Microsoft 365 ? Microsoft bloque de plus en plus l'envoi SMTP par mot de passe. Garde Gmail pour l'**envoi**, et mets ton adresse Outlook dans `MAIL_TO` pour la **réception**.

### 5. Ajouter les secrets
Va dans **Settings → Secrets and variables → Actions → New repository secret** et ajoute :

| Secret | Valeur |
|---|---|
| `NTFY_TOPIC` | le nom de ton sujet ntfy |
| `SMTP_USER` | l'adresse Gmail qui envoie, ex. `vulnwatch.alban@gmail.com` |
| `SMTP_PASSWORD` | le mot de passe d'application de 16 caractères |
| `MAIL_TO` | l'adresse qui reçoit (plusieurs adresses possibles, séparées par des virgules) |
| `NVD_API_KEY` | ta clé gratuite, **fortement recommandée** : <https://nvd.nist.gov/developers/request-an-api-key> |
| `WATCHLIST` | ton parc, séparé par des virgules, ex. `Fortinet, FortiOS, Cisco, Palo Alto, VMware, Citrix, Ivanti, Microsoft Exchange, Siemens, Mitsubishi Electric, Schneider Electric, Rockwell` |

Ces secrets restent chiffrés chez GitHub et n'apparaissent jamais dans le code public.

### 6. Démarrer
1. Ouvre l'onglet **Actions**. Si GitHub le demande, clique sur **I understand… enable them**.
2. Choisis **VulnWatch → Run workflow**, coche **Envoyer une notification de test**, puis clique sur **Run**.
3. Au bout de 1 à 3 minutes, tu reçois la notification de test sur ton iPhone et un **courriel avec le fichier Excel en pièce jointe**. Ensuite, tout est automatique.

---

## L'Excel

### Option A : le fichier prêt à l'emploi (iPhone, PC, Mac)
Adresse : `https://albanvigny18-bot.github.io/Vulnwatch/VulnWatch.xlsx`. Le fichier est régénéré chaque heure. Sur iPhone, le bouton **Ouvrir l'Excel** des notifications ntfy y mène directement. Tu le reçois aussi chaque matin par courriel.

| Feuille | Contenu |
|---|---|
| **Tableau de bord** | Indicateurs (24 h, 7 jours, critiques, KEV, parc), 25 CVE à traiter en priorité, dernières alertes |
| **Vulnérabilités** | Toutes les CVE des 30 derniers jours : *Nouveau (24 h)*, sévérité en couleurs, CVSS, EPSS, KEV, rançongiciel, parc, lien NVD |
| **CISA KEV** | Les ajouts des 90 derniers jours, avec l'action requise et l'échéance |
| **Journal des alertes** | Toutes les alertes, avec leur motif et les canaux utilisés |

### Option B : ton propre classeur connecté, qui s'actualise tout seul (Excel sur PC ou Mac)
1. Crée un classeur vide, puis va dans **Données → À partir du Web**.
2. Colle `https://albanvigny18-bot.github.io/Vulnwatch/vulns.csv` et clique sur **Charger**.
3. Recommence dans d'autres feuilles avec `kev.csv` et `alertes.csv`.
4. Va dans **Données → Requêtes et connexions**. Fais un clic droit sur chaque requête, puis **Propriétés**. Coche **Actualiser toutes les 60 minutes** et **Actualiser les données lors de l'ouverture du fichier**.
5. Enregistre le classeur dans OneDrive : tu le retrouveras dans Excel sur ton iPhone.

Ce classeur est le tien : tu peux y ajouter tes colonnes (responsable, statut de correction), tes graphiques et tes tableaux croisés dynamiques. Ils sont conservés à chaque actualisation.

### Le tableau de bord web
Adresse : `https://albanvigny18-bot.github.io/Vulnwatch/`. Sur iPhone, ouvre-le dans Safari, puis touche **Partager → Sur l'écran d'accueil** : il s'ouvre ensuite comme une application. Il propose une recherche et des filtres : Critiques, Exploitées, Mon parc, EPSS.

---

## Réglages facultatifs (Settings → Secrets and variables → Actions → onglet **Variables**)

| Variable | Défaut | Rôle |
|---|---|---|
| `DAILY_REPORT` | `true` | rapport quotidien par courriel avec l'Excel joint |
| `DAILY_REPORT_HOUR` | `7` | heure locale du rapport |
| `EMAIL_MIN_PRIORITY` | `4` | `5` = seulement les urgentes par courriel, `2` = tout, y compris les résumés |
| `CRITICAL_SCORE` | `9.0` | seuil CVSS des alertes critiques |
| `EPSS_ALERT` | `0.5` | seuil EPSS (0,5 = 50 %) |
| `WATCHLIST_MIN_SCORE` | `7.0` | CVSS minimal pour alerter sur ton parc |
| `SEND_DIGEST` | `true` | résumé horaire des nouvelles CVE par ntfy |
| `MAX_ALERTS_PER_RUN` | `10` | au-delà, les alertes sont regroupées |
| `RETENTION_DAYS` / `KEV_HISTORY_DAYS` | `30` / `90` | historique conservé |
| `HIDE_WATCHLIST` | `false` | `true` remplace le nom de tes produits par ✓ sur le site et dans l'Excel publics |
| `TIMEZONE` | `America/Toronto` | fuseau des dates |
| `SMTP_HOST` | `smtp.gmail.com` | serveur d'envoi, si tu n'utilises pas Gmail |

Pour changer la fréquence, modifie la ligne `cron` du workflow : `"7 * * * *"` correspond à toutes les heures, `"*/30 * * * *"` à toutes les 30 minutes.

---

## Fiabilité : ce qu'il faut savoir

- **Coût** : GitHub Actions et GitHub Pages sont gratuits pour un dépôt public. ntfy, Gmail et la clé NVD le sont aussi.
- **Ponctualité** : GitHub lance les tâches planifiées « au mieux ». Un retard de quelques minutes est courant, parfois plus aux heures de pointe. Aucune donnée n'est perdue : chaque passage reprend là où le dernier s'est arrêté, avec un chevauchement de 15 minutes.
- **Panne d'une source** : VulnWatch continue avec les autres sources et rattrape le retard ensuite. Tu reçois une alerte si une source reste injoignable environ 6 h. Si le catalogue de la CISA ne répond pas, un miroir officiel sur GitHub prend le relais.
- **Échec d'exécution** : GitHub t'envoie automatiquement un courriel quand un workflow planifié échoue.
- **Délai de la NVD** : beaucoup de CVE sont publiées sans score CVSS, le temps que la NVD les analyse. Elles apparaissent comme « NON ÉVALUÉE », puis déclenchent une alerte dès qu'elles reçoivent un score critique.
- **Confidentialité** : le dépôt et les fichiers publiés sont publics. Les données de vulnérabilités le sont de toute façon, et tes secrets restent chiffrés. Seules les correspondances avec ton parc sont visibles, et tu peux les masquer avec `HIDE_WATCHLIST=true`. Tu continues alors de recevoir le détail complet par ntfy et par courriel.

## Dépannage

| Symptôme | Solution |
|---|---|
| Pas de notification ntfy | Vérifie que le sujet est identique, sans espace, dans l'application et dans le secret `NTFY_TOPIC`. Vérifie aussi que les notifications sont autorisées pour ntfy dans Réglages iOS. |
| Pas de courriel | `SMTP_PASSWORD` doit être un **mot de passe d'application** et non ton mot de passe Gmail. Regarde aussi dans les indésirables. |
| Erreur `github-pages` / `Pages` | Settings → Pages → Source = **GitHub Actions**. |
| Le workflow n'apparaît pas | Le fichier doit être exactement à `.github/workflows/vulnwatch.yml`. |
| NVD lente ou erreurs 403 | Ajoute le secret `NVD_API_KEY`. |
| Tout réinitialiser | Supprime la branche `data` (onglet Branches). |
