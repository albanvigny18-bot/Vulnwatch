# Installer ton propre VulnWatch (gratuit, environ 10 minutes)

Tu obtiens **ta propre veille des vulnérabilités** :
- elle tourne toute seule toutes les heures ;
- elle surveille **tes** équipements ;
- elle envoie **tes** alertes sur ton téléphone ;
- elle produit **ton** fichier Excel et **ta** console web.

Tu n'as besoin d'aucune connaissance technique, et tout est faisable depuis un iPhone.

> Tu veux seulement **consulter** les failles qui touchent ton parc, sans alertes ? Pas besoin d'installer quoi que ce soit. Ouvre la console d'une installation existante, va dans l'onglet **« Mon parc »** et ajoute tes équipements. Ta liste reste sur ton appareil.

---

## Étape 1 : créer un compte GitHub (gratuit)
Va sur <https://github.com/signup> et crée un compte. Si tu en as déjà un, passe à l'étape 2.

## Étape 2 : copier VulnWatch
1. Ouvre <https://github.com/albanvigny18-bot/Vulnwatch>, ou le dépôt de la personne qui t'a partagé VulnWatch.
2. Touche le bouton vert **« Use this template »**, puis **« Create a new repository »**.
3. Choisis un nom, par exemple `vulnwatch`, et sélectionne **Public**. C'est ce qui rend l'outil gratuit et illimité.
4. Touche **« Create repository »**.

Ta copie est **vierge** : elle ne contient aucune donnée, aucun secret et aucun équipement de quelqu'un d'autre.

## Étape 3 : activer la publication
Dans ta copie, va dans **Settings → Pages**. Dans **Source**, choisis **GitHub Actions**.

## Étape 4 : recevoir les alertes sur ton téléphone
1. Installe l'application gratuite **ntfy**, depuis l'App Store ou le Play Store.
2. Touche **+** et invente un **nom secret**, long et difficile à deviner, par exemple `vulnwatch-k7q2m9x4wz`.
3. Dans GitHub, va dans **Settings → Secrets and variables → Actions → New repository secret** :
   - Name : `NTFY_TOPIC` ;
   - Secret : ton nom secret.
4. Touche **Add secret**.

## Étape 5 : décrire ton parc
1. Ouvre la console d'une installation VulnWatch, la tienne ou une autre, et va dans l'onglet **« Mon parc »**.
2. Ajoute tes équipements et logiciels : fournisseur, produit, version, importance, et s'il est accessible depuis Internet.
3. Touche **« Copier ma liste »**.
4. Dans GitHub, crée un nouveau secret :
   - Name : `INVENTAIRE` ;
   - Secret : colle ta liste.

Cette liste reste **secrète** : elle n'est jamais publiée.

## Étape 6 : démarrer
1. Dans ta copie, ouvre l'onglet **Actions**. Si GitHub le demande, touche **« I understand… enable them »**.
2. Choisis **VulnWatch → Run workflow → Run workflow**.
3. Au bout d'environ 3 minutes, la ligne devient verte ✅.

Ta console est en ligne à l'adresse `https://TON-NOM-GITHUB.github.io/vulnwatch/` (remplace par ton nom d'utilisateur). Sur iPhone, ouvre-la dans Safari puis touche **Partager → Sur l'écran d'accueil** pour l'avoir comme une application.

Ensuite, **tout est automatique** : les failles sont mises à jour et les alertes envoyées toutes les heures.

---

## Options facultatives
Ce sont des secrets à ajouter, comme à l'étape 4.

| Je veux… | Secret | Valeur |
|---|---|---|
| Une veille plus rapide | `NVD_API_KEY` | Clé gratuite demandée sur <https://nvd.nist.gov/developers/request-an-api-key> |
| Protéger l'Excel complet par un mot de passe | `EXCEL_PASSWORD` | Un mot de passe de ton choix |
| Recevoir l'Excel par courriel chaque matin | `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_TO` | Ton adresse Gmail, un « mot de passe d'application » Gmail (<https://myaccount.google.com/apppasswords>) et l'adresse qui reçoit |
| Recevoir les alertes dans Teams, Slack ou Discord | `WEBHOOK_URL` | L'adresse du webhook entrant de ton canal |

Les autres réglages (heures calmes, seuils, point quotidien…) se changent dans le fichier **`reglages.yml`**, où tout est expliqué en français. L'onglet **« Réglages »** de ta console peut aussi le générer pour toi.

## En cas de souci
- **La ligne est rouge dans Actions** : ouvre-la, touche « veille », puis l'étape en rouge. Les dernières lignes expliquent l'erreur.
- **Tu ne reçois pas de notification** : vérifie que le nom ntfy est identique dans l'application et dans le secret, et que les notifications de ntfy sont autorisées dans les réglages du téléphone.
- **Le site n'apparaît pas** : vérifie l'étape 3 (Pages → Source : GitHub Actions).
