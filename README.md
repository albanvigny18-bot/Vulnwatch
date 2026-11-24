# VulnWatch

Veille des vulnérabilités **automatique, gratuite et continue** (GitHub Actions, toutes les heures) :
NVD · CISA KEV · CISA Vulnrichment (SSVC) · FIRST EPSS · GitHub Advisories · Metasploit · Nuclei · Exploit-DB.

- **Compréhensible par tous** : chaque faille expliquée « en clair » avec « que faire », synthèse rédigée, glossaire
- **Excel professionnel** (14 feuilles, 58 colonnes par CVE, priorité P1-P4 justifiée, vues expertes, exposition par actif, tendances), chiffrable par mot de passe
- **Personnalisable sans coder** : `reglages.yml` commenté en français + onglet « Réglages » de la console (générateur de réglages et d'inventaire)
- **Console web** (mode simple / expert) avec langage de requêtes (`cvss>=9 exploit:metasploit famille:périmétrique`), export CSV
- **Alertes** : notification push iPhone/Android (ntfy), Teams / Slack / Discord, courriel, flux RSS
- **Suivi des corrections** par tickets GitHub, **inventaire d'actifs** (criticité, exposition Internet)

### Pour qui ?
- **Tout le monde, sans compte :** ouvre la console, onglet **Mon parc**, ajoute tes équipements et vois tes failles en clair (ta liste reste sur ton appareil).
- **Ta propre installation, avec tes alertes :** bouton **« Use this template »**, puis suis [INSTALLER.md](INSTALLER.md) (environ 10 min, faisable sur iPhone).

➡️ Mode d'emploi complet : [LISEZMOI.md](LISEZMOI.md) · Sources et mentions : [NOTICE.md](NOTICE.md) · Licence : MIT
