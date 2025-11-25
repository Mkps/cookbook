# 🚀 Guide d'Utilisation - VibeStream avec API Scorton Radar

## 🎯 Vue d'ensemble

VibeStream peut maintenant utiliser **l'API réelle de Scorton Radar** pour analyser n'importe quel site web en temps réel !

---

## 🔐 Prérequis : Obtenir votre clé API

### Étape 1 : Créer un compte Scorton

1. Allez sur **[https://radar.scorton.tech/ui/](https://radar.scorton.tech/ui/)**
2. Créez un compte (email + mot de passe)
3. Vérifiez votre email

### Étape 2 : Générer une clé API

1. Connectez-vous sur Scorton Radar
2. Allez dans **Paramètres** ou **API Keys**
3. Cliquez sur **"Générer une clé API"**
4. Copiez votre clé (format: `sk-xxx...`)

⚠️ **IMPORTANT** : Gardez votre clé secrète !

---

## 💻 Utilisation

### Installation des dépendances

```bash
cd vibestream/
pip install -r requirements.txt --break-system-packages
```

### 1️⃣ Tester votre connexion

```bash
python main_radar.py --api-key YOUR_API_KEY --test-connection
```

**Résultat attendu** :
```
🔐 Test de connexion à Scorton Radar API...

🔐 Vérification de la clé API...
✅ Clé API valide!
📊 Informations de la clé: {...}
📈 Usage: {...}

✅ Connexion réussie! Vous pouvez maintenant analyser des sites.
```

---

### 2️⃣ Analyser un site web

```bash
python main_radar.py --api-key YOUR_API_KEY --url https://example.com
```

**Exemple complet** :
```bash
python main_radar.py \
  --api-key sk-abc123xyz... \
  --url https://scorton.tech \
  --save-raw \
  --output ./rapports
```

**Options** :
- `--api-key` : Votre clé API Scorton (OBLIGATOIRE)
- `--url` : Site à analyser
- `--save-raw` : Sauvegarder les données brutes JSON de l'API
- `--output` : Dossier de sortie (défaut: `./reports`)

**Résultat** :
```
======================================================================
🎯 VIBESTREAM - ANALYSE VIA SCORTON RADAR
======================================================================

🔐 Vérification de la clé API...
✅ Clé API valide!

🔍 Scan du site: https://scorton.tech
🔍 Analyse de https://scorton.tech via Scorton Radar...
✅ Analyse terminée avec succès
💾 Données sauvegardées dans ./reports/raw_data_scorton.tech_20251125.json

📊 Parsing des données...
✅ Domaine: scorton.tech
   📍 IP: 104.21.45.123
   🏢 Hébergement: cloud
   🌍 Risque GeoIP: low

🔍 Détection des signaux...
  ├─ Total: 12 signaux
  ├─ 🔴 Critiques: 2
  ├─ 🟠 Élevés: 2
  ├─ 🟡 Moyens: 6
  └─ 🟢 Faibles: 2

  🚨 Signaux CRITIQUES détectés:
     • WHOIS introuvable
     • Ports critiques exposés publiquement

🎯 Analyse des risques...
  ├─ Hypothèses: 5
  ├─ ⚠️  Impact critique: 1
  └─ ⚠️  Impact élevé: 3

  🎯 Risque principal: Compromission par scan de ports
     Score: 82/100

📄 Génération du rapport...
✅ Rapport généré: ./reports/vibestream_report_scorton.tech_20251125.html
✅ Analyse JSON: ./reports/vibestream_analysis_scorton.tech_20251125.json

======================================================================
📋 RÉSUMÉ DE L'ANALYSE
======================================================================

🎯 Score Global: 66.21/100 (MEDIUM)

🚨 SIGNAUX FORTS (4):
  [CRITICAL] WHOIS introuvable
  [CRITICAL] Ports critiques exposés publiquement
  [HIGH] Content Security Policy absente
  [HIGH] Ports suspects exposés

🎯 HYPOTHÈSES DE RISQUES (5):
  1. Compromission par scan de ports
     • Probabilité: HIGH | Impact: CRITICAL
     • Score: 82/100
  2. Attaque XSS et injection de code
     • Probabilité: HIGH | Impact: HIGH
     • Score: 70/100
  3. Fuite ou vol de données
     • Probabilité: MEDIUM | Impact: HIGH
     • Score: 60/100

======================================================================

🎉 Analyse terminée avec succès!
📄 Rapport HTML: file:///path/to/reports/vibestream_report_scorton.tech_20251125.html
```

---

### 3️⃣ Analyser depuis un fichier sauvegardé

Si vous avez déjà effectué un scan et sauvegardé les données brutes :

```bash
python main_radar.py \
  --api-key YOUR_API_KEY \
  --file ./reports/raw_data_scorton.tech_20251125.json
```

⚠️ **Note** : La clé API est toujours nécessaire pour valider l'accès

---

## 📊 Fichiers Générés

Après chaque analyse, vous obtenez :

### 1. Rapport HTML
**Nom** : `vibestream_report_<domain>_<timestamp>.html`

Contient :
- Dashboard avec scores
- Signaux détectés (critiques → faibles)
- Hypothèses de risques avec scénarios
- Stack technologique
- Détails techniques complets

### 2. Analyse JSON
**Nom** : `vibestream_analysis_<domain>_<timestamp>.json`

Contient :
- Tous les signaux détectés
- Toutes les hypothèses de risques
- Résumés et statistiques
- Métadonnées (IP, hébergement, âge du domaine, etc.)

### 3. Données Brutes (optionnel avec `--save-raw`)
**Nom** : `raw_data_<domain>_<timestamp>.json`

Contient :
- **TOUTES** les 47 features de l'API Scorton Radar
- Données brutes non traitées
- Utile pour analyse avancée ou debugging

---

## 🎯 Avantages de l'API Radar

### ✅ Données en Temps Réel
- Scan frais à chaque requête
- Informations à jour (certificats, ports, etc.)
- Détection des changements récents

### ✅ 47 Features Complètes
L'API Radar fournit :
- Analyse TLS/SSL détaillée
- Scan de ports complet
- Headers HTTP de sécurité
- WHOIS et DNS
- Stack technologique
- Trackers et cookies
- CVE et vulnérabilités
- Carbon footprint
- Ranking
- Et bien plus...

### ✅ Scores ML/DL/AI
- Score Machine Learning
- Score Deep Learning
- Score AI global
- Score technique
- Analyse de risque complète

---

## 🔧 Options Avancées

### Analyser plusieurs sites

```bash
# Créer un script bash
for url in "https://example.com" "https://test.com" "https://demo.com"
do
  python main_radar.py --api-key YOUR_KEY --url "$url" --save-raw
  sleep 5  # Pause entre les requêtes
done
```

### Définir un répertoire personnalisé

```bash
python main_radar.py \
  --api-key YOUR_KEY \
  --url https://example.com \
  --output /path/to/custom/directory
```

### Mode silencieux (pour scripts)

```bash
python main_radar.py \
  --api-key YOUR_KEY \
  --url https://example.com \
  2>/dev/null  # Masquer les erreurs
```

---

## ⚠️ Limites et Rate Limiting

### Rate Limits
- **Free tier** : X requêtes/heure (voir documentation Scorton)
- **Premium** : Limites plus élevées

Si vous atteignez la limite :
- L'API retourne une erreur 429
- VibeStream attend automatiquement (backoff exponentiel)
- Réessaye jusqu'à 3 fois

### Bonnes Pratiques
- Ne pas lancer trop de scans simultanés
- Espacer les requêtes de quelques secondes
- Utiliser les données sauvegardées (`raw_data_*.json`) pour tester

---

## 🆘 Dépannage

### Erreur : "Clé API invalide"
```
❌ Clé API invalide ou expirée
```

**Solution** :
1. Vérifiez que vous avez copié la clé complète
2. Régénérez une nouvelle clé sur Scorton Radar
3. Vérifiez que votre compte est actif

### Erreur : "Timeout"
```
⏱️  Timeout (tentative 1/3)
```

**Solution** :
- Vérifiez votre connexion internet
- Le serveur Scorton peut être temporairement surchargé
- Réessayez dans quelques minutes

### Erreur : "Rate limit atteint"
```
⏳ Rate limit atteint. Attente de 2s...
```

**Solution** :
- Attendez que le script réessaye automatiquement
- Espacez vos requêtes
- Upgradez vers Premium pour plus de requêtes

---

## 📚 Exemples Pratiques

### Exemple 1 : Audit de sécurité rapide

```bash
python main_radar.py \
  --api-key YOUR_KEY \
  --url https://mycompany.com \
  --save-raw
```

Ouvrez le rapport HTML généré pour voir les failles.

### Exemple 2 : Comparaison avant/après

```bash
# Avant les corrections
python main_radar.py --api-key YOUR_KEY --url https://site.com --output ./avant

# Après les corrections (1 semaine plus tard)
python main_radar.py --api-key YOUR_KEY --url https://site.com --output ./apres

# Comparez les scores dans les rapports HTML
```

### Exemple 3 : Monitoring continu

```bash
# Créer un cron job (Linux/Mac)
# Tous les jours à 9h
0 9 * * * cd /path/to/vibestream && python main_radar.py --api-key YOUR_KEY --url https://mysite.com --output ./daily-reports
```

---

## 🎓 Différences avec l'ancien mode

| Fonctionnalité | Mode Ancien (`main.py`) | Mode Radar (`main_radar.py`) |
|----------------|------------------------|------------------------------|
| Source de données | Fichier JSON statique | API Scorton Radar en temps réel |
| Clé API | Optionnelle | **OBLIGATOIRE** |
| Données | Limitées (exemple) | **47 features complètes** |
| Fraîcheur | Statique | **Temps réel** |
| Usage | Tests/démo | **Production** |

---

## 🚀 Prochaines Étapes

1. ✅ Testez votre connexion : `--test-connection`
2. ✅ Analysez votre premier site : `--url`
3. ✅ Explorez le rapport HTML généré
4. ✅ Corrigez les vulnérabilités détectées
5. ✅ Ré-analysez pour vérifier les améliorations

---

## 📞 Support

- **Documentation Scorton** : https://radar.scorton.tech/docs
- **Interface Web** : https://radar.scorton.tech/ui/
- **Swagger API** : https://radar.scorton.tech/swagger

---

**Bon scan avec l'API Scorton Radar ! 🎯🚀**
