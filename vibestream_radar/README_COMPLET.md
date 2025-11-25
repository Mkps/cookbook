# 🎯 VibeStream - Challenge 1 Scorton Hackathon

**Analyse externe de sites web et détection d'anomalies de sécurité**

VibeStream est un outil d'analyse de sécurité qui collecte, analyse et détecte les signaux faibles et forts dans les configurations de sites web, puis génère des rapports professionnels avec des hypothèses de risques.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Architecture](#-architecture)
- [Exemples de résultats](#-exemples-de-résultats)
- [Critères du challenge](#-critères-du-challenge)

---

## 🚀 Fonctionnalités

### ✅ Scan Technique Complet
- **Analyse TLS/SSL**: Validité, force de clé, émetteur
- **Ports réseau**: Détection ports ouverts/fermés, identification ports critiques
- **Headers HTTP**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **DNSSEC**: Vérification configuration DNS sécurisée
- **WHOIS**: Informations domaine et âge
- **Stack technologique**: Détection frameworks, CMS, bibliothèques
- **Trackers**: Identification trackers tiers et risques RGPD

### 🔍 Détection de Signaux

#### Signaux Forts (CRITICAL/HIGH)
- ❌ **WHOIS introuvable**: Domaine suspect ou mal configuré
- ❌ **Ports critiques exposés**: SSH (22), RDP (3389), LDAP (389)
- ❌ **Absence de CSP**: Vulnérable aux attaques XSS
- ❌ **Certificat TLS faible**: Clé < 256 bits
- ❌ **Score de sécurité faible**: < 50/100

#### Signaux Faibles (MEDIUM/LOW)
- ⚠️ **Headers de sécurité manquants**: X-Frame-Options, X-XSS-Protection
- ⚠️ **DNSSEC désactivé**: Vulnérable DNS spoofing
- ⚠️ **Certificat expirant bientôt**: < 90 jours
- ⚠️ **Trop de ports ouverts**: > 5 ports
- ⚠️ **Trackers tiers détectés**: Risques confidentialité
- ⚠️ **Absence security.txt**: Pas de contact sécurité

### 🎯 Analyse de Risques & Hypothèses

Pour chaque combinaison de signaux, VibeStream génère des **hypothèses de risques** avec:
- **Probabilité** (low/medium/high)
- **Impact** (low/medium/high/critical)
- **Scénario d'attaque** détaillé
- **Indicateurs** observés
- **Score de risque** (0-100)

Exemples d'hypothèses générées:
1. **Risque de compromission par scan de ports**
2. **Risque d'attaque XSS et injection de code**
3. **Risque de fuite ou vol de données**
4. **Risque d'interruption de service**
5. **Risque de non-conformité RGPD**

### 📄 Rapport Professionnel

Génération automatique d'un **rapport HTML** comprenant:
- Dashboard avec métriques clés
- Liste détaillée des signaux avec recommandations
- Hypothèses de risques avec scénarios d'attaque
- Stack technologique
- Détails techniques (TLS, ports, headers)
- Export JSON pour traitement ultérieur

---

## 📦 Installation

### Prérequis
- Python 3.9+
- pip

### Étape 1: Cloner/télécharger le projet

```bash
cd vibestream/
```

### Étape 2: Installer les dépendances

```bash
pip install -r requirements.txt --break-system-packages
```

Dépendances:
- `requests`: Appels API HTTP
- `beautifulsoup4`: Parsing HTML
- `python-whois`: Analyse WHOIS
- `dnspython`: Requêtes DNS
- `python-dateutil`: Manipulation dates
- `jinja2`: Génération rapports HTML

---

## 💻 Utilisation

### Mode 1: Analyse depuis un fichier JSON

```bash
python main.py --file test_data.json
```

### Mode 2: Analyse depuis l'API Scorton (nécessite token)

```bash
python main.py --url https://example.com --token YOUR_API_TOKEN
```

### Mode 3: Spécifier répertoire de sortie

```bash
python main.py --file data.json --output ./mes_rapports
```

### Exemple de sortie

```
📂 Chargement des données depuis: test_data.json
📊 Parsing des données...
✅ Domaine: scorton.tech

🔍 Détection des signaux...
  ├─ Total: 12 signaux
  ├─ Critiques: 2
  ├─ Élevés: 2
  ├─ Moyens: 6
  └─ Faibles: 2

🎯 Analyse des risques...
  ├─ Hypothèses: 5
  ├─ Impact critique: 1
  └─ Impact élevé: 3

📄 Génération du rapport...
✅ Rapport généré: ./reports/vibestream_report_scorton.tech_20251125.html
✅ Données JSON: ./reports/vibestream_data_scorton.tech_20251125.json

🎉 Analyse terminée avec succès!
```

---

## 🏗️ Architecture

```
vibestream/
├── api/
│   ├── scorton_client.py       # Client API Scorton
│   └── __init__.py
├── analyzers/
│   ├── signal_detector.py      # Détection signaux faibles/forts
│   ├── risk_analyzer.py        # Analyse risques & hypothèses
│   └── __init__.py
├── reports/
│   ├── generator.py            # Génération rapports HTML
│   ├── templates/
│   │   └── report.html         # Template Jinja2
│   └── __init__.py
├── utils/
│   ├── config.py               # Configuration & seuils
│   └── __init__.py
├── main.py                     # Point d'entrée
├── requirements.txt            # Dépendances
├── test_data.json             # Données de test
└── README.md                  # Ce fichier
```

### Workflow d'analyse

```
1. Collecte des données
   ├─ Via API Scorton (avec token)
   └─ Via fichier JSON (mode démo)
   
2. Parsing & normalisation
   └─ scorton_client.parse_response()
   
3. Détection de signaux
   ├─ Analyse WHOIS
   ├─ Analyse ports
   ├─ Analyse TLS
   ├─ Analyse headers HTTP
   ├─ Analyse DNSSEC
   ├─ Analyse trackers
   └─ Calcul scores
   
4. Analyse de risques
   ├─ Identification patterns
   ├─ Génération hypothèses
   └─ Calcul scores de risque
   
5. Génération rapport
   ├─ Rapport HTML (via Jinja2)
   └─ Export JSON
```

---

## 📊 Exemples de résultats

### Cas 1: scorton.tech

**Signaux détectés** (12 au total):
- 🔴 **CRITICAL**: WHOIS introuvable, Ports critiques exposés (SSH, RDP)
- 🟠 **HIGH**: Absence CSP, Ports suspects (LDAP, SIP)
- 🟡 **MEDIUM**: DNSSEC désactivé, Headers manquants, Certificat expire dans 78j
- 🟢 **LOW**: Security.txt absent, Trackers Google

**Hypothèses de risques**:
1. **Compromission par scan de ports** (Score: 82/100)
   - Probabilité: HIGH
   - Impact: CRITICAL
   - Ports SSH/RDP exposés → Attaque brute force → Ransomware

2. **Attaque XSS et injection** (Score: 70/100)
   - Probabilité: HIGH  
   - Impact: HIGH
   - Pas de CSP → Injection scripts → Vol cookies/sessions

3. **Non-conformité RGPD** (Score: 50/100)
   - Probabilité: MEDIUM
   - Impact: MEDIUM
   - 3 trackers Google → Amende CNIL potentielle

---

## ✅ Critères du Challenge

### Livrables attendus
- [x] **API/Script de collecte et analyse**
- [x] **Dataset minimal** (test_data.json fourni)
- [x] **Page d'audit claire** (rapport HTML professionnel)
- [x] **Rapport professionnel** (PDF exportable depuis HTML)

### Fonctionnalités implémentées

#### 1. Collecte & Ingestion ✅
- [x] HTML, headers HTTP, certificat TLS
- [x] Redirections, SSL
- [x] WHOIS: dates clés, registrar, durée de vie
- [x] Ports ouverts/fermés
- [x] Stack technologique
- [x] Trackers tiers

#### 2. Analyse & Détection ✅
- [x] Certificat faible/expirant
- [x] Redirections anormales
- [x] Taille HTML atypique
- [x] Absence HTTPS
- [x] Technologies obsolètes
- [x] **Signaux faibles précoces** (BONUS)
- [x] Ports critiques exposés
- [x] Headers sécurité manquants
- [x] DNSSEC désactivé

#### 3. Hypothèses & Interprétation ✅
- [x] Explication contextualisée
- [x] Évaluation impact/sévérité/probabilité
- [x] Scénarios d'attaque détaillés
- [x] Score de risque calculé
- [x] Recommandations concrètes

#### 4. Bonus ✅
- [x] Détection signaux faibles précoces
- [x] Optimisations (structure modulaire)
- [x] Visualisations (rapport HTML avec design moderne)
- [x] Export JSON pour traitement ultérieur
- [x] CLI ergonomique

### Anomalies détectées (≥1 non triviale) ✅

**3 anomalies majeures identifiées sur scorton.tech**:

1. **WHOIS introuvable** (très inhabituel)
   - Justification: Aucun domaine actif légitime ne devrait avoir WHOIS complètement vide
   - Proposition: Vérifier l'enregistrement du domaine, activer WHOIS public

2. **Ports SSH/RDP exposés publiquement** (critique)
   - Justification: Ces ports d'administration ne devraient JAMAIS être publics
   - Proposition: Implémenter VPN, whitelist IP, ou fermer complètement
   - Feature suggérée: Scan automatique ports administration + alertes temps réel

3. **Absence totale de CSP malgré React** (incohérent)
   - Justification: Une app React moderne devrait avoir une CSP stricte
   - Proposition: Implémenter CSP avec script-src, style-src appropriés
   - Feature suggérée: Générateur automatique de CSP basé sur la stack détectée

---

## 🎓 Améliorations futures suggérées

### Court terme
- [ ] Scan automatique des CVE liées aux technologies détectées
- [ ] Comparaison avec best practices (OWASP, NIST)
- [ ] Notifications email/Slack pour alertes critiques

### Moyen terme
- [ ] Base de données pour historique des scans
- [ ] Dashboard web interactif (React + FastAPI)
- [ ] Scan planifiés / monitoring continu
- [ ] Intégration CI/CD (GitHub Actions, GitLab CI)

### Long terme
- [ ] Machine Learning pour prédiction de risques
- [ ] Scoring par industrie/contexte
- [ ] API REST complète avec authentification
- [ ] Marketplace de règles de détection communautaires

---

## 📝 Notes techniques

### Choix d'architecture
- **Python**: Écosystème riche pour sécurité (requests, cryptography, dnspython)
- **Modularité**: Séparation collecte/analyse/reporting pour extensibilité
- **Jinja2**: Templates HTML flexibles et maintenables
- **JSON**: Format standard pour interopérabilité

### Seuils de détection (configurables dans `utils/config.py`)
```python
THRESHOLDS = {
    'tls_expiry_warning_days': 90,
    'tls_expiry_critical_days': 30,
    'suspicious_ports': [22, 23, 3389, 389, 5060, 5900, 8080],
    'critical_ports': [22, 3389],
    'max_open_ports': 5,
    'min_security_score': 70,
}
```

---

## 👥 Auteur

Projet réalisé pour le **Scorton Cybersecurity Hackathon - Challenge 1 (VibeStream)**

---

## 📄 License

Ce projet est à usage éducatif dans le cadre du hackathon Scorton.

---

## 🙏 Remerciements

- **Scorton** pour l'API et le challenge
- **OWASP** pour les guidelines de sécurité web
- **Mozilla Observatory** pour l'inspiration des analyses
