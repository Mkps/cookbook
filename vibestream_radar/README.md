# 🔍 VibeStream - Web Security Analyzer

**Challenge 1 - Scorton Cybersecurity Hackathon**

Outil d'analyse externe de sites web pour la détection de signaux cyber, d'anomalies et la formulation d'hypothèses de risques.

---

## 📋 Objectifs

VibeStream répond aux 4 exigences principales du challenge :

1. ✅ **Scan technique** : Analyse complète des données web (TLS, ports, headers, WHOIS, DNSSEC)
2. ✅ **Extraction de signaux faibles et forts** : Détection hiérarchisée des vulnérabilités
3. ✅ **Détection d'anomalies** : Identification des comportements atypiques
4. ✅ **Hypothèses de risques** : Formulation de scénarios de menaces basés sur les signaux

---

## 🚀 Installation

### Prérequis
- Python 3.9+
- Accès à l'API Scorton (extension Chrome/Firefox installée)

### Installation des dépendances

```bash
cd vibestream
pip install -r requirements.txt
```

---

## 📖 Usage

### Méthode 1 : Analyse de données existantes

```bash
python main.py scorton_data.json
```

### Méthode 2 : Avec vos propres données

1. Obtenez les données de scan depuis l'API Scorton
2. Sauvegardez-les en JSON
3. Lancez l'analyse :

```bash
python main.py mon_scan.json
```

---

## 📂 Structure du Projet

```
vibestream/
├── main.py                     # Point d'entrée principal
├── analyzer.py                 # Moteur d'analyse de signaux
├── report_generator.py         # Générateur de rapports HTML
├── scorton_data.json          # Exemple de données (scorton.tech)
├── vibestream_report.json     # Rapport JSON généré
├── vibestream_report.html     # Rapport HTML interactif
├── requirements.txt           # Dépendances Python
└── README.md                  # Documentation
```

---

## 🔬 Méthodologie d'Analyse

### 1. Scan Technique

L'analyseur examine :
- **Certificat TLS** : Force du chiffrement, expiration, validité
- **Ports réseau** : Ports ouverts, services exposés
- **Headers HTTP** : CSP, HSTS, X-Frame-Options, X-XSS-Protection
- **WHOIS** : Âge du domaine, propriétaire, registrar
- **DNSSEC** : Validation de l'authenticité DNS
- **Technologies** : Stack technique, trackers, versions

### 2. Signaux Forts vs Faibles

#### Signaux Forts (CRITICAL/HIGH)
- Ports administratifs exposés (SSH, RDP, bases de données)
- Certificats auto-signés ou expirés
- Absence de CSP (Content Security Policy)
- WHOIS introuvable

#### Signaux Faibles (MEDIUM/LOW)
- Headers de sécurité manquants (X-Frame-Options)
- DNSSEC non configuré
- Trop de ports ouverts
- Trackers excessifs

### 3. Détection d'Anomalies

Le système détecte les comportements **atypiques** par rapport aux standards :
- Ports non-web exposés sur un site standard
- Configuration incohérente des headers de sécurité
- Absence de données WHOIS pour un domaine actif

### 4. Hypothèses de Risques

Basées sur les signaux collectés, l'outil formule des **scénarios de menaces** :
- Serveur de développement exposé en production
- Domaine potentiellement illégitime
- Absence de processus de sécurité établi
- Configuration partielle suggérant une mise en conformité incomplète

---

## 📊 Exemple de Résultat (scorton.tech)

### Résumé Exécutif

```
🚨 Signaux Forts (Critiques)    : 3
⚠️  Signaux Faibles             : 8
🔎 Anomalies Détectées          : 3
💡 Hypothèses Formulées         : 4
🎯 Niveau de Risque Global      : HIGH
```

### Signaux Forts Détectés

1. **[CRITICAL] Ports sensibles exposés publiquement**
   - Ports : 22 (SSH), 3389 (RDP), 389 (LDAP), 5060 (SIP)
   - Impact : Risque d'attaque par force brute, accès non autorisé
   - Remédiation : Restreindre l'accès via firewall/VPN

2. **[HIGH] WHOIS introuvable**
   - Impact : Impossible de vérifier la légitimité du domaine
   - Remédiation : Vérifier l'enregistrement auprès du registrar

3. **[HIGH] Content Security Policy non configurée**
   - Impact : Vulnérable aux attaques XSS
   - Remédiation : Implémenter une CSP stricte

### Anomalies Identifiées

1. **Network Security** : Ports administratifs exposés (22, 3389)
   - Probabilité : High
   - Un site web standard ne devrait exposer que 80/443

2. **Domain Security** : WHOIS inaccessible pour un domaine actif
   - Probabilité : Medium
   - Inhabituel pour un site légitime

3. **HTTP Security** : Headers manquants (CSP, X-Frame-Options, X-XSS-Protection)
   - Probabilité : High
   - Configuration incomplète

### Hypothèses de Risques

1. **Serveur de développement exposé en production**
   - Probabilité : High
   - Raisonnement : Ports administratifs + absence de restrictions réseau
   - Risque : Compromission du serveur

2. **Domaine récemment enregistré ou problème d'enregistrement**
   - Probabilité : Medium
   - Raisonnement : WHOIS introuvable
   - Risque : Perte du domaine, légitimité douteuse

3. **Absence de processus de sécurité établi**
   - Probabilité : High
   - Raisonnement : Multiples défauts de sécurité fondamentaux
   - Risque : Surface d'attaque importante

---

## 📈 Scores Techniques

| Métrique | Score |
|----------|-------|
| Score Technique | 66.21/100 |
| Score ML | 98.90/100 |
| Score DL | 57.36/100 |
| Score AI | 78.13/100 |
| **Score Final** | **66.21/100** |

### Catégories

- **Network Security** : 61.5/100 (Grade D) ⚠️
- **Data Protection** : 85/100 (Grade B) ✓
- **Access Control** : 78.8/100 (Grade C)
- **Security Awareness** : 67.4/100 (Grade D) ⚠️

---

## 🎯 Points Forts du Projet

### ✅ Conformité au Challenge

- **Scan technique complet** : TLS, ports, headers, WHOIS, DNSSEC
- **Hiérarchisation des signaux** : Classification claire (CRITICAL → LOW)
- **Détection d'anomalies non triviales** : Ports administratifs exposés
- **Hypothèses contextualisées** : Scénarios de menaces argumentés

### 🌟 Fonctionnalités Bonus

1. **Signaux faibles précoces** : Détection de CSP partiellement implémentée
2. **Rapport professionnel** : HTML interactif + JSON structuré
3. **Visualisation claire** : Design moderne, codes couleurs
4. **Scoring multi-dimensionnel** : 4 scores différents analysés

### 🧠 Détection Intelligente

- **Analyse contextuelle** : Pas de simple checklist, mais compréhension du contexte
- **Corrélation de signaux** : Les hypothèses combinent plusieurs indicateurs
- **Sévérité graduée** : 4 niveaux (CRITICAL, HIGH, MEDIUM, LOW)

---

## 🔮 Améliorations Futures

### Fonctionnalités Avancées
- Cache WHOIS pour optimiser les requêtes
- Timeline de détection avec historique
- Export PDF du rapport
- Comparaison multi-sites
- Intégration API Scorton directe

### Détection Enrichie
- Base CVE pour les technologies détectées
- Machine Learning pour prédiction de risques
- Analyse de réputation (VirusTotal, URLhaus)
- Vérification de blocklists

### Visualisations
- Graphiques de scores
- Timeline d'événements
- Carte réseau des ports
- Matrice de risques

---

## 📝 Notes Techniques

### Seuils de Détection

```python
THRESHOLDS = {
    'tls_expiry_warning': 90 jours
    'tls_expiry_critical': 30 jours
    'max_open_ports': 5
    'min_security_score': 70/100
    'dangerous_ports': [22, 23, 3389, 5900, 3306, ...]
}
```

### Format de Sortie

**JSON** : Données structurées pour intégration
**HTML** : Rapport visuel pour présentation

---

## 🏆 Livrables

✅ **API de collecte et analyse** : Module `analyzer.py`  
✅ **Dataset minimal** : `scorton_data.json` (scorton.tech)  
✅ **Page d'audit claire** : `vibestream_report.html`  
✅ **Rapport professionnel** : Design moderne, explications détaillées  

---

## 👤 Auteur

Projet réalisé dans le cadre du **Scorton Cybersecurity Hackathon - Challenge 1**

---

## 📄 Licence

Ce projet est fourni à des fins éducatives dans le cadre du hackathon Scorton.
