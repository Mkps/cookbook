# 🚀 Guide de Démarrage Rapide - VibeStream

## ⏱️ Démarrage en 3 minutes

### Étape 1: Installation (30 secondes)

```bash
cd vibestream/
pip install -r requirements.txt --break-system-packages
```

### Étape 2: Test avec données exemple (10 secondes)

```bash
python main.py --file test_data.json
```

### Étape 3: Voir le rapport (10 secondes)

Ouvrir le fichier HTML généré dans `./reports/`

---

## 📋 Commandes rapides

### Analyser un fichier JSON
```bash
python main.py --file mon_scan.json
```

### Analyser avec l'API Scorton
```bash
python main.py --url https://example.com --token YOUR_TOKEN
```

### Spécifier le dossier de sortie
```bash
python main.py --file data.json --output ./mes_rapports
```

---

## 🎯 Ce que fait VibeStream

1. **Collecte** les données techniques d'un site
2. **Détecte** 12+ types de signaux de sécurité
3. **Analyse** et formule des hypothèses de risques
4. **Génère** un rapport HTML professionnel

---

## 📊 Résultat attendu

```
🔍 Détection des signaux...
  ├─ Total: 12 signaux
  ├─ Critiques: 2        ← WHOIS, Ports SSH/RDP
  ├─ Élevés: 2           ← CSP absente, Ports LDAP
  ├─ Moyens: 6           ← DNSSEC, Headers
  └─ Faibles: 2          ← Security.txt, Trackers

🎯 Analyse des risques...
  ├─ Hypothèses: 5
  ├─ Impact critique: 1   ← Compromission serveur
  └─ Impact élevé: 3      ← XSS, Data breach, RGPD
```

---

## 🆘 Aide

### Voir toutes les options
```bash
python main.py --help
```

### Problème d'installation
```bash
pip install --upgrade pip
pip install -r requirements.txt --break-system-packages --no-cache-dir
```

### Données de test manquantes
Le fichier `test_data.json` contient un exemple de scan de scorton.tech

---

## 📖 Documentation complète

Voir `README_COMPLET.md` pour:
- Architecture détaillée
- Tous les types de signaux détectés
- Critères du challenge
- Exemples de résultats
- Améliorations futures
