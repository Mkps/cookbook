#!/bin/bash
# Script de lancement - Version Radar avec API

echo "🎯 VibeStream Radar - Analyse avec API Scorton"
echo "================================================"
echo ""

# Vérifier si on est dans le bon répertoire
if [ ! -f "main_radar.py" ]; then
    echo "❌ Erreur: Veuillez exécuter ce script depuis le dossier vibestream_radar/"
    echo "   cd vibestream_radar/ && ./run_radar.sh"
    exit 1
fi

# Créer les fichiers __init__.py si manquants (fix pour le module import)
echo "📁 Vérification de la structure..."
for dir in api analyzers reports utils; do
    if [ ! -f "$dir/__init__.py" ]; then
        echo "   ✅ Création de $dir/__init__.py"
        echo '"""Package '$dir'"""' > "$dir/__init__.py"
    fi
done
echo ""

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

echo "✅ Python détecté: $(python3 --version)"
echo ""

# Vérifier si une clé API est fournie
if [ -z "$SCORTON_API_KEY" ] && [ $# -eq 0 ]; then
    echo "⚠️  Aucune clé API fournie!"
    echo ""
    echo "📖 Utilisation:"
    echo "   Méthode 1: Variable d'environnement"
    echo "   export SCORTON_API_KEY='your-key-here'"
    echo "   ./run_radar.sh https://example.com"
    echo ""
    echo "   Méthode 2: Argument direct"
    echo "   ./run_radar.sh your-key-here https://example.com"
    echo ""
    echo "🔐 Obtenez votre clé sur: https://radar.scorton.tech/ui/"
    exit 1
fi

# Installer les dépendances si nécessaire
if [ ! -d ".venv" ]; then
    echo "📦 Installation des dépendances..."
    pip3 install -r requirements.txt --break-system-packages 2>&1 | grep -E "(Successfully|Requirement already)"
    echo ""
fi

# Déterminer la clé API et l'URL
if [ $# -eq 2 ]; then
    # Format: ./run_radar.sh API_KEY URL
    API_KEY="$1"
    URL="$2"
elif [ $# -eq 1 ]; then
    # Format: ./run_radar.sh URL (avec variable d'env)
    API_KEY="$SCORTON_API_KEY"
    URL="$1"
else
    echo "❌ Arguments invalides"
    echo "Usage: ./run_radar.sh [API_KEY] URL"
    exit 1
fi

# Lancer l'analyse
echo "🔍 Analyse de: $URL"
echo ""

python3 main_radar.py --api-key "$API_KEY" --url "$URL" --save-raw --output ./reports

echo ""
echo "✅ Terminé ! Ouvrez le rapport HTML dans ./reports/"
