#!/usr/bin/env python3
"""
VibeStream - Analyse externe de sites web et détection d'anomalies
Point d'entrée principal de l'application
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.scorton_client import ScortonClient
from analyzers.signal_detector import SignalDetector
from analyzers.risk_analyzer import RiskAnalyzer
from reports.generator import ReportGenerator


class VibeStream:
    """Application principale VibeStream"""
    
    def __init__(self, api_token=None):
        """
        Initialise VibeStream
        
        Args:
            api_token: Token API Scorton (optionnel)
        """
        self.client = ScortonClient(api_token=api_token)
        self.signal_detector = SignalDetector()
        self.report_generator = ReportGenerator()
    
    def analyze_from_url(self, url: str, output_dir: str = './reports') -> str:
        """
        Analyse un site web via l'API Scorton
        
        Args:
            url: URL du site à analyser
            output_dir: Répertoire de sortie des rapports
            
        Returns:
            Chemin du rapport généré
        """
        print(f"🔍 Scan du site: {url}")
        
        # Collecter les données
        raw_data = self.client.scan_website(url)
        
        if not raw_data:
            print("❌ Erreur: Impossible de récupérer les données")
            return None
        
        # Analyser
        return self._analyze_and_report(raw_data, output_dir)
    
    def analyze_from_file(self, filepath: str, output_dir: str = './reports') -> str:
        """
        Analyse des données depuis un fichier JSON
        
        Args:
            filepath: Chemin vers le fichier JSON
            output_dir: Répertoire de sortie des rapports
            
        Returns:
            Chemin du rapport généré
        """
        print(f"📂 Chargement des données depuis: {filepath}")
        
        # Charger les données
        raw_data = self.client.load_from_file(filepath)
        
        if not raw_data:
            print("❌ Erreur: Impossible de charger le fichier")
            return None
        
        # Analyser
        return self._analyze_and_report(raw_data, output_dir)
    
    def _analyze_and_report(self, raw_data: dict, output_dir: str) -> str:
        """
        Analyse les données et génère le rapport
        
        Args:
            raw_data: Données brutes du scan
            output_dir: Répertoire de sortie
            
        Returns:
            Chemin du rapport généré
        """
        # Parser les données
        print("📊 Parsing des données...")
        data = self.client.parse_response(raw_data)
        
        if not data:
            print("❌ Erreur: Données invalides")
            return None
        
        domain = data.get('domain', 'unknown')
        print(f"✅ Domaine: {domain}")
        
        # Détecter les signaux
        print("\n🔍 Détection des signaux...")
        signals = self.signal_detector.analyze(data)
        signal_summary = self.signal_detector.get_summary()
        
        print(f"  ├─ Total: {signal_summary['total']} signaux")
        print(f"  ├─ Critiques: {signal_summary['by_severity']['CRITICAL']}")
        print(f"  ├─ Élevés: {signal_summary['by_severity']['HIGH']}")
        print(f"  ├─ Moyens: {signal_summary['by_severity']['MEDIUM']}")
        print(f"  └─ Faibles: {signal_summary['by_severity']['LOW']}")
        
        # Analyser les risques
        print("\n🎯 Analyse des risques...")
        risk_analyzer = RiskAnalyzer(signals, data)
        hypotheses = risk_analyzer.analyze()
        risk_summary = risk_analyzer.get_summary()
        
        print(f"  ├─ Hypothèses: {risk_summary['total_hypotheses']}")
        print(f"  ├─ Impact critique: {risk_summary['by_impact']['critical']}")
        print(f"  └─ Impact élevé: {risk_summary['by_impact']['high']}")
        
        # Générer le rapport
        print("\n📄 Génération du rapport...")
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"vibestream_report_{domain}_{timestamp}.html"
        report_path = os.path.join(output_dir, report_filename)
        
        self.report_generator.generate(data, signals, hypotheses, report_path)
        
        print(f"✅ Rapport généré: {report_path}")
        
        # Sauvegarder aussi en JSON
        json_filename = f"vibestream_data_{domain}_{timestamp}.json"
        json_path = os.path.join(output_dir, json_filename)
        
        export_data = {
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'scores': data.get('scores', {}),
            'signals': [s.to_dict() for s in signals],
            'signal_summary': signal_summary,
            'hypotheses': [h.to_dict() for h in hypotheses],
            'risk_summary': risk_summary,
            'raw_data': data
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Données JSON: {json_path}")
        
        return report_path


def main():
    """Point d'entrée CLI"""
    parser = argparse.ArgumentParser(
        description='VibeStream - Analyse externe de sites web et détection d\'anomalies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Analyser depuis un fichier JSON
  python main.py --file scorton_data.json
  
  # Analyser un site web (nécessite un token API)
  python main.py --url https://example.com --token YOUR_API_TOKEN
  
  # Spécifier un répertoire de sortie
  python main.py --file data.json --output ./mes_rapports
        """
    )
    
    parser.add_argument('--url', type=str, help='URL du site à analyser')
    parser.add_argument('--file', type=str, help='Fichier JSON contenant les données')
    parser.add_argument('--token', type=str, help='Token API Scorton')
    parser.add_argument('--output', type=str, default='./reports', 
                       help='Répertoire de sortie (défaut: ./reports)')
    
    args = parser.parse_args()
    
    # Vérifier les arguments
    if not args.url and not args.file:
        parser.error("Vous devez spécifier --url ou --file")
    
    # Initialiser VibeStream
    vibestream = VibeStream(api_token=args.token)
    
    # Analyser
    try:
        if args.file:
            report_path = vibestream.analyze_from_file(args.file, args.output)
        else:
            if not args.token:
                print("⚠️  Warning: Aucun token API fourni. Utilisation en mode démo.")
            report_path = vibestream.analyze_from_url(args.url, args.output)
        
        if report_path:
            print("\n🎉 Analyse terminée avec succès!")
            print(f"📄 Ouvrez le rapport: file://{os.path.abspath(report_path)}")
        
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
