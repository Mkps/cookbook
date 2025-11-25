#!/usr/bin/env python3
"""
VibeStream - Analyse externe de sites web via Scorton Radar API
Point d'entrée principal avec API réelle
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.scorton_radar_client import ScortonRadarClient, test_connection
from analyzers.signal_detector import SignalDetector
from analyzers.risk_analyzer import RiskAnalyzer
from reports.generator import ReportGenerator


class VibeStreamRadar:
    """Application principale VibeStream avec API Radar"""
    
    def __init__(self, api_key: str):
        """
        Initialise VibeStream avec API Radar
        
        Args:
            api_key: Clé API Scorton (OBLIGATOIRE)
        """
        if not api_key:
            raise ValueError(
                "❌ Une clé API Scorton est OBLIGATOIRE.\n"
                "👉 Obtenez votre clé sur: https://radar.scorton.tech/ui/\n"
                "   1. Créez un compte\n"
                "   2. Générez une clé API\n"
                "   3. Utilisez: python main_radar.py --api-key YOUR_KEY --url https://example.com"
            )
        
        self.client = ScortonRadarClient(api_key=api_key)
        self.signal_detector = SignalDetector()
        self.report_generator = ReportGenerator()
        
        # Vérifier la clé au démarrage
        print("🔐 Vérification de la clé API...")
        key_info = self.client.verify_key()
        if key_info:
            print("✅ Clé API valide!")
        else:
            raise ValueError("❌ Clé API invalide ou expirée")
    
    def analyze_url(self, url: str, output_dir: str = './reports', 
                    save_raw: bool = True) -> str:
        """
        Analyse une URL via l'API Scorton Radar
        
        Args:
            url: URL du site à analyser
            output_dir: Répertoire de sortie des rapports
            save_raw: Sauvegarder les données brutes JSON
            
        Returns:
            Chemin du rapport généré
        """
        print(f"\n{'='*70}")
        print(f"🎯 VIBESTREAM - ANALYSE VIA SCORTON RADAR")
        print(f"{'='*70}\n")
        
        # Collecter les données via API Radar
        print(f"🔍 Scan du site: {url}")
        raw_data = self.client.analyze_url(url)
        
        if not raw_data:
            print("❌ Erreur: Impossible de récupérer les données")
            return None
        
        # L'API retourne parfois une liste, on prend le premier élément
        if isinstance(raw_data, list) and len(raw_data) > 0:
            raw_data = raw_data[0]
        
        # Si c'est toujours pas un dict, erreur
        if not isinstance(raw_data, dict):
            print(f"❌ Erreur: Format de données inattendu: {type(raw_data)}")
            return None
        
        # Sauvegarder les données brutes si demandé
        if save_raw:
            os.makedirs(output_dir, exist_ok=True)
            domain = raw_data.get('domain', 'unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            raw_filename = f"raw_data_{domain}_{timestamp}.json"
            raw_path = os.path.join(output_dir, raw_filename)
            self.client.save_to_file(raw_data, raw_path)
        
        # Analyser
        return self._analyze_and_report(raw_data, output_dir)
    
    def analyze_from_file(self, filepath: str, output_dir: str = './reports') -> str:
        """
        Analyse des données depuis un fichier JSON sauvegardé
        
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
        
        # Afficher quelques infos clés
        print(f"   📍 IP: {data.get('ip', 'N/A')}")
        print(f"   🏢 Hébergement: {data.get('Hosting_type', 'N/A')}")
        print(f"   🌍 Risque GeoIP: {data.get('GeoIP_risk', 'N/A')}")
        
        # Détecter les signaux
        print("\n🔍 Détection des signaux...")
        signals = self.signal_detector.analyze(data)
        signal_summary = self.signal_detector.get_summary()
        
        print(f"  ├─ Total: {signal_summary['total']} signaux")
        print(f"  ├─ 🔴 Critiques: {signal_summary['by_severity']['CRITICAL']}")
        print(f"  ├─ 🟠 Élevés: {signal_summary['by_severity']['HIGH']}")
        print(f"  ├─ 🟡 Moyens: {signal_summary['by_severity']['MEDIUM']}")
        print(f"  └─ 🟢 Faibles: {signal_summary['by_severity']['LOW']}")
        
        # Afficher les signaux critiques
        critical_signals = [s for s in signals if s.severity == 'CRITICAL']
        if critical_signals:
            print("\n  🚨 Signaux CRITIQUES détectés:")
            for sig in critical_signals:
                print(f"     • {sig.title}")
        
        # Analyser les risques
        print("\n🎯 Analyse des risques...")
        risk_analyzer = RiskAnalyzer(signals, data)
        hypotheses = risk_analyzer.analyze()
        risk_summary = risk_analyzer.get_summary()
        
        print(f"  ├─ Hypothèses: {risk_summary['total_hypotheses']}")
        print(f"  ├─ ⚠️  Impact critique: {risk_summary['by_impact']['critical']}")
        print(f"  └─ ⚠️  Impact élevé: {risk_summary['by_impact']['high']}")
        
        # Afficher le risque principal
        if hypotheses:
            top_risk = hypotheses[0]
            print(f"\n  🎯 Risque principal: {top_risk.title}")
            print(f"     Score: {top_risk._calculate_risk_score()}/100")
        
        # Générer le rapport
        print("\n📄 Génération du rapport...")
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"vibestream_report_{domain}_{timestamp}.html"
        report_path = os.path.join(output_dir, report_filename)
        
        self.report_generator.generate(data, signals, hypotheses, report_path)
        
        print(f"✅ Rapport généré: {report_path}")
        
        # Sauvegarder aussi en JSON
        json_filename = f"vibestream_analysis_{domain}_{timestamp}.json"
        json_path = os.path.join(output_dir, json_filename)
        
        export_data = {
            'domain': domain,
            'url': data.get('url', ''),
            'scan_date': datetime.now().isoformat(),
            'scan_source': 'Scorton Radar API',
            'scores': data.get('scores', {}),
            'signals': [s.to_dict() for s in signals],
            'signal_summary': signal_summary,
            'hypotheses': [h.to_dict() for h in hypotheses],
            'risk_summary': risk_summary,
            'metadata': {
                'ip': data.get('ip'),
                'hosting_type': data.get('Hosting_type'),
                'geoip_risk': data.get('GeoIP_risk'),
                'domain_age_days': data.get('Domain_age_days'),
                'blacklist_hits': data.get('Blacklist_hits')
            }
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Analyse JSON: {json_path}")
        
        # Afficher le résumé final
        self._print_summary(data, signals, hypotheses)
        
        return report_path
    
    def _print_summary(self, data, signals, hypotheses):
        """Affiche un résumé final dans la console"""
        print(f"\n{'='*70}")
        print("📋 RÉSUMÉ DE L'ANALYSE")
        print(f"{'='*70}")
        
        # Score global
        scores = data.get('scores', {})
        print(f"\n🎯 Score Global: {scores.get('final', 0)}/100 ({scores.get('risk_level', 'unknown').upper()})")
        
        # Signaux forts
        strong_signals = [s for s in signals if s.severity in ['CRITICAL', 'HIGH']]
        if strong_signals:
            print(f"\n🚨 SIGNAUX FORTS ({len(strong_signals)}):")
            for signal in strong_signals[:5]:  # Top 5
                print(f"  [{signal.severity}] {signal.title}")
        
        # Hypothèses principales
        if hypotheses:
            print(f"\n🎯 HYPOTHÈSES DE RISQUES ({len(hypotheses)}):")
            for i, hypo in enumerate(hypotheses[:3], 1):  # Top 3
                risk_score = hypo._calculate_risk_score()
                print(f"  {i}. {hypo.title}")
                print(f"     • Probabilité: {hypo.likelihood.upper()} | Impact: {hypo.impact.upper()}")
                print(f"     • Score: {risk_score}/100")
        
        print(f"\n{'='*70}\n")


def main():
    """Point d'entrée CLI avec API Radar"""
    parser = argparse.ArgumentParser(
        description='VibeStream - Analyse externe de sites web via Scorton Radar API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔐 OBTENIR UNE CLÉ API:
   1. Allez sur https://radar.scorton.tech/ui/
   2. Créez un compte
   3. Générez une clé API dans les paramètres

📖 EXEMPLES:
  # Analyser un site web avec votre clé API
  python main_radar.py --api-key YOUR_API_KEY --url https://example.com
  
  # Analyser et sauvegarder les données brutes
  python main_radar.py --api-key YOUR_KEY --url https://example.com --save-raw
  
  # Analyser depuis un fichier JSON sauvegardé
  python main_radar.py --api-key YOUR_KEY --file raw_data.json
  
  # Tester la connexion API
  python main_radar.py --api-key YOUR_KEY --test-connection
  
  # Spécifier un répertoire de sortie
  python main_radar.py --api-key YOUR_KEY --url https://example.com --output ./mes_rapports

⚠️  NOTE: Une clé API est OBLIGATOIRE pour utiliser ce script.
        """
    )
    
    parser.add_argument('--api-key', type=str, required=True,
                       help='Clé API Scorton (OBLIGATOIRE) - Obtenez-la sur https://radar.scorton.tech')
    parser.add_argument('--url', type=str, help='URL du site à analyser')
    parser.add_argument('--file', type=str, help='Fichier JSON contenant les données d\'un scan précédent')
    parser.add_argument('--output', type=str, default='./reports', 
                       help='Répertoire de sortie (défaut: ./reports)')
    parser.add_argument('--save-raw', action='store_true',
                       help='Sauvegarder les données brutes JSON de l\'API')
    parser.add_argument('--test-connection', action='store_true',
                       help='Tester la connexion à l\'API')
    
    args = parser.parse_args()
    
    # Mode test de connexion
    if args.test_connection:
        print("🔐 Test de connexion à Scorton Radar API...\n")
        if test_connection(args.api_key):
            print("\n✅ Connexion réussie! Vous pouvez maintenant analyser des sites.")
        else:
            print("\n❌ Échec de la connexion. Vérifiez votre clé API.")
        sys.exit(0)
    
    # Vérifier les arguments
    if not args.url and not args.file:
        parser.error("Vous devez spécifier --url ou --file")
    
    # Initialiser VibeStream avec API Radar
    try:
        vibestream = VibeStreamRadar(api_key=args.api_key)
        
        # Analyser
        if args.file:
            report_path = vibestream.analyze_from_file(args.file, args.output)
        else:
            report_path = vibestream.analyze_url(args.url, args.output, args.save_raw)
        
        if report_path:
            print("\n🎉 Analyse terminée avec succès!")
            print(f"📄 Rapport HTML: file://{os.path.abspath(report_path)}")
            print(f"📁 Tous les fichiers: {os.path.abspath(args.output)}/")
        
    except ValueError as e:
        print(f"\n{e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
