"""
Générateur de rapports HTML VibeStream
"""
from jinja2 import Environment, FileSystemLoader
from typing import Dict, List, Any
from datetime import datetime
import os


class ReportGenerator:
    """Génère des rapports HTML professionnels"""
    
    def __init__(self, template_dir: str = None):
        """
        Initialise le générateur de rapports
        
        Args:
            template_dir: Chemin vers le répertoire des templates
        """
        if template_dir is None:
            # Par défaut, utiliser le dossier templates relatif à ce fichier
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(current_dir, 'templates')
        
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.env.filters['tojson'] = self._to_json_filter
    
    def _to_json_filter(self, value, indent=2):
        """Filtre Jinja2 pour convertir en JSON"""
        import json
        return json.dumps(value, indent=indent, ensure_ascii=False)
    
    def generate(self, data: Dict[str, Any], signals: List, hypotheses: List, 
                 output_path: str) -> str:
        """
        Génère un rapport HTML complet
        
        Args:
            data: Données normalisées du scan
            signals: Liste des signaux détectés
            hypotheses: Liste des hypothèses de risques
            output_path: Chemin de sortie du rapport
            
        Returns:
            Chemin du rapport généré
        """
        template = self.env.get_template('report.html')
        
        # Préparer les données pour le template
        context = self._prepare_context(data, signals, hypotheses)
        
        # Générer le HTML
        html_content = template.render(**context)
        
        # Écrire le fichier
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _prepare_context(self, data: Dict, signals: List, hypotheses: List) -> Dict:
        """Prépare le contexte pour le template"""
        
        # Séparer signaux forts et faibles
        strong_signals = [s.to_dict() for s in signals if s.severity in ['CRITICAL', 'HIGH']]
        weak_signals = [s.to_dict() for s in signals if s.severity in ['MEDIUM', 'LOW', 'INFO']]
        
        # Convertir les hypothèses
        hypotheses_dict = [h.to_dict() for h in hypotheses]
        
        # Extraire les informations TLS
        ssl_data = data.get('ssl', {})
        tls_info = {
            'issuer': ssl_data.get('issuer', {}).get('CN', 'Unknown'),
            'valid_from': ssl_data.get('valid_from', 'N/A'),
            'valid_to': ssl_data.get('valid_to', 'N/A'),
            'bits': ssl_data.get('bits', 0)
        }
        
        # Informations sur les ports
        # L'API retourne Nb_ports_open comme string, pas un objet ports avec openPorts
        nb_ports_open = 0
        if 'Nb_ports_open' in data:
            try:
                nb_ports_open = int(data['Nb_ports_open'])
            except (ValueError, TypeError):
                nb_ports_open = 0
        
        # Comme l'API ne donne pas la liste des ports, on indique juste le nombre
        ports_info = {
            'open_count': nb_ports_open,
            'open_list': [],  # L'API ne fournit pas la liste détaillée
            'critical_ports': [],  # Impossible de savoir sans la liste
            'critical_count': 0
        }
        
        # Technologies
        tech_stack = data.get('tech_stack', {})
        technologies = tech_stack.get('technologies', [])
        
        # Scores
        scores = data.get('scores', {})
        
        # Headers de sécurité
        security_headers = data.get('http_security', {})
        
        # Résumé des signaux
        signal_summary = {
            'total': len(signals),
            'strong_signals': len(strong_signals),
            'weak_signals': len(weak_signals),
            'by_severity': {
                'CRITICAL': len([s for s in signals if s.severity == 'CRITICAL']),
                'HIGH': len([s for s in signals if s.severity == 'HIGH']),
                'MEDIUM': len([s for s in signals if s.severity == 'MEDIUM']),
                'LOW': len([s for s in signals if s.severity == 'LOW']),
                'INFO': len([s for s in signals if s.severity == 'INFO']),
            }
        }
        
        # Résumé des risques
        risk_summary = {
            'total_hypotheses': len(hypotheses),
            'by_impact': {
                'critical': len([h for h in hypotheses if h.impact == 'critical']),
                'high': len([h for h in hypotheses if h.impact == 'high']),
                'medium': len([h for h in hypotheses if h.impact == 'medium']),
                'low': len([h for h in hypotheses if h.impact == 'low']),
            }
        }
        
        return {
            'domain': data.get('domain', 'Unknown'),
            'url': data.get('url', ''),
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scores': scores,
            'signal_summary': signal_summary,
            'risk_summary': risk_summary,
            'strong_signals': strong_signals,
            'weak_signals': weak_signals,
            'hypotheses': hypotheses_dict,
            'technologies': technologies,
            'tls_info': tls_info,
            'ports_info': ports_info,
            'security_headers': security_headers,
        }
