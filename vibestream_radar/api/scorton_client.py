"""
Client API Scorton pour la collecte de données
"""
import requests
from typing import Dict, Any, Optional
import json


class ScortonClient:
    """Client pour interagir avec l'API Scorton"""
    
    def __init__(self, api_token: Optional[str] = None, base_url: str = "https://api.scorton.tech"):
        """
        Initialise le client Scorton
        
        Args:
            api_token: Token d'authentification API (optionnel pour demo)
            base_url: URL de base de l'API
        """
        self.api_token = api_token
        self.base_url = base_url
        self.headers = {
            'Content-Type': 'application/json',
        }
        if api_token:
            self.headers['Authorization'] = f'Bearer {api_token}'
    
    def scan_website(self, url: str) -> Dict[str, Any]:
        """
        Lance un scan complet d'un site web via l'API Scorton
        
        Args:
            url: URL du site à scanner
            
        Returns:
            Dict contenant toutes les données collectées
        """
        try:
            response = requests.post(
                f"{self.base_url}/scan",
                json={"url": url},
                headers=self.headers,
                timeout=60
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors du scan: {e}")
            return {}
    
    def load_from_file(self, filepath: str) -> Dict[str, Any]:
        """
        Charge des données depuis un fichier JSON (pour tests/demo)
        
        Args:
            filepath: Chemin vers le fichier JSON
            
        Returns:
            Dict contenant les données
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Erreur lors du chargement du fichier: {e}")
            return {}
    
    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse et normalise la réponse de l'API
        
        Args:
            data: Données brutes de l'API
            
        Returns:
            Dict avec données normalisées
        """
        if not data:
            return {}
        
        # Si c'est une liste (comme dans l'exemple), prendre le premier élément
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        
        return {
            'url': data.get('url', ''),
            'domain': data.get('domain', ''),
            'ssl': self._parse_ssl(data.get('ssl')),
            'whois': data.get('whois', {}),
            'ports': data.get('ports', {}),
            'http_security': data.get('http_sec', {}),
            'tech_stack': data.get('tech_stack', {}),
            'dnssec': data.get('dnssec', {}),
            'security_txt': data.get('security-txt', {}),
            'cookies': data.get('cookies', {}),
            'trackers': data.get('Trackers', {}),
            'scores': {
                'ml': float(data.get('score_ml', 0)),
                'dl': float(data.get('score_dl', 0)),
                'ai': float(data.get('score_ai', 0)),
                'tech': float(data.get('score_tech', 0)),
                'final': data.get('score_analyser', {}).get('score_0_100', 0),
                'risk_level': data.get('score_analyser', {}).get('risk_level', 'unknown'),
            },
            'metadata': data.get('Metadata', {}),
            'cve': data.get('CVE_features', {}),
            'raw_data': data  # Garder les données brutes pour analyse approfondie
        }
    
    def _parse_ssl(self, ssl_data: Any) -> Dict[str, Any]:
        """Parse les données SSL qui peuvent être au format string"""
        if isinstance(ssl_data, str):
            try:
                # Tenter de parser la string comme un dict Python
                import ast
                return ast.literal_eval(ssl_data)
            except:
                return {'raw': ssl_data}
        return ssl_data if isinstance(ssl_data, dict) else {}
