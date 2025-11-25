"""
Client API Scorton Radar - Version améliorée avec API réelle
"""
import requests
from typing import Dict, Any, Optional
import json
import time


class ScortonRadarClient:
    """Client pour interagir avec l'API Scorton Radar"""
    
    def __init__(self, api_key: str, base_url: str = "https://radar.scorton.tech"):
        """
        Initialise le client Scorton Radar
        
        Args:
            api_key: Clé API Scorton (OBLIGATOIRE)
            base_url: URL de base de l'API
        """
        if not api_key:
            raise ValueError("Une clé API est obligatoire. Obtenez-la sur https://radar.scorton.tech")
        
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    
    def verify_key(self) -> Dict[str, Any]:
        """
        Vérifie la validité de la clé API
        
        Returns:
            Dict avec les informations de la clé
        """
        try:
            response = requests.get(
                f"{self.base_url}/verify-key",
                headers={'x-api-key': self.api_key},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur lors de la vérification de la clé: {e}")
            return {}
    
    def get_usage(self) -> Dict[str, Any]:
        """
        Récupère les statistiques d'utilisation de la clé API
        
        Returns:
            Dict avec les compteurs d'utilisation
        """
        try:
            response = requests.get(
                f"{self.base_url}/usage-key",
                headers={'x-api-key': self.api_key},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Impossible de récupérer l'usage: {e}")
            return {}
    
    def analyze_url(self, url: str, output_format: str = "json", 
                    max_retries: int = 3) -> Dict[str, Any]:
        """
        Analyse complète d'une URL via l'API Scorton Radar
        
        Args:
            url: URL du site à analyser
            output_format: Format de sortie (json ou html)
            max_retries: Nombre de tentatives en cas d'échec
            
        Returns:
            Dict contenant toutes les données d'analyse
        """
        print(f"🔍 Analyse de {url} via Scorton Radar...")
        
        data = {
            'url': url,
            'output_format': output_format
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/analyze/url",
                    headers=self.headers,
                    data=data,
                    timeout=120  # Timeout de 2 minutes pour l'analyse complète
                )
                
                if response.status_code == 200:
                    print("✅ Analyse terminée avec succès")
                    return response.json()
                
                elif response.status_code == 429:
                    # Rate limit
                    wait_time = 2 ** attempt  # Backoff exponentiel
                    print(f"⏳ Rate limit atteint. Attente de {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                elif response.status_code == 401:
                    print("❌ Clé API invalide ou expirée")
                    return {}
                
                else:
                    print(f"❌ Erreur {response.status_code}: {response.text}")
                    response.raise_for_status()
                    
            except requests.exceptions.Timeout:
                print(f"⏱️  Timeout (tentative {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                else:
                    print("❌ Échec après plusieurs tentatives")
                    return {}
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Erreur réseau: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {}
        
        return {}
    
    def analyze_filtered(self, url: str, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyse filtrée d'une URL par catégorie
        
        Args:
            url: URL du site à analyser
            category: Catégorie à filtrer (network, security, privacy, etc.)
            
        Returns:
            Dict avec les données filtrées
        """
        print(f"🔍 Analyse filtrée de {url} (catégorie: {category or 'toutes'})")
        
        endpoint = f"{self.base_url}/analyze/filtered"
        if category:
            endpoint += f"?category={category}"
        
        data = {'url': url, 'output_format': 'json'}
        
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                data=data,
                timeout=120
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur lors de l'analyse filtrée: {e}")
            return {}
    
    def list_scanned_urls(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        Liste les URLs scannées précédemment
        
        Args:
            limit: Nombre max de résultats (1-500)
            offset: Décalage pour la pagination
            
        Returns:
            Dict avec la liste des URLs scannées
        """
        try:
            response = requests.get(
                f"{self.base_url}/scan-url",
                headers={'x-api-key': self.api_key},
                params={'limit': limit, 'offset': offset},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Impossible de lister les URLs: {e}")
            return {}
    
    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse et normalise la réponse de l'API Radar
        
        Args:
            data: Données brutes de l'API
            
        Returns:
            Dict avec données normalisées
        """
        if not data:
            return {}
        
        # L'API Radar retourne directement l'objet (pas de liste)
        
        # Construire l'objet SSL depuis les champs TLS individuels
        ssl_data = {}
        if data.get('TLS_strength'):
            ssl_data = {
                'strength': int(data.get('TLS_strength', 0)) if str(data.get('TLS_strength', 0)).isdigit() else 0,
                'expiry_days': int(data.get('TLS_expiry_days', 0)) if str(data.get('TLS_expiry_days', 0)).isdigit() else 0,
                'self_signed': data.get('cert_self_signed', '0') != '0',
                'cert_cn': data.get('cert_cn', ''),
                'san_count': int(data.get('san_count', 0)) if str(data.get('san_count', 0)).isdigit() else 0
            }
        
        return {
            'url': data.get('url', ''),
            'domain': data.get('domain', ''),
            'ip': data.get('ip', ''),
            
            # Informations de base
            'domain_len': int(data.get('domain_len', 0)) if str(data.get('domain_len', 0)).isdigit() else 0,
            'subdomain_depth': int(data.get('subdomain_depth', 0)) if str(data.get('subdomain_depth', 0)).isdigit() else 0,
            'has_idn': data.get('has_idn', '0') != '0',
            
            # TLS/SSL - Objet construit depuis les champs individuels
            'ssl': ssl_data,
            'TLS_strength': int(data.get('TLS_strength', 0)) if str(data.get('TLS_strength', 0)).isdigit() else 0,
            'TLS_expiry_days': int(data.get('TLS_expiry_days', 0)) if str(data.get('TLS_expiry_days', 0)).isdigit() else 0,
            'cert_self_signed': data.get('cert_self_signed', '0') != '0',
            'cert_cn': data.get('cert_cn', ''),
            'san_count': int(data.get('san_count', 0)) if str(data.get('san_count', 0)).isdigit() else 0,
            
            # Headers HTTP sécurité
            'http_security': {},  # L'API ne retourne pas cet objet
            'CSP_completeness': float(data.get('CSP_completeness', 0)),
            'Security_headers_count': int(data.get('Security_headers_count', 0)) if str(data.get('Security_headers_count', 0)).isdigit() else 0,
            'CSRF_protection': str(data.get('CSRF_protection', 'False')).lower() == 'true',
            'Secure_cookie_flag': data.get('Secure_cookie_flag', '0') != '0',
            'CSP_header': str(data.get('CSP_header', 'False')).lower() == 'true',
            'HSTS_header': str(data.get('HSTS_header', 'False')).lower() == 'true',
            'X_Frame_Options': str(data.get('X_Frame_Options', 'False')).lower() == 'true',
            
            # Réseau
            'ports': {},  # L'API ne retourne pas les détails des ports
            'Nb_ports_open': int(data.get('Nb_ports_open', 0)) if str(data.get('Nb_ports_open', 0)).isdigit() else 0,
            
            # Géolocalisation et hébergement
            'GeoIP_risk': data.get('GeoIP_risk', 'unknown'),
            'Hosting_type': data.get('Hosting_type', 'unknown'),
            
            # Réputation
            'block_lists': {},
            'Blacklist_hits': int(data.get('Blacklist_hits', 0)) if str(data.get('Blacklist_hits', 0)).isdigit() else 0,
            
            # Domaine
            'whois': {},  # L'API ne retourne pas les détails WHOIS
            'Domain_age_days': None if data.get('Domain_age_days') == 'None' else data.get('Domain_age_days'),
            'WHOIS_privacy': data.get('WHOIS_privacy', '0') != '0',
            
            # Métadonnées
            'Metadata': data.get('Metadata', {}),
            
            # CVE
            'cve': data.get('CVE_features', {}),
            'CVE_summaries': data.get('CVE_summaries', []),
            
            # Trackers
            'trackers': data.get('Trackers', {}),
            'cookies': data.get('cookies', {}),
            
            # Stack technologique
            'tech_stack': data.get('tech_stack', {}),
            
            # DNS
            'dnssec': data.get('dnssec', {}),
            'dnsserver': data.get('dnsserver', {}),
            
            # Sécurité
            'security_txt': data.get('security-txt', {}),
            'linked_pages': data.get('linked-pages', {}),
            
            # Carbon footprint
            'carbon': data.get('carbon', {}),
            
            # Ranking
            'rank': data.get('rank', {}),
            
            # Scores
            'scores': {
                'ml': float(data.get('score_ml', 0)),
                'dl': float(data.get('score_dl', 0)),
                'ai': float(data.get('score_ai', 0)),
                'tech': float(data.get('score_tech', 0)),
                'final': data.get('score_analyser', {}).get('score_0_100', 0),
                'risk_level': data.get('score_analyser', {}).get('risk_level', 'unknown'),
                'analyser': data.get('score_analyser', {})
            },
            
            # Données brutes complètes
            'raw_data': data
        }
    
    def save_to_file(self, data: Dict[str, Any], filepath: str):
        """Sauvegarde les données dans un fichier JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"💾 Données sauvegardées dans {filepath}")
    
    def load_from_file(self, filepath: str) -> Dict[str, Any]:
        """Charge des données depuis un fichier JSON"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Erreur lors du chargement: {e}")
            return {}


# Fonction helper pour tester rapidement la connexion
def test_connection(api_key: str) -> bool:
    """
    Teste la connexion à l'API Scorton Radar
    
    Args:
        api_key: Clé API à tester
        
    Returns:
        True si la connexion fonctionne
    """
    try:
        client = ScortonRadarClient(api_key)
        result = client.verify_key()
        
        if result:
            print("✅ Connexion réussie à Scorton Radar!")
            print(f"📊 Informations de la clé: {result}")
            
            # Afficher l'usage si disponible
            usage = client.get_usage()
            if usage:
                print(f"📈 Usage: {usage}")
            
            return True
        else:
            print("❌ Échec de la vérification de la clé")
            return False
            
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False
