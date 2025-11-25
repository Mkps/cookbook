"""
VibeStream - Analyseur de signaux cyber pour sites web
Détecte les anomalies, signaux faibles/forts et formule des hypothèses de risques
"""

import json
from datetime import datetime
from typing import Dict, List, Tuple


class WebSecurityAnalyzer:
    """Analyseur de sécurité web basé sur les données Scorton"""
    
    # Seuils de détection
    THRESHOLDS = {
        'tls_expiry_warning': 90,  # jours
        'tls_expiry_critical': 30,
        'max_open_ports': 5,
        'min_security_score': 70,
        'dangerous_ports': [22, 23, 3389, 5900, 3306, 5432, 1433],  # SSH, Telnet, RDP, VNC, DB
    }
    
    def __init__(self, data: Dict):
        self.data = data
        self.signals_strong = []
        self.signals_weak = []
        self.anomalies = []
        self.hypotheses = []
        
    def analyze(self) -> Dict:
        """Lance l'analyse complète"""
        print("[+] Démarrage de l'analyse VibeStream...")
        
        # Extraction des données
        self._extract_basic_info()
        
        # Analyses techniques
        self._analyze_tls()
        self._analyze_ports()
        self._analyze_security_headers()
        self._analyze_whois()
        self._analyze_dnssec()
        self._analyze_technologies()
        self._analyze_global_score()
        
        # Formulation d'hypothèses
        self._formulate_hypotheses()
        
        return self._generate_report()
    
    def _extract_basic_info(self):
        """Extrait les informations de base"""
        self.url = self.data.get('url', 'N/A')
        self.domain = self.data.get('domain', 'N/A')
        
    def _analyze_tls(self):
        """Analyse du certificat TLS"""
        ssl_data = self.data.get('ssl')
        if isinstance(ssl_data, str):
            ssl_data = eval(ssl_data)  # Convertir la string en dict
        
        if ssl_data:
            # Expiration du certificat
            expiry_days = int(self.data.get('TLS_expiry_days', 0))
            
            if expiry_days < self.THRESHOLDS['tls_expiry_critical']:
                self.signals_strong.append({
                    'type': 'TLS_EXPIRY_CRITICAL',
                    'severity': 'HIGH',
                    'description': f"Certificat TLS expire dans {expiry_days} jours",
                    'impact': "Le site deviendra inaccessible et affichera des avertissements de sécurité",
                    'remediation': "Renouveler le certificat immédiatement"
                })
            elif expiry_days < self.THRESHOLDS['tls_expiry_warning']:
                self.signals_weak.append({
                    'type': 'TLS_EXPIRY_WARNING',
                    'severity': 'MEDIUM',
                    'description': f"Certificat TLS expire dans {expiry_days} jours",
                    'impact': "Risque d'interruption de service si non renouvelé",
                    'remediation': "Planifier le renouvellement dans les 30 jours"
                })
            
            # Force de chiffrement
            tls_strength = int(self.data.get('TLS_strength', 0))
            if tls_strength < 256:
                self.signals_weak.append({
                    'type': 'TLS_WEAK_ENCRYPTION',
                    'severity': 'MEDIUM',
                    'description': f"Chiffrement TLS faible ({tls_strength} bits)",
                    'impact': "Vulnérable aux attaques cryptographiques avancées",
                    'remediation': "Migrer vers des clés 256 bits minimum (RSA 2048 ou ECC 256)"
                })
            
            # Certificat auto-signé
            if self.data.get('cert_self_signed') == '1':
                self.signals_strong.append({
                    'type': 'SELF_SIGNED_CERT',
                    'severity': 'HIGH',
                    'description': "Certificat TLS auto-signé détecté",
                    'impact': "Avertissements de sécurité pour les utilisateurs, perte de confiance",
                    'remediation': "Obtenir un certificat d'une autorité reconnue (Let's Encrypt gratuit)"
                })
    
    def _analyze_ports(self):
        """Analyse des ports ouverts"""
        ports_data = self.data.get('ports', {})
        open_ports = ports_data.get('openPorts', [])
        
        if len(open_ports) > self.THRESHOLDS['max_open_ports']:
            self.signals_weak.append({
                'type': 'EXCESSIVE_OPEN_PORTS',
                'severity': 'MEDIUM',
                'description': f"{len(open_ports)} ports ouverts détectés (seuil: {self.THRESHOLDS['max_open_ports']})",
                'impact': "Surface d'attaque élargie",
                'remediation': "Audit et fermeture des ports non essentiels"
            })
        
        # Détection de ports dangereux
        dangerous_open = [p for p in open_ports if p in self.THRESHOLDS['dangerous_ports']]
        
        if dangerous_open:
            self.signals_strong.append({
                'type': 'DANGEROUS_PORTS_EXPOSED',
                'severity': 'CRITICAL',
                'description': f"Ports sensibles exposés publiquement: {', '.join(map(str, dangerous_open))}",
                'details': self._get_port_details(dangerous_open),
                'impact': "Risque élevé d'attaque par force brute, accès non autorisé",
                'remediation': "Restreindre l'accès via firewall/VPN, désactiver si non utilisés"
            })
            
            self.anomalies.append({
                'category': 'Network Security',
                'anomaly': f"Ports administratifs exposés ({', '.join(map(str, dangerous_open))})",
                'likelihood': 'High',
                'explanation': "Un site web standard ne devrait exposer que les ports 80/443"
            })
        
        # Ports inhabituels pour un site web
        web_ports = [80, 443]
        unusual_ports = [p for p in open_ports if p not in web_ports and p not in self.THRESHOLDS['dangerous_ports']]
        
        if unusual_ports:
            self.signals_weak.append({
                'type': 'UNUSUAL_PORTS',
                'severity': 'LOW',
                'description': f"Ports inhabituels ouverts: {', '.join(map(str, unusual_ports))}",
                'impact': "Possibles services non sécurisés ou mal configurés",
                'remediation': "Vérifier la nécessité de ces services"
            })
    
    def _get_port_details(self, ports: List[int]) -> Dict:
        """Retourne les détails des ports dangereux"""
        port_info = {
            22: {'name': 'SSH', 'risk': 'Accès shell distant, cible d\'attaques brute-force'},
            23: {'name': 'Telnet', 'risk': 'Protocole non chiffré, obsolète'},
            3389: {'name': 'RDP', 'risk': 'Bureau à distance Windows, vulnérabilités connues'},
            5900: {'name': 'VNC', 'risk': 'Contrôle à distance, souvent mal sécurisé'},
            3306: {'name': 'MySQL', 'risk': 'Base de données accessible publiquement'},
            5432: {'name': 'PostgreSQL', 'risk': 'Base de données accessible publiquement'},
            1433: {'name': 'MSSQL', 'risk': 'Base de données accessible publiquement'},
        }
        return {p: port_info.get(p, {'name': 'Unknown', 'risk': 'Service inconnu'}) for p in ports}
    
    def _analyze_security_headers(self):
        """Analyse des en-têtes de sécurité HTTP"""
        http_sec = self.data.get('http_sec', {})
        
        missing_headers = []
        
        if not http_sec.get('xFrameOptions'):
            missing_headers.append('X-Frame-Options')
            self.signals_weak.append({
                'type': 'MISSING_X_FRAME_OPTIONS',
                'severity': 'MEDIUM',
                'description': "En-tête X-Frame-Options manquant",
                'impact': "Vulnérable aux attaques par clickjacking",
                'remediation': "Ajouter l'en-tête: X-Frame-Options: DENY ou SAMEORIGIN"
            })
        
        if not http_sec.get('contentSecurityPolicy'):
            missing_headers.append('Content-Security-Policy')
            self.signals_strong.append({
                'type': 'MISSING_CSP',
                'severity': 'HIGH',
                'description': "Content Security Policy (CSP) non configurée",
                'impact': "Vulnérable aux attaques XSS, injection de scripts malveillants",
                'remediation': "Implémenter une CSP stricte pour contrôler les sources de contenu"
            })
        
        if not http_sec.get('xXSSProtection'):
            missing_headers.append('X-XSS-Protection')
            self.signals_weak.append({
                'type': 'MISSING_XSS_PROTECTION',
                'severity': 'LOW',
                'description': "En-tête X-XSS-Protection désactivé ou manquant",
                'impact': "Protection XSS du navigateur désactivée",
                'remediation': "Activer via: X-XSS-Protection: 1; mode=block"
            })
        
        if missing_headers:
            self.anomalies.append({
                'category': 'HTTP Security',
                'anomaly': f"En-têtes de sécurité manquants: {', '.join(missing_headers)}",
                'likelihood': 'High',
                'explanation': "Configuration incomplète des protections HTTP standard"
            })
    
    def _analyze_whois(self):
        """Analyse WHOIS"""
        whois_data = self.data.get('whois', {})
        
        if 'error' in whois_data or not whois_data:
            self.signals_strong.append({
                'type': 'WHOIS_UNAVAILABLE',
                'severity': 'HIGH',
                'description': "Données WHOIS introuvables ou masquées",
                'impact': "Impossible de vérifier la légitimité du domaine, âge, propriétaire",
                'remediation': "Vérifier l'enregistrement du domaine auprès du registrar"
            })
            
            self.anomalies.append({
                'category': 'Domain Security',
                'anomaly': "WHOIS inaccessible pour un domaine actif",
                'likelihood': 'Medium',
                'explanation': "Inhabituels pour un site légitime : protection extrême, erreur d'enregistrement, ou domaine très récent"
            })
        
        # Âge du domaine
        domain_age = self.data.get('Domain_age_days')
        if domain_age == 'None' or domain_age is None:
            self.signals_weak.append({
                'type': 'UNKNOWN_DOMAIN_AGE',
                'severity': 'MEDIUM',
                'description': "Âge du domaine inconnu",
                'impact': "Impossible d'évaluer la maturité et la confiance du domaine",
                'remediation': "Investigation manuelle du domaine requise"
            })
    
    def _analyze_dnssec(self):
        """Analyse DNSSEC"""
        dnssec = self.data.get('dnssec', {})
        
        if not any([
            dnssec.get('DNSKEY', {}).get('isFound'),
            dnssec.get('DS', {}).get('isFound'),
            dnssec.get('RRSIG', {}).get('isFound')
        ]):
            self.signals_weak.append({
                'type': 'DNSSEC_NOT_CONFIGURED',
                'severity': 'MEDIUM',
                'description': "DNSSEC non configuré",
                'impact': "Vulnérable au DNS spoofing et cache poisoning",
                'remediation': "Activer DNSSEC auprès du registrar pour garantir l'authenticité DNS"
            })
    
    def _analyze_technologies(self):
        """Analyse de la stack technique"""
        tech_stack = self.data.get('tech_stack', {})
        technologies = tech_stack.get('technologies', [])
        
        # Recherche de technologies obsolètes ou vulnérables
        for tech in technologies:
            slug = tech.get('slug', '')
            version = tech.get('version')
            
            # Exemple: détection de versions obsolètes (à enrichir)
            if slug == 'react' and version:
                # Logique de vérification de version (simplifiée)
                pass
        
        # Détection de trackers excessifs
        trackers = self.data.get('Trackers', {})
        if trackers.get('Tracker_detected'):
            trackers_found = trackers.get('Trackers_found', [])
            if len(trackers_found) > 5:
                self.signals_weak.append({
                    'type': 'EXCESSIVE_TRACKERS',
                    'severity': 'LOW',
                    'description': f"{len(trackers_found)} trackers détectés",
                    'impact': "Préoccupations de confidentialité, ralentissement du site",
                    'remediation': "Audit des trackers et suppression des non essentiels"
                })
    
    def _analyze_global_score(self):
        """Analyse du score global"""
        score_analyser = self.data.get('score_analyser', {})
        final_score = score_analyser.get('score_0_100', 0)
        risk_level = score_analyser.get('risk_level', 'unknown')
        
        if final_score < self.THRESHOLDS['min_security_score']:
            self.signals_strong.append({
                'type': 'LOW_SECURITY_SCORE',
                'severity': 'HIGH',
                'description': f"Score de sécurité global faible: {final_score}/100 (risque: {risk_level})",
                'impact': "Vulnérabilités multiples compromettant la sécurité globale",
                'remediation': "Audit de sécurité complet requis"
            })
        
        # Analyse des catégories
        categories = score_analyser.get('categories', [])
        for cat in categories:
            if cat.get('score100', 100) < 60:
                self.signals_weak.append({
                    'type': f"LOW_CATEGORY_SCORE_{cat.get('key', 'unknown').upper()}",
                    'severity': 'MEDIUM',
                    'description': f"Score faible en {cat.get('label')}: {cat.get('score100')}/100 (Grade: {cat.get('grade')})",
                    'impact': f"Faiblesses dans le domaine {cat.get('label')}",
                    'remediation': "Renforcement spécifique requis"
                })
    
    def _formulate_hypotheses(self):
        """Formule des hypothèses basées sur les signaux détectés"""
        
        # Hypothèse 1: Configuration serveur exposée
        if any(s['type'] == 'DANGEROUS_PORTS_EXPOSED' for s in self.signals_strong):
            self.hypotheses.append({
                'hypothesis': "Serveur de développement ou de test exposé en production",
                'probability': 'High',
                'reasoning': "La présence de ports administratifs (SSH, RDP) suggère une mauvaise séparation dev/prod",
                'risk': "Accès non autorisé, compromission du serveur",
                'indicators': [
                    "Ports 22 (SSH) et 3389 (RDP) ouverts publiquement",
                    "Absence de restrictions réseau appropriées",
                    f"14 ports ouverts au total (normal: 2 pour un site web)"
                ]
            })
        
        # Hypothèse 2: Problème d'enregistrement de domaine
        if any(s['type'] == 'WHOIS_UNAVAILABLE' for s in self.signals_strong):
            self.hypotheses.append({
                'hypothesis': "Domaine récemment enregistré ou problème d'enregistrement",
                'probability': 'Medium',
                'reasoning': "L'absence de données WHOIS est inhabituelle pour un domaine établi",
                'risk': "Domaine potentiellement non légitime, risque de perte du domaine",
                'indicators': [
                    "WHOIS retourne 'No matches found'",
                    "Âge du domaine inconnu",
                    "Impossible de vérifier le propriétaire"
                ]
            })
        
        # Hypothèse 3: Posture de sécurité faible
        if len(self.signals_strong) >= 3:
            self.hypotheses.append({
                'hypothesis': "Absence de processus de sécurité établi",
                'probability': 'High',
                'reasoning': "Multiples défauts de sécurité fondamentaux détectés",
                'risk': "Surface d'attaque importante, cible facile pour les attaquants",
                'indicators': [
                    f"{len(self.signals_strong)} signaux critiques détectés",
                    "Absence de headers de sécurité standard",
                    "Configuration réseau non sécurisée",
                    "Score de sécurité global faible"
                ]
            })
        
        # Hypothèse 4: Signaux faibles précoces
        csp_completeness = float(self.data.get('CSP_completeness', 0))
        if csp_completeness > 0 and csp_completeness < 0.5:
            self.hypotheses.append({
                'hypothesis': "Tentative partielle de mise en conformité sécuritaire",
                'probability': 'Medium',
                'reasoning': "CSP partiellement implémentée suggère une prise de conscience récente",
                'risk': "Protection incomplète, faux sentiment de sécurité",
                'indicators': [
                    f"CSP configurée à {csp_completeness*100}% seulement",
                    "Certains headers présents, d'autres manquants",
                    "Configuration probablement copiée sans compréhension complète"
                ]
            })
    
    def _generate_report(self) -> Dict:
        """Génère le rapport final"""
        return {
            'metadata': {
                'url': self.url,
                'domain': self.domain,
                'scan_date': datetime.now().isoformat(),
                'analyzer_version': '1.0.0'
            },
            'summary': {
                'total_signals_strong': len(self.signals_strong),
                'total_signals_weak': len(self.signals_weak),
                'total_anomalies': len(self.anomalies),
                'total_hypotheses': len(self.hypotheses),
                'global_risk_level': self._calculate_global_risk()
            },
            'signals': {
                'strong': self.signals_strong,
                'weak': self.signals_weak
            },
            'anomalies': self.anomalies,
            'hypotheses': self.hypotheses,
            'raw_scores': {
                'score_tech': self.data.get('score_tech'),
                'score_ml': self.data.get('score_ml'),
                'score_dl': self.data.get('score_dl'),
                'score_ai': self.data.get('score_ai'),
                'final_score': self.data.get('score_analyser', {}).get('score_0_100')
            }
        }
    
    def _calculate_global_risk(self) -> str:
        """Calcule le niveau de risque global"""
        if len(self.signals_strong) >= 3:
            return 'CRITICAL'
        elif len(self.signals_strong) >= 1:
            return 'HIGH'
        elif len(self.signals_weak) >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'


def main():
    """Point d'entrée principal"""
    # Exemple d'utilisation avec les données fournies
    sample_data_path = 'scorton_data.json'
    
    try:
        with open(sample_data_path, 'r') as f:
            data = json.load(f)
        
        analyzer = WebSecurityAnalyzer(data)
        report = analyzer.analyze()
        
        # Sauvegarde du rapport
        with open('vibestream_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Analyse terminée!")
        print(f"[✓] {report['summary']['total_signals_strong']} signaux forts détectés")
        print(f"[✓] {report['summary']['total_signals_weak']} signaux faibles détectés")
        print(f"[✓] {report['summary']['total_anomalies']} anomalies identifiées")
        print(f"[✓] {report['summary']['total_hypotheses']} hypothèses formulées")
        print(f"[✓] Risque global: {report['summary']['global_risk_level']}")
        print(f"\n[✓] Rapport sauvegardé: vibestream_report.json")
        
    except FileNotFoundError:
        print(f"[!] Fichier {sample_data_path} introuvable")
        print("[i] Veuillez créer ce fichier avec vos données Scorton")


if __name__ == '__main__':
    main()
