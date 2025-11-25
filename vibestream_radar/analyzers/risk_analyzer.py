"""
Analyseur de risques et formulation d'hypothèses
"""
from typing import Dict, List, Any
from analyzers.signal_detector import Signal


class RiskHypothesis:
    """Représente une hypothèse de risque"""
    
    def __init__(self, title: str, description: str, likelihood: str, 
                 impact: str, scenario: str, indicators: List[str]):
        self.title = title
        self.description = description
        self.likelihood = likelihood  # low, medium, high
        self.impact = impact  # low, medium, high, critical
        self.scenario = scenario
        self.indicators = indicators
    
    def to_dict(self) -> Dict:
        return {
            'title': self.title,
            'description': self.description,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'scenario': self.scenario,
            'indicators': self.indicators,
            'risk_score': self._calculate_risk_score()
        }
    
    def _calculate_risk_score(self) -> int:
        """Calcule un score de risque (0-100)"""
        likelihood_scores = {'low': 25, 'medium': 50, 'high': 75}
        impact_scores = {'low': 25, 'medium': 50, 'high': 75, 'critical': 100}
        
        l_score = likelihood_scores.get(self.likelihood, 50)
        i_score = impact_scores.get(self.impact, 50)
        
        # Moyenne pondérée (impact compte plus)
        return int((l_score * 0.4 + i_score * 0.6))


class RiskAnalyzer:
    """Analyse les signaux et formule des hypothèses de risques"""
    
    def __init__(self, signals: List[Signal], data: Dict[str, Any]):
        self.signals = signals
        self.data = data
        self.hypotheses: List[RiskHypothesis] = []
    
    def analyze(self) -> List[RiskHypothesis]:
        """Génère les hypothèses de risques basées sur les signaux"""
        self.hypotheses = []
        
        # Analyser les combinaisons de signaux
        self._analyze_attack_surface()
        self._analyze_compromise_risk()
        self._analyze_data_breach_risk()
        self._analyze_service_disruption()
        self._analyze_compliance_risk()
        
        # Trier par score de risque
        self.hypotheses.sort(key=lambda h: h._calculate_risk_score(), reverse=True)
        
        return self.hypotheses
    
    def _has_signal(self, signal_id: str) -> bool:
        """Vérifie si un signal spécifique est présent"""
        return any(s.id == signal_id for s in self.signals)
    
    def _get_signal(self, signal_id: str) -> Signal:
        """Récupère un signal spécifique"""
        return next((s for s in self.signals if s.id == signal_id), None)
    
    def _analyze_attack_surface(self):
        """Analyse la surface d'attaque"""
        critical_ports_signal = self._get_signal('critical_ports_exposed')
        suspicious_ports_signal = self._get_signal('suspicious_ports_open')
        
        if critical_ports_signal or suspicious_ports_signal:
            indicators = []
            likelihood = 'medium'
            
            if critical_ports_signal:
                indicators.append('Ports SSH/RDP exposés publiquement')
                likelihood = 'high'
            
            if suspicious_ports_signal:
                indicators.extend([
                    'Multiples services non-web exposés',
                    'Présence de ports d\'administration'
                ])
            
            self.hypotheses.append(RiskHypothesis(
                title='Risque de compromission par scan de ports',
                description='Les ports d\'administration exposés sont constamment scannés par des botnets et attaquants',
                likelihood=likelihood,
                impact='critical',
                scenario='Un attaquant automatisé détecte les ports SSH/RDP ouverts, '
                        'lance une attaque par force brute avec des credentials courants '
                        '(admin/admin, root/password), obtient un accès au serveur, '
                        'installe un ransomware ou un cryptomineur, et compromet toutes les données.',
                indicators=indicators
            ))
    
    def _analyze_compromise_risk(self):
        """Analyse le risque de compromission web"""
        has_no_csp = self._has_signal('no_csp')
        has_no_xframe = self._has_signal('no_xframe')
        has_missing_headers = self._has_signal('missing_security_headers')
        
        if has_no_csp or has_missing_headers:
            indicators = []
            
            if has_no_csp:
                indicators.append('Absence de Content Security Policy')
            if has_no_xframe:
                indicators.append('Pas de protection contre le clickjacking')
            if has_missing_headers:
                indicators.append('Headers de sécurité incomplets')
            
            self.hypotheses.append(RiskHypothesis(
                title='Risque d\'attaque XSS et injection de code',
                description='L\'absence de protections web permet l\'injection de scripts malveillants',
                likelihood='high',
                impact='high',
                scenario='Un attaquant trouve une faille d\'injection (formulaire, commentaire, URL) '
                        'et injecte un script JavaScript malveillant. Ce script s\'exécute chez tous '
                        'les visiteurs et vole leurs cookies de session, permettant à l\'attaquant '
                        'de prendre le contrôle de leurs comptes.',
                indicators=indicators
            ))
    
    def _analyze_data_breach_risk(self):
        """Analyse le risque de fuite de données"""
        has_weak_tls = self._has_signal('weak_tls_key')
        has_no_dnssec = self._has_signal('no_dnssec')
        open_ports = self.data.get('ports', {}).get('openPorts', [])
        
        # Ports de base de données exposés
        db_ports = [p for p in open_ports if p in [3306, 5432, 27017, 6379, 1433]]
        
        if db_ports or has_weak_tls or has_no_dnssec:
            indicators = []
            likelihood = 'medium'
            impact = 'high'
            
            if db_ports:
                indicators.append(f'Ports de base de données détectés: {db_ports}')
                likelihood = 'high'
                impact = 'critical'
            
            if has_weak_tls:
                indicators.append('Chiffrement TLS affaibli')
            
            if has_no_dnssec:
                indicators.append('Pas de protection DNS (DNSSEC)')
            
            if indicators:
                self.hypotheses.append(RiskHypothesis(
                    title='Risque de fuite ou vol de données',
                    description='Les faiblesses de sécurité permettent l\'interception ou l\'accès direct aux données',
                    likelihood=likelihood,
                    impact=impact,
                    scenario='Un attaquant exploite les faiblesses du chiffrement ou accède directement '
                            'aux bases de données exposées. Les données sensibles (credentials, informations '
                            'personnelles, données métier) sont exfiltrées et potentiellement vendues ou '
                            'utilisées pour du chantage.',
                    indicators=indicators
                ))
    
    def _analyze_service_disruption(self):
        """Analyse le risque de disruption de service"""
        tls_expiring = self._get_signal('tls_expiring')
        
        if tls_expiring:
            days_remaining = tls_expiring.evidence.get('days_remaining', 0)
            likelihood = 'high' if days_remaining < 30 else 'medium'
            
            self.hypotheses.append(RiskHypothesis(
                title='Risque d\'interruption de service (certificat expiré)',
                description='L\'expiration imminente du certificat TLS menace la disponibilité du site',
                likelihood=likelihood,
                impact='high',
                scenario=f'Dans {days_remaining} jours, le certificat TLS expire. '
                        'Les navigateurs affichent un avertissement de sécurité majeur, '
                        'bloquant l\'accès au site pour la plupart des utilisateurs. '
                        'Le trafic chute de 95%, la réputation est endommagée, '
                        'et les revenus sont impactés jusqu\'au renouvellement.',
                indicators=[
                    f'Certificat expire dans {days_remaining} jours',
                    'Pas de processus de renouvellement automatique détecté'
                ]
            ))
    
    def _analyze_compliance_risk(self):
        """Analyse les risques de conformité"""
        has_trackers = self._has_signal('trackers_detected')
        has_no_security_txt = self._has_signal('no_security_txt')
        
        if has_trackers:
            trackers_signal = self._get_signal('trackers_detected')
            tracker_count = trackers_signal.evidence.get('count', 0)
            
            self.hypotheses.append(RiskHypothesis(
                title='Risque de non-conformité RGPD',
                description=f'{tracker_count} trackers tiers détectés sans information claire sur le consentement',
                likelihood='medium',
                impact='medium',
                scenario='Un utilisateur ou association (NOYB, La Quadrature du Net) porte plainte '
                        'auprès de la CNIL pour collecte de données sans consentement explicite. '
                        'Enquête de la CNIL, publicité négative, et amende potentielle de 2-4% '
                        'du CA annuel ou 10-20M€.',
                indicators=[
                    f'{tracker_count} trackers tiers actifs',
                    'Conformité du consentement non vérifiée',
                    'Google Analytics et autres trackers publicitaires'
                ]
            ))
    
    def get_summary(self) -> Dict:
        """Génère un résumé des risques"""
        return {
            'total_hypotheses': len(self.hypotheses),
            'by_likelihood': {
                'high': len([h for h in self.hypotheses if h.likelihood == 'high']),
                'medium': len([h for h in self.hypotheses if h.likelihood == 'medium']),
                'low': len([h for h in self.hypotheses if h.likelihood == 'low']),
            },
            'by_impact': {
                'critical': len([h for h in self.hypotheses if h.impact == 'critical']),
                'high': len([h for h in self.hypotheses if h.impact == 'high']),
                'medium': len([h for h in self.hypotheses if h.impact == 'medium']),
                'low': len([h for h in self.hypotheses if h.impact == 'low']),
            },
            'highest_risk': self.hypotheses[0].to_dict() if self.hypotheses else None
        }
