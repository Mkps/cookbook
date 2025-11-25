"""
Détecteur de signaux faibles et forts
"""
from typing import Dict, List, Any
from datetime import datetime, timedelta
from utils.config import THRESHOLDS, STRONG_SIGNALS, WEAK_SIGNALS, SIGNAL_SEVERITY


class Signal:
    """Représente un signal détecté"""
    
    def __init__(self, signal_id: str, severity: str, title: str, 
                 description: str, impact: str, recommendation: str, 
                 evidence: Any = None, category: str = "security"):
        self.id = signal_id
        self.severity = severity
        self.title = title
        self.description = description
        self.impact = impact
        self.recommendation = recommendation
        self.evidence = evidence
        self.category = category
        self.priority = SIGNAL_SEVERITY[severity]['priority']
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'category': self.category,
            'priority': self.priority,
            'color': SIGNAL_SEVERITY[self.severity]['color']
        }


class SignalDetector:
    """Détecte les signaux faibles et forts dans les données collectées"""
    
    def __init__(self):
        self.signals: List[Signal] = []
    
    def _safe_dict(self, value: Any) -> Dict:
        """Convertit une valeur en dict, retourne {} si ce n'est pas un dict"""
        if isinstance(value, dict):
            return value
        return {}
    
    def analyze(self, data: Dict[str, Any]) -> List[Signal]:
        """
        Analyse les données et détecte les signaux
        
        Args:
            data: Données normalisées du scan
            
        Returns:
            Liste des signaux détectés
        """
        self.signals = []
        
        # Analyse WHOIS
        self._check_whois(self._safe_dict(data.get('whois')))
        
        # Analyse des ports - Passer le nombre de ports depuis data principal
        nb_ports = 0
        try:
            nb_ports = int(data.get('Nb_ports_open', 0)) if data.get('Nb_ports_open') else 0
        except (ValueError, TypeError):
            pass
        self._check_ports_count(nb_ports)
        
        # Analyse TLS/SSL
        self._check_tls(self._safe_dict(data.get('ssl')))
        
        # Analyse headers HTTP sécurité
        self._check_http_security(self._safe_dict(data.get('http_security')))
        
        # Analyse DNSSEC
        self._check_dnssec(self._safe_dict(data.get('dnssec')))
        
        # Analyse security.txt
        self._check_security_txt(self._safe_dict(data.get('security_txt')))
        
        # Analyse trackers
        self._check_trackers(self._safe_dict(data.get('trackers')))
        
        # Analyse scores
        self._check_scores(self._safe_dict(data.get('scores')))
        
        # Trier par priorité
        self.signals.sort(key=lambda x: x.priority)
        
        return self.signals
    
    def _check_whois(self, whois_data: Dict):
        """Vérifie les données WHOIS"""
        if whois_data.get('error') or not whois_data:
            self.signals.append(Signal(
                signal_id='whois_not_found',
                severity='CRITICAL',
                title='Informations WHOIS introuvables',
                description='Les informations WHOIS du domaine sont indisponibles ou protégées',
                impact='Impossible de vérifier l\'âge du domaine, le propriétaire, ou la légitimité. '
                       'Cela peut indiquer un domaine très récent, une protection WHOIS extrême, '
                       'ou un problème d\'enregistrement.',
                recommendation='1. Vérifier auprès du registrar si le domaine est correctement enregistré\n'
                             '2. Activer les informations WHOIS publiques pour la transparence\n'
                             '3. Si protection intentionnelle, documenter la raison',
                evidence=whois_data.get('error', 'No WHOIS data available'),
                category='identity'
            ))
    
    def _check_ports_count(self, nb_ports: int):
        """
        Vérifie le nombre de ports ouverts
        Note: L'API Scorton ne fournit pas la liste des ports, juste le nombre total
        """
        if nb_ports == 0:
            return
        
        # Signal si trop de ports ouverts
        if nb_ports > THRESHOLDS['max_open_ports']:
            self.signals.append(Signal(
                signal_id='too_many_ports',
                severity='HIGH',
                title='Nombre élevé de ports ouverts',
                description=f'{nb_ports} ports détectés ouverts (recommandé: < {THRESHOLDS["max_open_ports"]})',
                impact='• Surface d\'attaque très large\n'
                       '• Chaque port ouvert est une porte d\'entrée potentielle\n'
                       '• Augmente significativement les risques d\'exploitation\n'
                       '• Peut indiquer une configuration réseau non optimisée',
                recommendation='1. Identifier tous les services exposés\n'
                             '2. Appliquer le principe du moindre privilège\n'
                             '3. Fermer tous les ports non essentiels\n'
                             '4. Utiliser un firewall pour restreindre l\'accès\n'
                             '5. Mettre en place un monitoring des ports',
                evidence={'port_count': nb_ports, 'threshold': THRESHOLDS['max_open_ports']},
                category='network'
            ))
        elif nb_ports > 5:
            self.signals.append(Signal(
                signal_id='many_ports_open',
                severity='MEDIUM',
                title='Plusieurs ports ouverts détectés',
                description=f'{nb_ports} ports ouverts (recommandé pour un site web: 2-3 ports)',
                impact='Surface d\'attaque élargie. Plus de ports ouverts = plus de risques potentiels.',
                recommendation='Vérifier que tous les ports exposés sont nécessaires et correctement sécurisés',
                evidence={'port_count': nb_ports},
                category='network'
            ))
    
    def _check_ports(self, ports_data: Dict):
        """Vérifie les ports ouverts (version originale - obsolète avec l'API Scorton)"""
        # Cette méthode n'est plus utilisée car l'API Scorton ne fournit pas la liste détaillée
        # Conservée pour compatibilité avec d'autres sources de données
        open_ports = ports_data.get('openPorts', [])
        
        if not open_ports:
            return
        
        # Ports critiques
        critical_ports = [p for p in open_ports if p in THRESHOLDS['critical_ports']]
        if critical_ports:
            port_details = {
                22: 'SSH - Accès administrateur distant',
                3389: 'RDP - Bureau à distance Windows'
            }
            
            self.signals.append(Signal(
                signal_id='critical_ports_exposed',
                severity='CRITICAL',
                title=f'Ports critiques exposés publiquement',
                description=f'Les ports {", ".join(map(str, critical_ports))} sont accessibles depuis Internet',
                impact='Risque MAJEUR de compromission:\n'
                       f'• Port 22 (SSH): Cible de brute-force, exploitation de CVE OpenSSH\n'
                       f'• Port 3389 (RDP): Vecteur principal des ransomwares, attaques BlueKeep\n'
                       'Ces ports permettent un accès administrateur complet au serveur.',
                recommendation='URGENT - Dans les 24h:\n'
                             '1. Fermer ces ports au niveau du firewall\n'
                             '2. Si nécessaires, les restreindre à des IP whitelistées\n'
                             '3. Implémenter un VPN pour l\'accès administratif\n'
                             '4. Activer l\'authentification multi-facteurs',
                evidence={'critical_ports': critical_ports, 'all_open_ports': open_ports},
                category='network'
            ))
        
        # Ports suspects (non critiques mais inhabituels)
        suspicious_ports = [p for p in open_ports if p in THRESHOLDS['suspicious_ports'] 
                           and p not in THRESHOLDS['critical_ports']]
        if suspicious_ports:
            port_details = {
                23: 'Telnet - Protocole non chiffré obsolète',
                389: 'LDAP - Annuaire Active Directory',
                5060: 'SIP - Téléphonie VoIP',
                5900: 'VNC - Bureau à distance',
                8080: 'HTTP alternatif - Souvent proxy/admin'
            }
            
            descriptions = [f"Port {p}: {port_details.get(p, 'Service non standard')}" 
                          for p in suspicious_ports]
            
            self.signals.append(Signal(
                signal_id='suspicious_ports_open',
                severity='HIGH',
                title='Ports suspects exposés',
                description=f'Ports inhabituels pour un site web public: {", ".join(map(str, suspicious_ports))}',
                impact='Surface d\'attaque élargie:\n' + '\n'.join(f'• {desc}' for desc in descriptions),
                recommendation='1. Auditer l\'utilité de chaque port\n'
                             '2. Fermer les ports non utilisés\n'
                             '3. Restreindre l\'accès par IP si nécessaire',
                evidence={'suspicious_ports': suspicious_ports},
                category='network'
            ))
        
        # Trop de ports ouverts
        if len(open_ports) > THRESHOLDS['max_open_ports']:
            self.signals.append(Signal(
                signal_id='too_many_ports',
                severity='MEDIUM',
                title='Nombre élevé de ports ouverts',
                description=f'{len(open_ports)} ports détectés ouverts (seuil: {THRESHOLDS["max_open_ports"]})',
                impact='Chaque port ouvert est une porte d\'entrée potentielle. '
                       'Une surface d\'attaque large augmente les risques d\'exploitation.',
                recommendation='Appliquer le principe du moindre privilège: '
                             'ne garder ouverts que les ports strictement nécessaires',
                evidence={'count': len(open_ports), 'ports': open_ports},
                category='network'
            ))
    
    def _check_tls(self, ssl_data: Dict):
        """Vérifie le certificat TLS"""
        if not ssl_data:
            return
        
        # Vérifier l'expiration du certificat
        expiry_days = ssl_data.get('expiry_days', 0)
        
        if expiry_days and expiry_days > 0:
            if expiry_days < THRESHOLDS['tls_expiry_critical_days']:
                severity = 'CRITICAL'
                title = 'Certificat TLS expire dans moins de 30 jours'
            elif expiry_days < THRESHOLDS['tls_expiry_warning_days']:
                severity = 'MEDIUM'
                title = 'Certificat TLS expire bientôt'
            else:
                return  # Tout va bien
            
            self.signals.append(Signal(
                signal_id='tls_expiring',
                severity=severity,
                title=title,
                description=f'Le certificat TLS expire dans {expiry_days} jours',
                impact='Si le certificat expire:\n'
                       '• Les navigateurs afficheront un avertissement de sécurité\n'
                       '• Perte de confiance des utilisateurs\n'
                       '• Interruption possible des services',
                recommendation='Planifier le renouvellement du certificat TLS\n'
                             'Conseil: Automatiser avec Let\'s Encrypt ou votre CA',
                evidence={'expiry_days': expiry_days},
                category='encryption'
            ))
        
        # Vérifier la force de la clé
        strength = ssl_data.get('strength', 0)
        if strength and strength < 256:
            self.signals.append(Signal(
                signal_id='weak_tls_key',
                severity='HIGH',
                title='Clé TLS faible',
                description=f'Clé de {strength} bits (recommandé: 256+ bits)',
                impact='Une clé faible peut être cassée par des attaquants disposant de ressources',
                recommendation='Générer un nouveau certificat avec une clé de 256 bits minimum (RSA 2048+ ou ECC 256+)',
                evidence={'key_strength': strength},
                category='encryption'
            ))
        
        # Vérifier si certificat auto-signé
        if ssl_data.get('self_signed'):
            self.signals.append(Signal(
                signal_id='self_signed_cert',
                severity='MEDIUM',
                title='Certificat auto-signé détecté',
                description='Le certificat TLS est auto-signé',
                impact='• Les navigateurs afficheront un avertissement\n'
                       '• Perte de confiance des utilisateurs\n'
                       '• Peut indiquer un site de test/développement',
                recommendation='Utiliser un certificat signé par une autorité de certification reconnue (Let\'s Encrypt, etc.)',
                evidence={'cert_cn': ssl_data.get('cert_cn', '')},
                category='encryption'
            ))
    
    def _check_http_security(self, http_sec: Dict):
        """Vérifie les headers HTTP de sécurité"""
        missing_headers = []
        
        if not http_sec.get('contentSecurityPolicy'):
            missing_headers.append('Content-Security-Policy')
            self.signals.append(Signal(
                signal_id='no_csp',
                severity='HIGH',
                title='Content Security Policy (CSP) absente',
                description='Aucune politique de sécurité du contenu n\'est configurée',
                impact='Vulnérable aux attaques XSS (Cross-Site Scripting):\n'
                       '• Injection de scripts malveillants\n'
                       '• Vol de cookies de session\n'
                       '• Redirection vers sites de phishing\n'
                       '• Modification du contenu de la page',
                recommendation='Implémenter une CSP stricte:\n'
                             'Content-Security-Policy: default-src \'self\'; '
                             'script-src \'self\' https://trusted-cdn.com; '
                             'style-src \'self\' \'unsafe-inline\'; '
                             'img-src \'self\' data: https:',
                evidence={'header': 'Content-Security-Policy', 'present': False},
                category='headers'
            ))
        
        if not http_sec.get('xFrameOptions'):
            missing_headers.append('X-Frame-Options')
            self.signals.append(Signal(
                signal_id='no_xframe',
                severity='MEDIUM',
                title='X-Frame-Options absent',
                description='Le site peut être intégré dans une iframe',
                impact='Vulnérable au clickjacking:\n'
                       '• Le site peut être affiché dans une iframe malveillante\n'
                       '• L\'utilisateur peut cliquer sur des éléments cachés\n'
                       '• Risque de vol d\'identifiants',
                recommendation='Ajouter le header: X-Frame-Options: DENY ou SAMEORIGIN',
                evidence={'header': 'X-Frame-Options', 'present': False},
                category='headers'
            ))
        
        if not http_sec.get('xContentTypeOptions'):
            missing_headers.append('X-Content-Type-Options')
        
        if not http_sec.get('xXSSProtection'):
            missing_headers.append('X-XSS-Protection')
        
        if len(missing_headers) > 2:
            self.signals.append(Signal(
                signal_id='missing_security_headers',
                severity='MEDIUM',
                title=f'{len(missing_headers)} headers de sécurité manquants',
                description=f'Headers absents: {", ".join(missing_headers)}',
                impact='Exposition à diverses vulnérabilités web classiques',
                recommendation='Configurer les headers de sécurité standard dans le serveur web',
                evidence={'missing_headers': missing_headers},
                category='headers'
            ))
    
    def _check_dnssec(self, dnssec_data: Dict):
        """Vérifie la configuration DNSSEC"""
        has_dnssec = any([
            dnssec_data.get('DNSKEY', {}).get('isFound'),
            dnssec_data.get('DS', {}).get('isFound'),
            dnssec_data.get('RRSIG', {}).get('isFound')
        ])
        
        if not has_dnssec:
            self.signals.append(Signal(
                signal_id='no_dnssec',
                severity='MEDIUM',
                title='DNSSEC non configuré',
                description='Le domaine n\'utilise pas DNSSEC pour sécuriser ses enregistrements DNS',
                impact='Vulnérable aux attaques DNS:\n'
                       '• DNS spoofing: redirection vers un faux site\n'
                       '• Cache poisoning: corruption des caches DNS\n'
                       '• Man-in-the-middle au niveau DNS',
                recommendation='Activer DNSSEC auprès de votre registrar:\n'
                             '1. Générer les clés DNSSEC\n'
                             '2. Signer la zone DNS\n'
                             '3. Publier les enregistrements DS',
                evidence=dnssec_data,
                category='dns'
            ))
    
    def _check_security_txt(self, security_txt: Dict):
        """Vérifie la présence de security.txt"""
        if not security_txt.get('isPresent'):
            self.signals.append(Signal(
                signal_id='no_security_txt',
                severity='LOW',
                title='Fichier security.txt absent',
                description='Aucun point de contact sécurité n\'est publié',
                impact='Les chercheurs en sécurité ne savent pas comment signaler des vulnérabilités de manière responsable',
                recommendation='Créer un fichier /.well-known/security.txt avec:\n'
                             'Contact: security@votredomaine.com\n'
                             'Expires: 2026-12-31T23:59:59z\n'
                             'Preferred-Languages: fr, en',
                evidence={'present': False},
                category='policy'
            ))
    
    def _check_trackers(self, trackers_data: Dict):
        """Vérifie les trackers tiers"""
        if trackers_data.get('Tracker_detected'):
            trackers_found = trackers_data.get('Trackers_found', [])
            self.signals.append(Signal(
                signal_id='trackers_detected',
                severity='LOW',
                title=f'{len(trackers_found)} trackers tiers détectés',
                description=f'Trackers: {", ".join(trackers_found[:5])}',
                impact='Risques de confidentialité:\n'
                       '• Collecte de données utilisateurs par des tiers\n'
                       '• Non-conformité RGPD potentielle\n'
                       '• Fuite d\'informations sensibles',
                recommendation='1. Auditer chaque tracker\n'
                             '2. Obtenir consentement explicite (RGPD)\n'
                             '3. Minimiser les trackers au strict nécessaire',
                evidence={'count': len(trackers_found), 'trackers': trackers_found},
                category='privacy'
            ))
    
    def _check_scores(self, scores: Dict):
        """Vérifie les scores globaux"""
        final_score = scores.get('final', 0)
        if final_score < THRESHOLDS['min_security_score']:
            self.signals.append(Signal(
                signal_id='low_security_score',
                severity='HIGH' if final_score < 50 else 'MEDIUM',
                title=f'Score de sécurité faible: {final_score}/100',
                description=f'Niveau de risque: {scores.get("risk_level", "unknown")}',
                impact='Le site présente plusieurs faiblesses de sécurité cumulées',
                recommendation='Prioriser la correction des vulnérabilités critiques et hautes',
                evidence=scores,
                category='overall'
            ))
    
    def get_strong_signals(self) -> List[Signal]:
        """Retourne uniquement les signaux forts (CRITICAL, HIGH)"""
        return [s for s in self.signals if s.severity in ['CRITICAL', 'HIGH']]
    
    def get_weak_signals(self) -> List[Signal]:
        """Retourne uniquement les signaux faibles (MEDIUM, LOW, INFO)"""
        return [s for s in self.signals if s.severity in ['MEDIUM', 'LOW', 'INFO']]
    
    def get_summary(self) -> Dict:
        """Génère un résumé des signaux détectés"""
        return {
            'total': len(self.signals),
            'by_severity': {
                'CRITICAL': len([s for s in self.signals if s.severity == 'CRITICAL']),
                'HIGH': len([s for s in self.signals if s.severity == 'HIGH']),
                'MEDIUM': len([s for s in self.signals if s.severity == 'MEDIUM']),
                'LOW': len([s for s in self.signals if s.severity == 'LOW']),
                'INFO': len([s for s in self.signals if s.severity == 'INFO']),
            },
            'strong_signals': len(self.get_strong_signals()),
            'weak_signals': len(self.get_weak_signals()),
        }
