"""
Configuration et constantes pour VibeStream
"""

# Seuils de détection
THRESHOLDS = {
    'tls_expiry_warning_days': 90,
    'tls_expiry_critical_days': 30,
    'suspicious_ports': [22, 23, 3389, 389, 5060, 5900, 8080],
    'critical_ports': [22, 3389],  # SSH, RDP
    'max_open_ports': 5,
    'min_security_score': 70,
    'domain_age_young_days': 90,
}

# Catégories de signaux
SIGNAL_SEVERITY = {
    'CRITICAL': {'color': '#dc3545', 'priority': 1},
    'HIGH': {'color': '#fd7e14', 'priority': 2},
    'MEDIUM': {'color': '#ffc107', 'priority': 3},
    'LOW': {'color': '#28a745', 'priority': 4},
    'INFO': {'color': '#17a2b8', 'priority': 5},
}

# Règles de détection de signaux forts
STRONG_SIGNALS = {
    'whois_not_found': {
        'severity': 'CRITICAL',
        'description': 'Informations WHOIS introuvables',
        'impact': 'Impossible de vérifier l\'authenticité du domaine',
        'recommendation': 'Vérifier l\'enregistrement du domaine et la configuration WHOIS'
    },
    'critical_ports_exposed': {
        'severity': 'CRITICAL',
        'description': 'Ports critiques exposés publiquement',
        'impact': 'Risque élevé de compromission du serveur',
        'recommendation': 'Fermer immédiatement les ports SSH, RDP et LDAP ou les restreindre par IP'
    },
    'no_csp': {
        'severity': 'HIGH',
        'description': 'Content Security Policy absente',
        'impact': 'Vulnérable aux attaques XSS et injection de code',
        'recommendation': 'Implémenter une CSP stricte pour limiter les sources de contenu'
    },
    'no_dnssec': {
        'severity': 'MEDIUM',
        'description': 'DNSSEC non configuré',
        'impact': 'Vulnérable au DNS spoofing et cache poisoning',
        'recommendation': 'Activer DNSSEC pour sécuriser les résolutions DNS'
    },
    'tls_expiring_soon': {
        'severity': 'MEDIUM',
        'description': 'Certificat TLS expire bientôt',
        'impact': 'Risque d\'interruption de service et perte de confiance',
        'recommendation': 'Planifier le renouvellement du certificat TLS'
    },
    'missing_security_headers': {
        'severity': 'MEDIUM',
        'description': 'Headers de sécurité manquants',
        'impact': 'Exposition à diverses attaques (clickjacking, MIME sniffing)',
        'recommendation': 'Ajouter X-Frame-Options, X-Content-Type-Options, X-XSS-Protection'
    },
}

# Règles de détection de signaux faibles
WEAK_SIGNALS = {
    'no_security_txt': {
        'severity': 'LOW',
        'description': 'Fichier security.txt absent',
        'impact': 'Difficulté pour les chercheurs en sécurité de signaler des vulnérabilités',
        'recommendation': 'Créer un fichier /.well-known/security.txt avec contact sécurité'
    },
    'too_many_open_ports': {
        'severity': 'MEDIUM',
        'description': 'Nombre élevé de ports ouverts',
        'impact': 'Surface d\'attaque élargie',
        'recommendation': 'Auditer et fermer les ports non utilisés'
    },
    'trackers_detected': {
        'severity': 'LOW',
        'description': 'Trackers tiers détectés',
        'impact': 'Risques de confidentialité et conformité RGPD',
        'recommendation': 'Auditer les trackers et obtenir consentements explicites'
    },
}

# Configuration API Scorton
SCORTON_API = {
    'base_url': 'https://api.scorton.tech',
    'timeout': 30,
}
