"""
Générateur de rapport HTML pour VibeStream
"""

import json
from datetime import datetime
from typing import Dict


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeStream - Rapport d'Audit de Sécurité</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .metadata-item {
            display: flex;
            flex-direction: column;
        }
        
        .metadata-label {
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .metadata-value {
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
            margin-top: 3px;
        }
        
        .summary {
            padding: 40px;
            background: #fff;
        }
        
        .summary h2 {
            font-size: 1.8em;
            color: #1e3c72;
            margin-bottom: 25px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .summary-card .number {
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .summary-card .label {
            font-size: 0.95em;
            opacity: 0.95;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 10px 25px;
            border-radius: 50px;
            font-weight: 700;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .risk-critical {
            background: #dc3545;
            color: white;
        }
        
        .risk-high {
            background: #ff6b6b;
            color: white;
        }
        
        .risk-medium {
            background: #ffa500;
            color: white;
        }
        
        .risk-low {
            background: #28a745;
            color: white;
        }
        
        .section {
            padding: 40px;
            border-top: 1px solid #e0e0e0;
        }
        
        .section h2 {
            font-size: 1.8em;
            color: #1e3c72;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .signal-card, .anomaly-card, .hypothesis-card {
            background: #f8f9fa;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            transition: transform 0.2s;
        }
        
        .signal-card:hover, .anomaly-card:hover, .hypothesis-card:hover {
            transform: translateX(5px);
        }
        
        .signal-card.critical {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .signal-card.high {
            border-left-color: #ff6b6b;
            background: #fff8f8;
        }
        
        .signal-card.medium {
            border-left-color: #ffa500;
            background: #fffaf0;
        }
        
        .signal-card.low {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        
        .signal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .signal-title {
            font-size: 1.2em;
            font-weight: 700;
            color: #1e3c72;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-high {
            background: #ff6b6b;
            color: white;
        }
        
        .severity-medium {
            background: #ffa500;
            color: white;
        }
        
        .severity-low {
            background: #28a745;
            color: white;
        }
        
        .signal-description {
            color: #555;
            margin-bottom: 12px;
            font-size: 0.95em;
        }
        
        .signal-detail {
            margin-top: 10px;
        }
        
        .signal-detail-label {
            font-weight: 600;
            color: #1e3c72;
            margin-right: 8px;
        }
        
        .signal-detail-value {
            color: #666;
        }
        
        .hypothesis-card {
            border-left-color: #764ba2;
        }
        
        .hypothesis-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .hypothesis-title {
            font-size: 1.15em;
            font-weight: 700;
            color: #1e3c72;
            flex: 1;
        }
        
        .probability-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            background: #764ba2;
            color: white;
        }
        
        .hypothesis-section {
            margin-bottom: 12px;
        }
        
        .hypothesis-label {
            font-weight: 600;
            color: #1e3c72;
            margin-bottom: 5px;
        }
        
        .hypothesis-text {
            color: #555;
            line-height: 1.6;
        }
        
        .indicators-list {
            list-style: none;
            margin-top: 8px;
        }
        
        .indicators-list li {
            padding-left: 20px;
            position: relative;
            margin-bottom: 5px;
            color: #555;
        }
        
        .indicators-list li:before {
            content: "▸";
            position: absolute;
            left: 0;
            color: #764ba2;
            font-weight: bold;
        }
        
        .scores-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .score-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        
        .score-label {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
        }
        
        .score-value {
            font-size: 1.8em;
            font-weight: 700;
            color: #1e3c72;
        }
        
        .footer {
            background: #1e3c72;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
            font-style: italic;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 VibeStream</h1>
            <div class="subtitle">Rapport d'Audit de Sécurité Web</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">URL Analysée</span>
                    <span class="metadata-value">{url}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Domaine</span>
                    <span class="metadata-value">{domain}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Date de Scan</span>
                    <span class="metadata-value">{scan_date}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Version Analyseur</span>
                    <span class="metadata-value">{version}</span>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Résumé Exécutif</h2>
            <div class="summary-cards">
                <div class="summary-card">
                    <div class="number">{total_strong}</div>
                    <div class="label">Signaux Forts</div>
                </div>
                <div class="summary-card">
                    <div class="number">{total_weak}</div>
                    <div class="label">Signaux Faibles</div>
                </div>
                <div class="summary-card">
                    <div class="number">{total_anomalies}</div>
                    <div class="label">Anomalies</div>
                </div>
                <div class="summary-card">
                    <div class="number">{total_hypotheses}</div>
                    <div class="label">Hypothèses</div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 20px;">
                <span class="risk-badge risk-{risk_class}">Risque Global: {risk_level}</span>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Signaux Forts (Critiques)</h2>
            {signals_strong_html}
        </div>
        
        <div class="section">
            <h2>⚠️ Signaux Faibles</h2>
            {signals_weak_html}
        </div>
        
        <div class="section">
            <h2>🔎 Anomalies Détectées</h2>
            {anomalies_html}
        </div>
        
        <div class="section">
            <h2>💡 Hypothèses de Risques</h2>
            {hypotheses_html}
        </div>
        
        <div class="section">
            <h2>📈 Scores Techniques</h2>
            <div class="scores-grid">
                {scores_html}
            </div>
        </div>
        
        <div class="footer">
            <p>Généré par VibeStream Analyzer v1.0.0</p>
            <p>Scorton Cybersecurity Hackathon - Challenge 1</p>
        </div>
    </div>
</body>
</html>
"""


def generate_html_report(report_data: Dict, output_path: str = 'vibestream_report.html'):
    """Génère un rapport HTML à partir des données d'analyse"""
    
    metadata = report_data['metadata']
    summary = report_data['summary']
    signals = report_data['signals']
    anomalies = report_data['anomalies']
    hypotheses = report_data['hypotheses']
    raw_scores = report_data['raw_scores']
    
    # Formater la date
    scan_date = datetime.fromisoformat(metadata['scan_date']).strftime('%d/%m/%Y %H:%M')
    
    # Classe de risque pour le CSS
    risk_class = summary['global_risk_level'].lower()
    
    # Générer les signaux forts
    signals_strong_html = ""
    if signals['strong']:
        for signal in signals['strong']:
            severity_class = signal['severity'].lower()
            signals_strong_html += f"""
            <div class="signal-card {severity_class}">
                <div class="signal-header">
                    <div class="signal-title">{signal['description']}</div>
                    <span class="severity-badge severity-{severity_class}">{signal['severity']}</span>
                </div>
                <div class="signal-description">
                    <div class="signal-detail">
                        <span class="signal-detail-label">Impact:</span>
                        <span class="signal-detail-value">{signal['impact']}</span>
                    </div>
                    <div class="signal-detail">
                        <span class="signal-detail-label">Remédiation:</span>
                        <span class="signal-detail-value">{signal['remediation']}</span>
                    </div>
                </div>
            </div>
            """
    else:
        signals_strong_html = '<div class="no-data">Aucun signal fort détecté ✓</div>'
    
    # Générer les signaux faibles
    signals_weak_html = ""
    if signals['weak']:
        for signal in signals['weak']:
            severity_class = signal['severity'].lower()
            signals_weak_html += f"""
            <div class="signal-card {severity_class}">
                <div class="signal-header">
                    <div class="signal-title">{signal['description']}</div>
                    <span class="severity-badge severity-{severity_class}">{signal['severity']}</span>
                </div>
                <div class="signal-description">
                    <div class="signal-detail">
                        <span class="signal-detail-label">Impact:</span>
                        <span class="signal-detail-value">{signal['impact']}</span>
                    </div>
                    <div class="signal-detail">
                        <span class="signal-detail-label">Remédiation:</span>
                        <span class="signal-detail-value">{signal['remediation']}</span>
                    </div>
                </div>
            </div>
            """
    else:
        signals_weak_html = '<div class="no-data">Aucun signal faible détecté ✓</div>'
    
    # Générer les anomalies
    anomalies_html = ""
    if anomalies:
        for anomaly in anomalies:
            anomalies_html += f"""
            <div class="anomaly-card">
                <div class="signal-header">
                    <div class="signal-title">{anomaly['anomaly']}</div>
                    <span class="probability-badge">{anomaly['likelihood']}</span>
                </div>
                <div class="signal-description">
                    <div class="signal-detail">
                        <span class="signal-detail-label">Catégorie:</span>
                        <span class="signal-detail-value">{anomaly['category']}</span>
                    </div>
                    <div class="signal-detail">
                        <span class="signal-detail-label">Explication:</span>
                        <span class="signal-detail-value">{anomaly['explanation']}</span>
                    </div>
                </div>
            </div>
            """
    else:
        anomalies_html = '<div class="no-data">Aucune anomalie détectée ✓</div>'
    
    # Générer les hypothèses
    hypotheses_html = ""
    if hypotheses:
        for hyp in hypotheses:
            indicators_html = ""
            for indicator in hyp['indicators']:
                indicators_html += f"<li>{indicator}</li>"
            
            hypotheses_html += f"""
            <div class="hypothesis-card">
                <div class="hypothesis-header">
                    <div class="hypothesis-title">{hyp['hypothesis']}</div>
                    <span class="probability-badge">Probabilité: {hyp['probability']}</span>
                </div>
                <div class="hypothesis-section">
                    <div class="hypothesis-label">Raisonnement:</div>
                    <div class="hypothesis-text">{hyp['reasoning']}</div>
                </div>
                <div class="hypothesis-section">
                    <div class="hypothesis-label">Risque:</div>
                    <div class="hypothesis-text">{hyp['risk']}</div>
                </div>
                <div class="hypothesis-section">
                    <div class="hypothesis-label">Indicateurs:</div>
                    <ul class="indicators-list">
                        {indicators_html}
                    </ul>
                </div>
            </div>
            """
    else:
        hypotheses_html = '<div class="no-data">Aucune hypothèse formulée</div>'
    
    # Générer les scores
    scores_html = ""
    score_labels = {
        'score_tech': 'Score Technique',
        'score_ml': 'Score ML',
        'score_dl': 'Score DL',
        'score_ai': 'Score AI',
        'final_score': 'Score Final'
    }
    
    for key, label in score_labels.items():
        value = raw_scores.get(key, 'N/A')
        if value != 'N/A':
            try:
                value = float(value)
                value = f"{value:.1f}"
            except:
                pass
        
        scores_html += f"""
        <div class="score-box">
            <div class="score-label">{label}</div>
            <div class="score-value">{value}</div>
        </div>
        """
    
    # Remplir le template
    html_content = HTML_TEMPLATE.format(
        url=metadata['url'],
        domain=metadata['domain'],
        scan_date=scan_date,
        version=metadata['analyzer_version'],
        total_strong=summary['total_signals_strong'],
        total_weak=summary['total_signals_weak'],
        total_anomalies=summary['total_anomalies'],
        total_hypotheses=summary['total_hypotheses'],
        risk_level=summary['global_risk_level'],
        risk_class=risk_class,
        signals_strong_html=signals_strong_html,
        signals_weak_html=signals_weak_html,
        anomalies_html=anomalies_html,
        hypotheses_html=hypotheses_html,
        scores_html=scores_html
    )
    
    # Sauvegarder
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[✓] Rapport HTML généré: {output_path}")


if __name__ == '__main__':
    # Exemple d'utilisation
    try:
        with open('vibestream_report.json', 'r') as f:
            report = json.load(f)
        
        generate_html_report(report)
    except FileNotFoundError:
        print("[!] Fichier vibestream_report.json introuvable")
        print("[i] Exécutez d'abord analyzer.py")
