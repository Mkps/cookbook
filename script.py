import requests
import os
import sys

API_URL = "https://radar.scorton.tech/analyze/url"
API_KEY = os.getenv('API_KEY', 'placeholder')

def call_scorton_api(url: str, output_format="json"):
    headers = {
        "accept": "application/json",
        "x-api-key": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "url": url,
        "output_format": output_format
    }

    response = requests.post(API_URL, headers=headers, data=data)

    if response.status_code != 200:
        raise Exception(f"Error {response.status_code}: {response.text}")

    return response.json()

def analyze_security(data):
    # --- fix: if the API returns a list instead of a dict ---
    if isinstance(data, list):
        if len(data) == 0:
            raise Exception("Empty API response")
        data = data[0]  # take the first element

    results = {
        "certificat_faible_ou_expirant": False,
        "redirection_anormale": False,
        "taille_html_anormale": False,
        "absence_https": False,
        "technologies_obsoletes": False,
        "signaux_faibles_detectes": False
    }

    # 1. Certificate checks
    cert = data.get("certificate", {})
    if isinstance(cert, dict):
        expiring = cert.get("expiring_soon", False)
        weak = cert.get("weak", False)
        results["certificat_faible_ou_expirant"] = expiring or weak

    # 2. Redirect anomalies
    redirect = data.get("redirect", {})
    if isinstance(redirect, dict):
        results["redirection_anormale"] = redirect.get("abnormal", False)

    # 3. HTML size anomaly
    html = data.get("html", {})
    if isinstance(html, dict):
        size = html.get("size", 0)
        results["taille_html_anormale"] = size < 500 or size > 5_000_000

    # 4. HTTPS presence
    scheme = data.get("scheme", "")
    results["absence_https"] = scheme.lower() != "https"

    # 5. Deprecated technologies
    tech_list = data.get("technologies", [])
    if isinstance(tech_list, list):
        for t in tech_list:
            if t.get("deprecated", False):
                results["technologies_obsoletes"] = True
                break

    # 6. Weak signals
    weak_signals = data.get("weak_signals", [])
    results["signaux_faibles_detectes"] = len(weak_signals) > 0

    return results


if __name__ == "__main__":
    website = ""
    if len(sys.argv) == 2:
        website = sys.argv[1]
    else:
        print("Please give one and only one target")
        exit(1)
    print(website)

    print("=== Querying API... ===")
    raw = call_scorton_api(website)

    print("\n=== Raw API Output ===")
    print(raw)

    print("\n=== Analyse de sécurité ===")
    results = analyze_security(raw)

    for key, value in results.items():
        print(f"{key}: {'OUI' if value else 'NON'}")
