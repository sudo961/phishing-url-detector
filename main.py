import re
import requests
import whois
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Function to check for phishing patterns
def is_suspicious_url(url):
    phishing_patterns = ["login", "secure", "account", "update", "verify", "bank", "password", "free", "gift"]
    return any(word in url.lower() for word in phishing_patterns)

# Function to check domain age
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        return w.creation_date
    except Exception:
        return "WHOIS Lookup Failed"

# Function to check against Google Safe Browsing (Requires API Key)
def check_google_safe_browsing(api_key, url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    return response.json()

# Feature extraction for machine learning
def extract_features(url):
    parsed_url = urlparse(url)
    return [
        len(url),
        url.count('-'),
        url.count('@'),
        url.count('.'),
        len(parsed_url.netloc.split('.')),
        parsed_url.netloc.endswith('.xyz')
    ]

# Sample training data (To be replaced with real data)
X_train = np.array([[50, 1, 0, 3, 2, False], [80, 3, 1, 5, 4, True]])
y_train = np.array([0, 1])  # 0 = Safe, 1 = Phishing

# Train a model
model = RandomForestClassifier()
model.fit(X_train, y_train)

def predict_phishing(url):
    features = np.array([extract_features(url)])
    return model.predict(features)[0]

if __name__ == "__main__":
    test_url = input("Enter URL to check: ")
    parsed_domain = urlparse(test_url).netloc
    
    print("\nChecking URL:", test_url)
    print("- Suspicious Patterns:", is_suspicious_url(test_url))
    print("- Domain Age:", get_domain_age(parsed_domain))
    print("- Google Safe Browsing Check:", check_google_safe_browsing("YOUR_API_KEY", test_url))
    print("- Machine Learning Prediction:", "Phishing" if predict_phishing(test_url) else "Safe")
