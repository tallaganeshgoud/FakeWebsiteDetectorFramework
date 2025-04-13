from flask import Flask, render_template, request
import joblib
import numpy as np
import validators
import whois
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Load the trained model
model = joblib.load("data/phishing_model.pkl")

# In-memory prediction log
prediction_log = []

# Feature extraction function
def extract_features(url):
    features = []
    messages = []

    if not validators.url(url):
        return None, ["❌ Invalid URL"]

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Whois info
    try:
        whois_info = whois.whois(domain)
    except:
        whois_info = {}

    # Feature 1: @ symbol
    has_at = '@' in url
    features.append(1 if has_at else 0)
    if has_at:
        messages.append("⚠️ URL contains '@' symbol.")

    # Feature 2: IP address (simplified check)
    has_ip = isinstance(whois_info, dict) and 'address' in whois_info
    features.append(1 if has_ip else 0)

    # Feature 3: URL length
    features.append(len(url))

    # Feature 4: Domain age
    try:
        age = whois_info.creation_date
        if isinstance(age, list):
            age = age[0]
        messages.append(f"✅ Domain created on: {age}")
        features.append((np.datetime64('now') - np.datetime64(age)).astype(int) // (365 * 24 * 60 * 60))
    except:
        features.append(0)
        messages.append("⚠️ Could not determine domain creation date.")

    # Feature 5: Path length
    features.append(len(parsed_url.path))

    # Feature 6: HTTPS check
    is_https = parsed_url.scheme == 'https'
    features.append(1 if is_https else 0)
    if not is_https:
        messages.append("⚠️ No SSL certificate found!")

    # Feature 7: Subdomains
    features.append(1 if len(parsed_url.netloc.split('.')) > 2 else 0)

    # Feature 8: Redirection check
    features.append(1 if '//' in url else 0)

    # Feature 9: Hyphen in domain
    features.append(1 if '-' in domain else 0)

    # Feature 10: Suspicious keywords in URL
    suspicious_keywords = ['secure', 'account', 'webscr', 'login', 'signin']
    features.append(1 if any(k in url.lower() for k in suspicious_keywords) else 0)

    # Feature 11: Number of dots
    features.append(url.count('.'))

    # Features 12–15: Advanced HTML features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        html = response.text.lower()

        # <form> detection
        form_count = len(soup.find_all('form'))
        features.append(form_count)
        if form_count > 0:
            messages.append("⚠️ Website has login forms – potential phishing site!")

        # <iframe> usage
        features.append(1 if '<iframe' in html else 0)

        # Suspicious JS events
        features.append(1 if any(tag in html for tag in ['onmouseover', 'onload', 'eval', 'unescape']) else 0)

        # Right-click disabled
        features.append(1 if 'event.button==2' in html or 'contextmenu' in html else 0)

    except Exception as e:
        features.extend([0, 0, 0, 0])
        messages.append("⚠️ Could not scan website HTML content.")

    messages.append("✅ Website scan complete!")

    return features, messages

# Home page
@app.route('/')
def home():
    return render_template("index.html")

# Prediction endpoint
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        try:
            url = request.form['url']
            features, messages = extract_features(url)

            if features is None:
                return render_template("result.html", prediction='Invalid URL', messages=messages)

            final_features = np.array(features).reshape(1, -1)
            prediction = model.predict(final_features)
            result = "Phishing Website" if prediction[0] == 1 else "Legitimate Website"

            prediction_log.append({'url': url, 'result': result})

            return render_template("result.html", prediction=result, history=prediction_log, messages=messages)
        except Exception as e:
            return render_template("result.html", prediction=f"Error: {e}", messages=["❌ Unexpected error occurred."])

if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(debug=True)
