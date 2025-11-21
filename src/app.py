# src/app.py
from flask import Flask, render_template, request
import joblib
import pandas as pd
import re
import os

# -------------------------------
# Correct Path Setup (IMPORTANT)
# -------------------------------
# This ensures Flask finds your 'templates' and 'static' folders correctly.
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

# -------------------------------
# Load model safely
# -------------------------------
try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None


# -------------------------------
# URL Feature Extraction
# -------------------------------
def extract_url_features(url):
    url = url.lower()
    return pd.DataFrame([{
        'url_length': len(url),
        'num_dots': url.count('.'),
        'has_https': 1 if 'https' in url else 0,
        'has_at': 1 if '@' in url else 0,
        'num_hyphens': url.count('-'),
        'num_digits': sum(c.isdigit() for c in url),
        'has_ip': 1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', url) else 0,
        'suspicious_words': 1 if any(word in url for word in [
            'secure', 'account', 'update', 'login', 'verify', 'bank', 'confirm', 'pay', 'signin'
        ]) else 0
    }])


# -------------------------------
# Extract links from email text
# -------------------------------
def extract_links_from_email(email_text):
    pattern = r'(https?://[^\s]+)'
    return re.findall(pattern, email_text)


# -------------------------------
# Home Route
# -------------------------------
@app.route('/')
def home():
    return render_template('index.html')


# -------------------------------
# URL Prediction Route
# -------------------------------
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = extract_url_features(url)

    if model:
        prediction = model.predict(features)[0]
        confidence = round(max(model.predict_proba(features)[0]) * 100, 2)
        label = "Legitimate" if prediction == 0 else "Phishing"
    else:
        label = "Unable to Analyze"
        confidence = "N/A"

    features_text = (
        f"Length: {len(url)}, HTTPS: {'Yes' if 'https' in url else 'No'}, "
        f"'@' present: {'Yes' if '@' in url else 'No'}, Dots: {url.count('.')}"
    )

    return render_template(
        'result.html',
        url=url,
        prediction=label,
        confidence=confidence,
        features=features_text
    )


# -------------------------------
# EMAIL CHECK ROUTE (your version — unchanged)
# -------------------------------
@app.route('/check_email', methods=['POST'])
def check_email():
    email_text = request.form['email_text'].strip()

    if not email_text:
        return render_template(
            'result.html',
            url="Empty email content.",
            prediction="Unable to Analyze",
            confidence="N/A",
            features="No text provided."
        )

    # Extract URLs from email
    urls = extract_links_from_email(email_text)

    # Define suspicious patterns (strong indicators)
    strong_keywords = [
        'verify', 'confirm', 'reset password', 'click here', 'login',
        'secure link', 'update your info', 'suspend', 'urgent', 'security alert'
    ]
    weak_keywords = ['account', 'update', 'bank', 'paypal', 'secure', 'password']

    text_lower = email_text.lower()

    # Check for keyword presence
    strong_hits = [word for word in strong_keywords if word in text_lower]
    weak_hits = [word for word in weak_keywords if word in text_lower]

    features_info = []
    if urls:
        features_info.append(f"URLs found: {', '.join(urls)}")
    else:
        features_info.append("No URLs found in the email.")

    if strong_hits:
        features_info.append(f"⚠️ Strong suspicious words: {', '.join(strong_hits)}")
    elif weak_hits:
        features_info.append(f"⚠️ Mild suspicious words: {', '.join(weak_hits)}")
    else:
        features_info.append("✅ No suspicious keywords found.")

    # -----------------------------
    # Decision Logic
    # -----------------------------
    if not urls and not strong_hits and not weak_hits:
        prediction = "Legitimate"
        confidence = 98.0

    elif strong_hits:
        prediction = "Phishing"
        confidence = 95.0

    elif urls:
        if model:
            features = extract_url_features(urls[0])
            model_pred = model.predict(features)[0]
            model_conf = round(max(model.predict_proba(features)[0]) * 100, 2)
            prediction = "Phishing" if model_pred == 1 else "Legitimate"
            confidence = model_conf
            features_info.append(f"Analyzed URL: {urls[0]}")
        else:
            prediction = "Phishing" if strong_hits or len(weak_hits) > 2 else "Legitimate"
            confidence = 85.0

    elif len(weak_hits) <= 2:
        prediction = "Legitimate"
        confidence = 93.0
    else:
        prediction = "Phishing"
        confidence = 88.0

    return render_template(
        'result.html',
        url=email_text[:120] + ("..." if len(email_text) > 120 else ""),
        prediction=prediction,
        confidence=confidence,
        features=" | ".join(features_info)
    )


# -------------------------------
# Run Flask App
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)
