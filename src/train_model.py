# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import re

# ---------------------------------------------
# 1️⃣ Sample dataset (replace with your real one if available)
# ---------------------------------------------
data = {
    'url': [
        'https://google.com',
        'http://phishing-site.ru/login',
        'https://secure.paypal.com',
        'http://fakebank.verify-login.net',
        'https://github.com',
        'http://malicious-update.xyz',
        'https://secure-login.bankofamerica.com',
        'http://update-paypal.info',
        'https://accounts.google.com',
        'http://verify-login.amazon-support.com'
    ],
    'label': [0, 1, 0, 1, 0, 1, 1, 1, 0, 1]  # 0 = Legitimate, 1 = Phishing
}

df = pd.DataFrame(data)

# ---------------------------------------------
# 2️⃣ Feature extraction (same as app.py)
# ---------------------------------------------
def extract_features(url):
    url = url.lower()
    return {
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
    }

feature_rows = [extract_features(u) for u in df['url']]
features_df = pd.DataFrame(feature_rows)

X = features_df
y = df['label']

# ---------------------------------------------
# 3️⃣ Train/test split
# ---------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ---------------------------------------------
# 4️⃣ Train model
# ---------------------------------------------
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# ---------------------------------------------
# 5️⃣ Save model (use joblib to match Flask)
# ---------------------------------------------
joblib.dump(model, 'phishing_model.pkl')

print("✅ Upgraded model trained and saved successfully with all 8 features!")
print("📊 Features used:", list(X.columns))
