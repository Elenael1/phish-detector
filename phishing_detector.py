# phishing_detector.py
import argparse
from urllib.parse import urlparse
import re
import os
import joblib
import numpy as np

MODEL_PATH = "model.joblib"
VECT_PATH = "vect.joblib"

# Heuristic helpers
SUSPICIOUS_TLDS = {'.ru', '.cn', '.tk', '.zip', '.ml'}

def url_features(url):
    if not url:
        return [0,0,0,0,0,0]
    parsed = urlparse(url if '://' in url else 'http://' + url)
    host = parsed.netloc.lower()
    has_https = 1 if parsed.scheme == 'https' else 0
    has_at = 1 if '@' in url else 0
    num_dots = host.count('.')
    tld = '.' + host.split('.')[-1] if '.' in host else ''
    suspicious_tld = 1 if any(t in host for t in SUSPICIOUS_TLDS) else 0
    has_ip = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) else 0
    return [has_https, has_at, num_dots, suspicious_tld, has_ip, len(host)]

def text_heuristics(text):
    text = text or ""
    keywords = ["urgent", "verify", "click here", "login", "confirm", "password", "account", "update"]
    hits = sum(1 for k in keywords if k in text.lower())
    exclam = text.count('!')
    allcaps = sum(1 for w in text.split() if w.isupper() and len(w)>1)
    return [hits, exclam, allcaps]

def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECT_PATH):
        raise FileNotFoundError("Model files missing. Run train_model.py first.")
    model = joblib.load(MODEL_PATH)
    vect = joblib.load(VECT_PATH)
    return model, vect

def feature_vector(text, url, vect):
    tfidf = vect.transform([text])
    url_feats = np.array(url_features(url)).reshape(1, -1)
    txt_feats = np.array(text_heuristics(text)).reshape(1, -1)
    from scipy.sparse import hstack
    X = hstack([tfidf, url_feats, txt_feats])
    return X

def predict(text, url):
    model, vect = load_model()
    X = feature_vector(text, url, vect)
    prob = model.predict_proba(X)[:,1][0]
    label = "PHISH" if prob >= 0.5 else "LEGIT"
    # Provide simple explanation: show heuristic flags
    heur = url_features(url) + text_heuristics(text)
    heur_names = ["has_https","has_at","num_dots","suspicious_tld","has_ip","host_len",
                  "keyword_hits","exclamation","all_caps"]
    reasons = {n:v for n,v in zip(heur_names, heur) if v}
    return label, prob, reasons

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--text", default="", help="Email/body text")
    parser.add_argument("--url", default="", help="URL in email")
    args = parser.parse_args()
    try:
        label, prob, reasons = predict(args.text, args.url)
        print(f"Prediction: {label}  (phish probability = {prob:.2f})")
        print("Heuristic reasons (non-zero):", reasons)
    except FileNotFoundError as e:
        print(e)
        print("Run: python train_model.py to create demo model.")

