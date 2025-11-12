# phishing_detector.py
import re
import os
import joblib
import math
import numpy as np
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
from collections import Counter

MODEL_PATH = "model.joblib"
VECT_PATH = "vect.joblib"
META_PATH = "meta.json"

SUSPICIOUS_TLDS = {'.ru', '.cn', '.tk', '.zip', '.ml', '.cf'}

# -----------------------
# helper utilities
# -----------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [v / len(s) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def _is_ipv4(host: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))

def _contains_credential_words(text: str):
    creds = ['password', 'passwd', 'login', 'account', 'verify', 'confirm', 'ssn']
    t = text.lower()
    return sum(1 for w in creds if w in t)

def _punycode_domain(host: str):
    # detect xn-- punycode
    try:
        if host.startswith("xn--") or "xn--" in host:
            return True
    except Exception:
        pass
    return False

# -----------------------
# URL features
# -----------------------
def url_features(url: str):
    """
    Returns a fixed-length list of numeric features for the URL/host/path.
    Order is important and later used for names.
    """
    if not url:
        return [0]*18

    # normalize (ensure scheme)
    if '://' not in url:
        url = 'http://' + url
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse('http://' + url)

    host = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    netloc = parsed.netloc or host

    # Basic counts
    len_host = len(host)
    len_path = len(path)
    len_netloc = len(netloc)
    num_dots = host.count('.')
    num_hyphens = host.count('-') + path.count('-')
    num_at = url.count('@')
    num_qparams = 1 if query else 0
    has_https = 1 if parsed.scheme == 'https' else 0
    has_ip = 1 if _is_ipv4(host) else 0
    suspicious_tld = 1 if any(host.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    puny = 1 if _punycode_domain(host) else 0

    # entropy & digits
    host_entropy = _entropy(host)
    path_entropy = _entropy(path)
    digits_ratio = sum(c.isdigit() for c in netloc) / max(1, len(netloc))

    # tokens & suspicious patterns
    tokens = re.split(r'[\-._/]', host + path)
    tokens = [t for t in tokens if t]
    uncommon_tokens = sum(1 for t in tokens if len(t) <= 2)  # too short tokens
    suspicious_keywords = sum(1 for k in ['secure', 'login', 'verify', 'account', 'update', 'bank'] if k in url.lower())

    # length-based heuristics
    long_url = 1 if len(url) > 100 else 0
    many_dots = 1 if num_dots > 3 else 0

    feats = [
        has_https,
        num_at,
        num_dots,
        num_hyphens,
        suspicious_tld,
        has_ip,
        puny,
        int(num_qparams),
        len_host,
        len_path,
        digits_ratio,
        round(host_entropy, 3),
        round(path_entropy, 3),
        uncommon_tokens,
        suspicious_keywords,
        long_url,
        many_dots,
        int(_is_ipv4(parsed.hostname or '')),
    ]
    return feats

URL_FEAT_NAMES = [
    "has_https","num_at","num_dots","num_hyphens","suspicious_tld","has_ip","punycode",
    "has_qparams","host_len","path_len","digits_ratio","host_entropy","path_entropy",
    "short_token_count","suspicious_keywords","long_url","many_dots","host_is_ipv4"
]

# -----------------------
# Text heuristics
# -----------------------
def text_heuristics(text: str):
    t = (text or "").lower()
    keywords = ["urgent","verify","click here","login","confirm","password","account","update","bank","limited"]
    keyword_hits = sum(1 for kw in keywords if kw in t)
    exclamations = t.count('!')
    all_caps_words = sum(1 for w in re.findall(r'\b[A-Z]{2,}\b', text))
    num_urls = len(re.findall(r'https?://', text))
    cred_words = _contains_credential_words(text)
    avg_word_len = (sum(len(w) for w in re.findall(r'\w+', text)) / max(1, len(re.findall(r'\w+', text))))
    text_entropy = _entropy(t)
    len_text = len(t)

    feats = [
        keyword_hits,
        exclamations,
        all_caps_words,
        num_urls,
        cred_words,
        round(avg_word_len,2),
        round(text_entropy,3),
        len_text
    ]
    return feats

TEXT_FEAT_NAMES = [
    "keyword_hits","exclamations","all_caps_words","num_urls","credential_words",
    "avg_word_len","text_entropy","text_length"
]

# -----------------------
# Feature vector builder
# -----------------------
def build_feature_vector(text: str, url: str, vect):
    """
    Return scipy sparse matrix with [TF-IDF | numeric_feats].
    vect must be the trained TF-IDF vectorizer (with transform).
    """
    # text TF-IDF
    X_text = vect.transform([text or ""])
    # numeric features
    url_feats = np.array(url_features(url)).reshape(1, -1)
    txt_feats = np.array(text_heuristics(text)).reshape(1, -1)
    numeric = np.hstack([url_feats, txt_feats])
    numeric_sparse = csr_matrix(numeric.astype(float))
    X = hstack([X_text, numeric_sparse])
    return X

# -----------------------
# model loading & prediction
# -----------------------
def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECT_PATH):
        raise FileNotFoundError("Run train_model.py to create model.joblib and vect.joblib")
    model = joblib.load(MODEL_PATH)
    vect = joblib.load(VECT_PATH)
    return model, vect

def predict(text, url):
    """
    Returns (label, prob, reasons, feature_snapshot)
    label: "PHISH" or "LEGIT"
    prob: float between 0..1 (probability of PHISH)
    reasons: dict of heuristic names -> value (non-zero only)
    feature_snapshot: dict of numeric features + top tokens (small)
    """
    model, vect = load_model()
    X = build_feature_vector(text, url, vect)
    prob = float(model.predict_proba(X)[:,1][0])
    label = "PHISH" if prob >= 0.5 else "LEGIT"

    # heuristic reasons (only non-zero numeric ones)
    url_vals = url_features(url)
    txt_vals = text_heuristics(text)
    all_vals = url_vals + txt_vals
    feat_names = URL_FEAT_NAMES + TEXT_FEAT_NAMES
    reasons = {n: v for n, v in zip(feat_names, all_vals) if (isinstance(v, (int,float)) and v)}
    
    # quick approximate top TF-IDF tokens that influenced the decision:
    top_tokens = []
    try:
        # if linear, we can inspect coef for TF-IDF part (approx)
        if hasattr(model, "coef_"):
            coef = model.coef_.ravel()
            # vectorizer feature names
            try:
                tf_names = vect.get_feature_names_out()
                # TF-IDF part length
                k = len(tf_names)
                # we can't easily multiply without the full X vector in dense, but we can get indices
                x_text = vect.transform([text or ""])
                # get nonzero tokens in text and score = coef[token_idx] * x_val
                nz = x_text.tocoo()
                scores = []
                for i, v in zip(nz.col, nz.data):
                    score = float(coef[i] * v) if i < len(coef) else 0.0
                    scores.append((score, tf_names[i]))
                scores = sorted(scores, key=lambda x: -abs(x[0]))[:6]
                top_tokens = [{"token": t, "impact": round(s,4)} for s,t in scores]
            except Exception:
                top_tokens = []
    except Exception:
        top_tokens = []

    # feature contribution (linear model) for numeric features
    feature_snapshot = {}
    try:
        if hasattr(model, "coef_"):
            coef = model.coef_.ravel()
            # last numeric features are appended after TF-IDF; find offsets
            tf_len = len(vect.get_feature_names_out())
            # numeric dims:
            numeric_len = len(URL_FEAT_NAMES) + len(TEXT_FEAT_NAMES)
            numeric_coefs = coef[tf_len:tf_len+numeric_len]
            contribs = {}
            for name, val, c in zip(URL_FEAT_NAMES + TEXT_FEAT_NAMES, all_vals, numeric_coefs):
                contribs[name] = {"value": val, "coef": float(round(c,6)), "contribution": round(float(c * val),6)}
            # sort by absolute contribution
            feature_snapshot = {
                "numeric_contributions_sorted": sorted(
                    [{ "name": n, **d } for n,d in contribs.items()],
                    key=lambda x: -abs(x["contribution"])
                )[:8],
                "top_tfidf_tokens": top_tokens
            }
    except Exception:
        feature_snapshot = {}

    return label, prob, reasons, feature_snapshot


# CLI support
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--text", default="", help="Email/body text")
    parser.add_argument("--url", default="", help="URL to score")
    args = parser.parse_args()
    try:
        label, prob, reasons, snapshot = predict(args.text, args.url)
        print(f"Prediction: {label} (phish probability = {prob:.2f})")
        print("Heuristic reasons:", reasons)
        print("Feature snapshot (top contributions):")
        for item in snapshot.get("numeric_contributions_sorted", []):
            print(item)
    except FileNotFoundError as e:
        print(e)
        print("Run: python train_model.py to create demo model.")
