# train_model.py
import pandas as pd
import joblib
import numpy as np
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_recall_curve, auc, precision_score, recall_score
from scipy.sparse import hstack
from phishing_detector import url_features, text_heuristics, URL_FEAT_NAMES, TEXT_FEAT_NAMES

# load dataset
df = pd.read_csv("data/train.csv").fillna("")
# assume columns: 'text', 'url', 'label' where label is 0 (legit) or 1 (phish)
y = df['label'].values

# TF-IDF
vect = TfidfVectorizer(max_features=5000, ngram_range=(1,2), stop_words='english')
X_text = vect.fit_transform(df["text"].astype(str))

# numeric features
def build_numeric(df):
    rows = []
    for _, r in df.iterrows():
        u = url_features(r.get("url",""))
        t = text_heuristics(r.get("text",""))
        rows.append(u + t)
    return np.array(rows, dtype=float)

X_num = build_numeric(df)

# stack
from scipy.sparse import csr_matrix
X = hstack([X_text, csr_matrix(X_num)])

# quick stratified CV
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
pr_aucs = []
precisions = []
recalls = []
for train_idx, test_idx in skf.split(X, y):
    Xtr, Xte = X[train_idx], X[test_idx]
    ytr, yte = y[train_idx], y[test_idx]
    model = LogisticRegression(max_iter=2000, class_weight='balanced')
    model.fit(Xtr, ytr)
    probs = model.predict_proba(Xte)[:,1]
    precision, recall, _ = precision_recall_curve(yte, probs)
    pr_auc = auc(recall, precision)
    pr_aucs.append(pr_auc)
    preds = (probs >= 0.5).astype(int)
    precisions.append(precision_score(yte, preds))
    recalls.append(recall_score(yte, preds))

print("CV PR-AUC:", np.mean(pr_aucs), "precision", np.mean(precisions), "recall", np.mean(recalls))

# train final model on full data
final_model = LogisticRegression(max_iter=2000, class_weight='balanced')
final_model.fit(X, y)

# save artifacts
joblib.dump(final_model, "model.joblib")
joblib.dump(vect, "vect.joblib")
meta = {
    "tfidf_features": len(vect.get_feature_names_out()),
    "numeric_feature_names": URL_FEAT_NAMES + TEXT_FEAT_NAMES,
    "cv_pr_auc_mean": float(np.mean(pr_aucs)),
}
with open("meta.json", "w") as f:
    json.dump(meta, f, indent=2)

print("Saved model.joblib, vect.joblib, meta.json")
