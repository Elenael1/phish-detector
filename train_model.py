import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib, numpy as np
from scipy.sparse import hstack
from phishing_detector import url_features, text_heuristics

df = pd.read_csv("data/train.csv").fillna("")

vect = TfidfVectorizer(max_features=1000, ngram_range=(1,2))
X_text = vect.fit_transform(df["text"].astype(str))

def build_numeric(df):
    rows = []
    for _, r in df.iterrows():
        u = url_features(r.get("url",""))
        t = text_heuristics(r.get("text",""))
        rows.append(u + t)
    return np.array(rows)

X = hstack([X_text, build_numeric(df)])
y = df["label"].values

model = LogisticRegression(max_iter=1000)
model.fit(X, y)

joblib.dump(model, "model.joblib")
joblib.dump(vect,  "vect.joblib")
print("Saved model.joblib and vect.joblib")
