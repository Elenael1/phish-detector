# app.py
from fastapi import FastAPI, Form
from pydantic import BaseModel
from phishing_detector import predict
import uvicorn

app = FastAPI(title="Phish Detector", version="0.1")

class PredictRequest(BaseModel):
    text: str = ""
    url: str = ""

@app.post("/predict")
async def predict_endpoint(req: PredictRequest):
    label, prob, reasons, snapshot = predict(req.text, req.url)
    return {
        "label": label,
        "probability": float(round(prob,4)),
        "reasons": reasons,
        "feature_snapshot": snapshot
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
