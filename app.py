# app.py
import os, time, json
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from phishing_detector import predict
from redis import Redis
from rq import Queue
from rq.job import Job

# ---------- App & health ----------
app = FastAPI(title="Phish Detector")

from fastapi.responses import JSONResponse

@app.get("/")
def root():
    return JSONResponse({
        "message": "✅ Phish Detector API is running!",
        "docs": "Visit /docs to test the endpoints",
        "endpoints": ["/predict", "/predict-deep", "/result/{job_id}"]
    })


@app.get("/")
def root():
    return {"ok": True, "message": "Phish Detector API. POST /predict (fast) or /predict-deep (async). Open /docs."}

@app.get("/health")
def health():
    return {"status": "ok"}

# ---------- Redis / RQ ----------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
RQ_QUEUE = os.getenv("RQ_QUEUE", "deepchecks")
r = Redis.from_url(REDIS_URL)
q = Queue(RQ_QUEUE, connection=r)

# ---------- Existing fast endpoint ----------
@app.post("/predict")
def predict_endpoint(payload: dict):
    text = payload.get("text", "")
    url = payload.get("url", "")
    label, prob, reasons = predict(text, url)[:3]  # your function returns (label, prob, reasons[,...])
    # If your predict() already returns a snapshot as 4th item, adjust accordingly.
    snapshot = predict(text, url)[3] if len(predict(text, url)) > 3 else {}
    return {"label": label, "probability": float(prob), "reasons": reasons, "feature_snapshot": snapshot}

# ---------- NEW: async deep pipeline ----------
@app.post("/predict-deep")
def predict_deep(payload: dict):
    """
    (1) Return fast result immediately
    (2) Enqueue a deep job and give client a job_id to poll
    (3) If cached deep result exists, fast-path by returning job_id that is already 'done'
    """
    from deepchecks import cache_key_for_url
    text = payload.get("text", "")
    url = payload.get("url", "")

    # Fast result
    label, prob, reasons = predict(text, url)[:3]
    snapshot = predict(text, url)[3] if len(predict(text, url)) > 3 else {}
    fast = {"label": label, "probability": float(prob), "reasons": reasons, "feature_snapshot": snapshot}

    # Cache check
    key = cache_key_for_url(url)
    cached = r.get(key)
    if cached:
        # fabricate a job_id-like response for convenience
        jid = f"cached:{int(time.time())}"
        return {"job_id": jid, "fast_result": fast, "cached_deep_result": json.loads(cached)}

    # Enqueue real job
    job = q.enqueue("deepchecks.deep_checks", url, job_timeout=60)
    return {"job_id": job.get_id(), "fast_result": fast}

@app.get("/result/{job_id}")
def get_result(job_id: str):
    """
    Polling endpoint. When job finishes, return deep_result and also write it into cache with TTL.
    """
    if job_id.startswith("cached:"):
        return {"status": "done", "deep_result": None, "note": "Client received cached_deep_result in /predict-deep"}

    try:
        job = Job.fetch(job_id, connection=r)
    except Exception:
        return {"status": "not_found"}

    if not job.is_finished:
        return {"status": job.get_status()}

    # Cache completed results (24h)
    from deepchecks import cache_key_for_url
    url = job.args[0] if job.args else ""
    key = cache_key_for_url(url)
    try:
        r.setex(key, 24*3600, json.dumps(job.result))
    except Exception:
        pass

    return {"status": "done", "deep_result": job.result}
