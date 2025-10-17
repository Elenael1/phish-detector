import csv
from phishing_detector import predict

with open("samples.txt","r",encoding="utf-8") as f:
    urls = [l.strip() for l in f if l.strip()]

with open("results.csv","w",newline="",encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["url","label","probability","reasons"])
    for u in urls:
        try:
            label, prob, reasons = predict("", u)
        except Exception as e:
            label, prob, reasons = "ERROR", 0.0, {"error": str(e)}
        w.writerow([u, label, f"{prob:.2f}", ";".join(f"{k}={v}" for k,v in reasons.items())])
print("Wrote results.csv")
