# deepchecks.py
import time, socket, ssl, json, hashlib
from datetime import datetime
from urllib.parse import urlparse
import requests
import dns.resolver

# optional WHOIS (can be flaky for some TLDs; always guard with try/except)
try:
    import whois as pywhois
except Exception:
    pywhois = None

USER_AGENT = "PhishDetector/0.2 (+https://example.invalid)"
TIMEOUT = 12
MAX_REDIRECTS = 8

PRIVATE_NETS = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.", "127.", "0.0.0.0")

def _is_private_host(host: str) -> bool:
    # Only a quick guard: we resolve and reject obvious RFC1918/loopback hits
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        return any(a.startswith(PRIVATE_NETS) for a in addrs)
    except Exception:
        return False

def _whois_age_days(domain: str):
    if not pywhois:
        return None
    try:
        w = pywhois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not isinstance(cd, datetime):
            return None
        return (datetime.utcnow() - cd).days
    except Exception:
        return None

def _tls_info(host: str):
    out = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # issuer
        issuer = cert.get("issuer")
        if issuer and isinstance(issuer, tuple) and issuer:
            # issuer is list/tuple of ( (('commonName','R3'),), ... )
            out["issuer"] = ",".join("=".join(p) for r in issuer for p in r)
        # expiry
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            out["days_to_expiry"] = (exp - datetime.utcnow()).days
    except Exception:
        pass
    return out

def _dns_records(domain: str):
    data = {"a": [], "mx": []}
    try:
        a = dns.resolver.resolve(domain, "A", lifetime=5)
        data["a"] = [str(r) for r in a]
    except Exception:
        pass
    try:
        mx = dns.resolver.resolve(domain, "MX", lifetime=5)
        data["mx"] = [str(r.exchange).rstrip(".") for r in mx]
    except Exception:
        pass
    return data

def deep_checks(url: str):
    """
    Heavy-ish checks that we DON'T do inline in the API request.
    Always return a JSON-serializable dict.
    """
    start = time.time()
    out = {"url": url, "started_at": start, "risk_flags": []}

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        out["host"] = host

        if host and _is_private_host(host):
            out["error"] = "Refusing to scan private/internal hosts"
            out["risk_flags"].append("private_host")
            out["finished_at"] = time.time()
            return out

        # 1) Follow redirects (no JS)
        sess = requests.Session()
        sess.headers.update({"User-Agent": USER_AGENT})
        resp = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
        chain = [h.headers.get("Location") for h in resp.history] if resp.history else []
        out["redirect_chain"] = [url] + [c for c in chain if c] + [resp.url]
        out["final_url"] = resp.url
        out["http"] = {
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "length": len(resp.content),
        }

        # 2) Simple HTML intel (no DOM exec)
        html = ""
        if "html" in (out["http"]["content_type"] or "") and isinstance(resp.text, str):
            html = resp.text.lower()
            pwd_inputs = html.count('type="password"') + html.count("type='password'")
            out["forms"] = {
                "password_inputs": int(pwd_inputs),
                "total_forms": html.count("<form"),
                "suspicious_words": [w for w in ["verify", "account", "login", "password"] if w in html],
            }
            if pwd_inputs > 0:
                out["risk_flags"].append("has_password_form")

        # 3) DNS
        domain = urlparse(out["final_url"]).hostname or host
        out["domain"] = {"name": domain}
        out["domain"].update(_dns_records(domain))

        # 4) TLS (only if https)
        if out["final_url"].startswith("https://") and domain:
            tls = _tls_info(domain)
            if tls:
                out["tls"] = tls

        # 5) WHOIS age (best-effort)
        out["domain"]["whois_age_days"] = _whois_age_days(domain)

        # Example risk score (toy)
        score = 0.5
        if domain and domain.split(".")[-1] in {"ru", "cn", "tk", "ml", "zip"}:
            out["risk_flags"].append("suspicious_tld")
            score += 0.15
        if out.get("forms", {}).get("password_inputs"):
            score += 0.2
        if out["domain"].get("whois_age_days") is not None and out["domain"]["whois_age_days"] < 30:
            out["risk_flags"].append("young_domain")
            score += 0.15

        out["risk_score"] = round(min(score, 0.99), 3)
    except Exception as e:
        out["error"] = str(e)
    finally:
        out["finished_at"] = time.time()

    return out

def cache_key_for_url(url: str) -> str:
    return "deep:" + hashlib.sha256(url.encode("utf-8")).hexdigest()
