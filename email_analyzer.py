import re
import requests
from urllib.parse import urlparse

def analyze_email_content(content):
    results = {}

    # Count suspicious words
    keywords = ['verify', 'urgent', 'password', 'account', 'click here', 'login']
    hits = sum(word in content.lower() for word in keywords)
    results['keyword_hits'] = hits

    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', content)
    results['urls_found'] = urls

    # Check if any URL looks suspicious
    suspicious_urls = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.netloc.endswith(('.com', '.org', '.edu', '.gov')):
            suspicious_urls.append(url)
        elif parsed.scheme != 'https':
            suspicious_urls.append(url)
    results['suspicious_urls'] = suspicious_urls

    return results

if __name__ == "__main__":
    test_email = """
    Dear user, verify your account immediately.
    Click here: http://secure-login-verify.ru
    """
    print(analyze_email_content(test_email))
