import requests

REDIRECT_PAYLOADS = [
    "//google.com", "https://attacker.site", "http://malicious.com",
    "///example.com", "//127.0.0.1:8080", "%2f%2fevil.com"
]

def check_open_redirect(url):
    results = []
    for payload in REDIRECT_PAYLOADS:
        test_url = f"{url}?next={payload}"
        try:
            r = requests.get(test_url, allow_redirects=False, timeout=5)
            location = r.headers.get("Location", "")
            if any(p in location for p in REDIRECT_PAYLOADS):
                results.append(f"⚠️ Açık yönlendirme tespit edildi: {test_url} -> {location}")
        except requests.RequestException:
            continue
    return results
