import requests

xss_payloads = ['<script>alert("XSS")</script>', '" onerror="alert(1)"']

def test_xss(url):
    vulnerabilities = []
    
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                vulnerabilities.append(f"⚠️ XSS Açığı Tespit Edildi: {test_url}")
        except:
            pass
    
    return vulnerabilities
