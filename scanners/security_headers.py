import requests

def check_security_headers(url):
    security_headers = ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
    vulnerabilities = []
    
    try:
        response = requests.get(url, timeout=5)
        for header in security_headers:
            if header not in response.headers:
                vulnerabilities.append(f"⚠️ Güvenlik başlığı eksik: {header}")
    
    except:
        pass
    
    return vulnerabilities
