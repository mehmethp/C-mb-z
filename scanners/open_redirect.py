import requests

payloads = [
    "http://evil.com",
    "//evil.com",
    "/\\evil.com"
]

def check_open_redirect(url):
    vulnerabilities = []
    
    # URL'ye payload ekleyelim
    for payload in payloads:
        if "?" in url:
            test_url = url + "&url=" + payload
        else:
            test_url = url + "?url=" + payload
        
        try:
            response = requests.get(test_url, allow_redirects=False, timeout=5)
            if "Location" in response.headers:
                location = response.headers["Location"]
                if "evil.com" in location:
                    vulnerabilities.append(f"⚠️ Open Redirect Açığı Tespit Edildi: {test_url}")
        except:
            continue
    
    return vulnerabilities
