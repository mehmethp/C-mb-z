import requests
from bs4 import BeautifulSoup

def test_csrf(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            if "csrf_token" not in str(form):
                vulnerabilities.append("⚠️ CSRF Token Eksik: Bir formda CSRF koruması yok!")
    
    except:
        pass
    
    return vulnerabilities
