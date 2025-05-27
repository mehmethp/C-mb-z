import requests
from bs4 import BeautifulSoup

TOKEN_NAMES = ["csrf", "csrf_token", "_csrf", "authenticity_token", "csrfmiddlewaretoken"]

def test_csrf(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for i, form in enumerate(forms, start=1):
            inputs = form.find_all("input")
            has_token = any(any(token in (inp.get("name") or "").lower() for token in TOKEN_NAMES) for inp in inputs)
            if not has_token:
                vulnerabilities.append(f"⚠️ CSRF Token Eksik: {i}. formda koruma bulunamadı.")
    except requests.RequestException:
        pass

    return vulnerabilities
