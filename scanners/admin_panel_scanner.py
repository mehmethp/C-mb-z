import requests

COMMON_ADMIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/panel",
    "/adminpanel", "/wp-login.php", "/wp-admin", "/user/login"
]

def check_admin_panels(base_url):
    vulnerabilities = []
    base_url = base_url.rstrip("/")

    for path in COMMON_ADMIN_PATHS:
        test_url = base_url + path
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and ("login" in response.text.lower() or "password" in response.text.lower()):
                vulnerabilities.append(f"⚠️ Açık Admin Paneli Bulundu: {test_url}")
        except requests.RequestException:
            continue

    return vulnerabilities
