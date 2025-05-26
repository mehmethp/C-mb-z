import requests

admin_paths = ["/admin", "/login", "/wp-admin", "/administrator", "/panel"]

def check_admin_panels(url):
    vulnerabilities = []
    
    for path in admin_paths:
        admin_url = url + path
        try:
            response = requests.get(admin_url)
            if response.status_code == 200:
                vulnerabilities.append(f"⚠️ Açık Admin Paneli Bulundu: {admin_url}")
        except:
            pass
    
    return vulnerabilities
