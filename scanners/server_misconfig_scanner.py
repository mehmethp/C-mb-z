import requests

def test_server_misconfig(url):
    endpoints = ["/.git/", "/phpinfo.php", "/.env", "/server-status"]
    results = []

    try:
        headers = requests.get(url, timeout=5).headers
        for header in headers:
            if header.lower() in ["x-powered-by", "server"] and "apache" in headers[header].lower():
                results.append(f"Gizlenmemiş başlık: {header}: {headers[header]}")

        for ep in endpoints:
            resp = requests.get(url + ep, timeout=5)
            if resp.status_code == 200:
                results.append(f"Tehlikeli dosya veya yapılandırma erişilebilir: {url+ep}")

    except:
        pass

    return results
