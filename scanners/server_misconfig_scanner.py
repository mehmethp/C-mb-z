import requests

SENSITIVE_PATHS = ["/.git/", "/phpinfo.php", "/.env", "/server-status", "/.htaccess", "/config.php", "/backup.zip"]

def test_server_misconfig(url):
    results = []
    try:
        headers = requests.get(url, timeout=5).headers
        server_info = headers.get("Server", "") + headers.get("X-Powered-By", "")
        if server_info:
            results.append(f"⚠️ Sunucu bilgisi ifşa edilmiş: {server_info}")

        for ep in SENSITIVE_PATHS:
            test_url = url.rstrip("/") + ep
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                results.append(f"⚠️ Tehlikeli dosya veya yapılandırma erişilebilir: {test_url}")
    except requests.RequestException:
        pass

    return results
