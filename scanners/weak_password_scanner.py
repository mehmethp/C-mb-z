import requests

def test_weak_passwords(url):
    # Bu örnek çok basit HTML login formu için geçerlidir.
    user_list = ["admin", "test"]
    pass_list = ["admin", "1234", "password", "test"]
    results = []

    for user in user_list:
        for pwd in pass_list:
            try:
                data = {"username": user, "password": pwd}
                r = requests.post(url, data=data, timeout=5)

                if "Welcome" in r.text or r.status_code == 302:
                    results.append(f"Zayıf parola ile erişim sağlanabilir: {user}:{pwd}")
            except:
                continue

    return results
