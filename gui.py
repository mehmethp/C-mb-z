import base64
import os
import streamlit as st
import time
from urllib.parse import urlparse
from save_report import save_report

from scanners.sqli_scanner import test_sql_injection
from scanners.xss_scanner import test_xss
from scanners.csrf_scanner import test_csrf
from scanners.security_headers import check_security_headers
from scanners.admin_panel_scanner import check_admin_panels
from scanners.directory_traversal import check_directory_traversal
from scanners.open_redirect import check_open_redirect
from scanners.cmdi_scanner import test_cmd_injection
from scanners.server_misconfig_scanner import test_server_misconfig
from scanners.network_scanner import test_network_ports

col1, col2, col3 = st.columns([1, 2, 1])  
with col2:
    st.image("assets/cimbiz_logo.png", width=300)
st.markdown(
    "<h4 style='text-align: center; margin-top: -10px;'>GUI Web Güvenlik Açığı Tarayıcısı</h4>",
    unsafe_allow_html=True
)
st.markdown("Basit ve etkili zafiyet tarayıcı. Created by <a href='https://www.linkedin.com/in/mehmetcanaydogan/'>Mehmetcan Aydoğan</a>.", unsafe_allow_html=True)
st.write("---")

user_mode = st.selectbox("👤 Kullanıcı Modu Seçin", ["Temel Kullanıcı", "Uzman Kullanıcı", "I'M the Boss"])

st.write("---")
selected_tests = st.multiselect(
    "🔍 Tarama Yapılacak Modüller",
    ["Admin Panel", "CSRF", "Directory Traversal", "SQLi", "XSS",
     "Server Misconfig", "Open Redirect", "CMDi", "Network Ports"],
    default=["Admin Panel", "CSRF", "SQLi", "XSS"]
)
url = st.text_input("🌐 URL Girin (http://...):")

OWASP_LINKS = {
    "SQLi": ("https://owasp.org/Top10/A01_2021-Broken_Access_Control/", ["CWE-89", "CWE-564"]),
    "XSS": ("https://owasp.org/Top10/A03_2021-Injection/", ["CWE-79"]),
    "CSRF": ("https://owasp.org/www-community/attacks/csrf", ["CWE-352"]),
    "Directory Traversal": ("https://owasp.org/www-community/attacks/Path_Traversal", ["CWE-22"]),
    "Open Redirect": ("https://owasp.org/www-community/attacks/Redirect_Based_Attacks", ["CWE-601"]),
    "CMDi": ("https://owasp.org/www-community/attacks/Command_Injection", ["CWE-77"]),
    "Admin Panel": ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces", ["CWE-285"]),
    "Server Misconfig": ("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", ["CWE-933"]),
    "Network Ports": ("https://owasp.org/www-project-internet-of-things/", ["CWE-200"]),
}

OWASP_GUIDES = {
    "SQLi": "SQL Injection: Veritabanına zararlı sorguların enjekte edilmesi. https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "XSS": "XSS: Zararlı JavaScript kodlarının enjekte edilmesi. https://owasp.org/Top10/A03_2021-Injection/",
    "CSRF": "CSRF: Kullanıcının haberi olmadan işlem yaptırma. https://owasp.org/www-community/attacks/csrf",
    "Directory Traversal": "Directory Traversal: Dizin dışına çıkarak sistem dosyalarına erişim. https://owasp.org/www-community/attacks/Path_Traversal",
    "Open Redirect": "Open Redirect: Kullanıcıyı zararlı bir siteye yönlendirme. https://owasp.org/www-community/attacks/Redirect_Based_Attacks",
    "CMDi": "Command Injection: Komut satırı komutlarının sisteme enjekte edilmesi. https://owasp.org/www-community/attacks/Command_Injection",
    "Admin Panel": "Admin Panel: Yetkisiz erişime açık yönetici panelleri. https://owasp.org/www-project-testing/",
    "Server Misconfig": "Server Misconfiguration: Açık dosyalar ve varsayılan yapılandırmalar. https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "Network Ports": "Network Ports: Gereksiz açık portlar. https://owasp.org/www-project-internet-of-things/"
}

if st.button("🚀 Taramayı Başlat"):
    if not url.strip():
        st.error("❗ Lütfen geçerli bir URL girin.")
    else:
        st.info(f"Mod: {user_mode}")
        st.info(f"Seçilen Modüller: {', '.join(selected_tests)}")
        with st.spinner("Tarama yapılıyor..."):
            time.sleep(1)
            results = {}

            try:
                if "Admin Panel" in selected_tests:
                    results["Admin Panel"] = check_admin_panels(url)
                if "CSRF" in selected_tests:
                    results["CSRF"] = test_csrf(url)
                if "Directory Traversal" in selected_tests:
                    results["Directory Traversal"] = check_directory_traversal(url)
                if "SQLi" in selected_tests:
                    results["SQLi"] = test_sql_injection(url)
                if "XSS" in selected_tests:
                    results["XSS"] = test_xss(url)
                if "Server Misconfig" in selected_tests:
                    results["Server Misconfig"] = test_server_misconfig(url)
                if "Open Redirect" in selected_tests:
                    results["Open Redirect"] = check_open_redirect(url)
                if "CMDi" in selected_tests:
                    results["CMDi"] = test_cmd_injection(url)
                if "Network Ports" in selected_tests:
                    parsed = urlparse(url)
                    domain = parsed.netloc or parsed.path
                    results["Network Ports"] = test_network_ports(domain)

                for module, result in results.items():
                    with st.expander(f"📂 {module}"):
                        if result:
                            for r in result:
                                if user_mode == "Temel Kullanıcı":
                                    st.warning(r)
                                    explanation = OWASP_GUIDES.get(module, "")
                                    if explanation:
                                        st.info(explanation)
                                elif user_mode == "Uzman Kullanıcı":
                                    st.warning(r)
                                    _, cwes = OWASP_LINKS.get(module, ("", []))
                                    st.info(f"📌 Mapped CWEs: {', '.join(cwes)}")
                                else:  # I'M the Boss
                                    st.warning(r)
                        else:
                            st.success("✅ Açık bulunamadı.")

                report_file, report_text = save_report(url, results)
                st.success(f"📄 Rapor oluşturuldu: {report_file}")
                st.download_button("📥 Raporu İndir", data=report_text, file_name=report_file)
            except Exception as e:
                st.error(f"❌ Hata oluştu: {str(e)}")