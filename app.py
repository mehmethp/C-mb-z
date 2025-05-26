import base64
import os
import streamlit as st
import time
import socket
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
from scanners.weak_password_scanner import test_weak_passwords
from scanners.network_scanner import test_network_ports

# ✅ Sayfa ayarı
st.set_page_config(page_title="Cımbız", page_icon="🕵️‍♂️", layout="centered")

# ✅ Logo tam ortada
st.markdown(
    """
    <div style='text-align: center;'>
        <img src='assets/cimbiz_logo.png width='200'>
    </div>
    """,
    unsafe_allow_html=True
)

# ✅ Alt başlık
st.markdown(
    "<h4 style='text-align: center; margin-top: -10px;'>GUI Web Güvenlik Açığı Tarayıcısı</h4>",
    unsafe_allow_html=True
)
st.write("---")


# 🔧 Tarama Ayarları
profile = st.selectbox("🛡️ Tarama Profili", ["High-Risk", "Critical-Risk", "DeepScan"])
crawl_depth = st.slider("🌐 Tarama Derinliği (yakında aktif)", 1, 5, 2)
threaded = st.checkbox("⚡ Çoklu iş parçacığı ile tarama (yakında)", value=False)
no_prompt = st.checkbox("🤖 Otomasyon Modu (no-prompt)", value=True)

# 🧩 Modül Seçimi
st.markdown("### 🔧 Dahil Edilecek Testler")
selected_tests = st.multiselect(
    "Hangi modülleri taramak istersiniz?",
    [
        "SQL Injection", "XSS", "CSRF", "Security Headers", "Admin Panel",
        "Directory Traversal", "Open Redirect", "Command Injection",
        "Server Misconfiguration", "Weak Passwords", "Network Vulnerabilities"
    ],
    default=[
        "SQL Injection", "XSS", "CSRF", "Security Headers", "Admin Panel",
        "Directory Traversal", "Open Redirect"
    ]
)

# 🌐 Hedef URL
url = st.text_input("🌐 Test etmek istediğiniz web sitesi URL’sini girin", placeholder="Örn: http://example.com")

# ▶️ Başlat Butonu
if st.button("🚀 Taramayı Başlat"):
    if not url.strip():
        st.error("❗ Lütfen geçerli bir URL girin.")
    else:
        st.info(f"🧪 Seçilen Profil: {profile}")
        st.info(f"📋 Seçilen Modüller: {', '.join(selected_tests)}")
        st.info(f"🌐 Tarama Derinliği: {crawl_depth}")

        with st.spinner("🔍 Taranıyor..."):
            time.sleep(1)
            results_dict = {}

            try:
                if "SQL Injection" in selected_tests:
                    results_dict["SQL Injection"] = test_sql_injection(url)
                if "XSS" in selected_tests:
                    results_dict["XSS"] = test_xss(url)
                if "CSRF" in selected_tests:
                    results_dict["CSRF"] = test_csrf(url)
                if "Security Headers" in selected_tests:
                    results_dict["Güvenlik Başlıkları"] = check_security_headers(url)
                if "Admin Panel" in selected_tests:
                    results_dict["Admin Panel"] = check_admin_panels(url)
                if "Directory Traversal" in selected_tests:
                    results_dict["Directory Traversal"] = check_directory_traversal(url)
                if "Open Redirect" in selected_tests:
                    results_dict["Open Redirect"] = check_open_redirect(url)
                if "Command Injection" in selected_tests:
                    results_dict["Command Injection"] = test_cmd_injection(url)
                if "Server Misconfiguration" in selected_tests:
                    results_dict["Server Misconfiguration"] = test_server_misconfig(url)
                if "Weak Passwords" in selected_tests:
                    results_dict["Weak Passwords"] = test_weak_passwords(url)
                if "Network Vulnerabilities" in selected_tests:
                    parsed = urlparse(url)
                    domain = parsed.netloc or parsed.path
                    results_dict["Network Vulnerabilities"] = test_network_ports(domain)

                for module, results in results_dict.items():
                    with st.expander(f"🔍 {module}"):
                        if results:
                            for r in results:
                                st.warning(r)
                        else:
                            st.success("✅ Açık bulunamadı.")

                report_file, report_content = save_report(url, results_dict)
                st.success(f"📄 Rapor oluşturuldu: `{report_file}`")
                st.download_button(
                    label="📥 Raporu İndir",
                    data=report_content,
                    file_name=report_file,
                    mime="text/plain"
                )

            except Exception as e:
                st.error(f"❌ Hata oluştu: {str(e)}")
