from flask import Flask, request, jsonify
from scanners.admin_panel_scanner import check_admin_panels
from scanners.csrf_scanner import test_csrf
from scanners.directory_traversal import check_directory_traversal
from scanners.sqli_scanner import test_sql_injection
from scanners.xss_scanner import test_xss
from scanners.server_misconfig_scanner import test_server_misconfig
from scanners.open_redirect import check_open_redirect
from scanners.cmdi_scanner import test_cmd_injection
from scanners.network_scanner import test_network_ports

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    url = data.get("url")
    modules = data.get("modules", [])

    results = {}

    if "admin" in modules:
        results["Admin Panel"] = check_admin_panels(url)
    if "csrf" in modules:
        results["CSRF"] = test_csrf(url)
    if "traversal" in modules:
        results["Directory Traversal"] = check_directory_traversal(url)
    if "sqli" in modules:
        results["SQLi"] = test_sql_injection(url)
    if "xss" in modules:
        results["XSS"] = test_xss(url)
    if "server" in modules:
        results["Server Misconfig"] = test_server_misconfig(url)
    if "redirect" in modules:
        results["Open Redirect"] = check_open_redirect(url)
    if "cmd" in modules:
        results["CMDi"] = test_cmd_injection(url)
    if "ports" in modules:
        results["Network Ports"] = test_network_ports(url)

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
