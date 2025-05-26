# Cımbız (Cımbız Web Vulnerability Scanner)
![cimbiz_logo](https://github.com/user-attachments/assets/145fd66d-d1d1-43f8-8062-8d8381e6ce4f)
🕵️‍♂️ **Cımbız** is a GUI-based web security vulnerability scanner built with Python and Streamlit. It helps security professionals and enthusiasts to scan websites for common vulnerabilities such as SQL Injection, XSS, CSRF, and more, providing an easy-to-use interface with customizable scanning modules.


---

## Features

* Scan for multiple common web vulnerabilities:

  * SQL Injection (SQLi)
  * Cross-Site Scripting (XSS)
  * Cross-Site Request Forgery (CSRF)
  * Security Headers
  * Admin Panel Detection
  * Directory Traversal
  * Open Redirect
  * Command Injection
  * Server Misconfiguration
  * Weak Passwords
  * Network Vulnerabilities (port scanning)
* Choose scanning profiles (High-Risk, Critical-Risk, DeepScan)
* Adjustable scan depth (feature coming soon)
* Support for selecting specific test modules
* Generates downloadable plain text vulnerability reports
* User-friendly Streamlit-based GUI

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/mehmethp/C-mb-z.git
cd C-mb-z
```

2. (Optional) Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run the Streamlit app:

```bash
streamlit run app.py
```

* Enter the target website URL.
* Select the scan profile and modules you want to include.
* Click **Start Scan**.
* View scan results in expandable sections.
* Download the generated vulnerability report.

---

## Project Structure

* `app.py` — Main Streamlit application with UI and scanning workflow.
* `scanners/` — Folder containing individual vulnerability scanner modules (e.g., SQLi, XSS, CSRF, etc.).
* `save_report.py` — Utility to save and generate scan reports.
* `assets/` — Contains logo and other static files.

---

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

If you want, I can also help you generate the `requirements.txt` file or write detailed usage instructions for each scanner module!
