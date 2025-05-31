# 🛡️ Secure URL Scan & Phishing link , QR GENERATOR 

This application has developed a comprehensive URL scanning and phishing detection web application integrating Google Safe Browsing API, WHOIS lookup, SSL certificate validation, and QR code generation. Designed a professional, multi-colored UI to enhance user experience while providing real-time security insights on URLs and generating encoded phishing simulation links.

---

## 🚀 Features

- ✅ URL Validity Check
- 🔍 Phishing Detection (basic heuristics + Google Safe Browsing)
- 🌐 WHOIS Domain Info
- 🔐 SSL Certificate Inspector
- 📌 IP Address Resolution
- 🧪 Phishing Simulation Link Generator
- 📷 QR Code Generator for URLs
- 🎨 Beautiful TailwindCSS-based UI

---

## 🧰 Technologies Used

- FastAPI
- Jinja2 (for templating)
- Requests
- Whois
- OpenSSL / SSL
- Google Safe Browsing API
- Tailwind CSS
- qrcode (Python module)
- Uvicorn

---

## 🖥️ Installation

Make sure you have **Python 3.8+** installed.

🔐 Google Safe Browsing API Setup
Go to Google Cloud Console.

Create a project and enable Safe Browsing API.

Generate an API key.

Add this key to your code:
GOOGLE_API_KEY = "YOUR_API_KEY"


### 🔧 Clone the Repository

```bash
git clone https://github.com/PEXKIDDY/secure-scan-pro.git
cd secure-scan-pro



