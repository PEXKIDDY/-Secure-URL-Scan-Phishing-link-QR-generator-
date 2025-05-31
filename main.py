from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from jinja2 import Template
import re
import socket
import tldextract
import requests
import whois
import ssl
import OpenSSL
import uvicorn
import base64
import qrcode
import io
import os

app = FastAPI()

# === Replace with your Google Safe Browsing API key here ===
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>🛡️ Phishing & Security Toolkit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom colors */
        .bg-blue-custom { background-color: #2563eb; }
        .bg-yellow-custom { background-color: #fbbf24; }
        .bg-red-custom { background-color: #dc2626; }
        .bg-orange-custom { background-color: #f97316; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen p-6 font-sans">
    <h1 class="text-5xl font-extrabold text-center mb-12 bg-blue-custom text-white py-6 rounded-lg shadow-lg">🛡️ Phishing & Security Toolkit</h1>

    <form method="post" class="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-12">

        <!-- URL Scanner Section -->
        <div class="bg-white border border-gray-300 p-8 rounded-xl shadow-lg">
            <h2 class="text-3xl font-semibold mb-6 text-blue-700">🔍 Scan URLs</h2>
            <textarea name="urls" rows="10" class="w-full border border-gray-300 p-4 rounded focus:outline-none focus:ring-4 focus:ring-blue-300" placeholder="Enter one or more URLs (one per line)">{{ urls }}</textarea>
            <button type="submit" class="mt-6 w-full bg-blue-custom hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded transition duration-300">Scan</button>
        </div>

        <!-- Results Section -->
        <div class="bg-white border border-gray-300 p-8 rounded-xl shadow-lg max-h-[700px] overflow-y-auto">
            <h2 class="text-3xl font-semibold mb-6 text-yellow-600">📊 Scan Results</h2>
            {% if results %}
                {% for result in results %}
                <div class="mb-6 p-5 rounded-lg border
                    {% if result.invalid %}
                        border-red-custom bg-red-50
                    {% elif result.phishing %}
                        border-orange-custom bg-orange-50
                    {% elif result.safe %}
                        border-green-400 bg-green-50
                    {% else %}
                        border-yellow-custom bg-yellow-50
                    {% endif %}
                ">
                    <p><strong>🔗 URL:</strong> <a href="{{ result.url }}" target="_blank" class="text-blue-600 underline break-all">{{ result.url }}</a></p>
                    <p><strong>Status:</strong> 
                        {% if result.invalid %}
                            <span class="text-red-custom font-semibold">Invalid URL</span>
                        {% elif result.active %}
                            <span class="text-green-600 font-semibold">Active</span>
                        {% else %}
                            <span class="text-yellow-600 font-semibold">Inactive</span>
                        {% endif %}
                    </p>
                    <p><strong>Domain:</strong> {{ result.domain }}</p>
                    <p><strong>Registered:</strong> {{ result.registered }}</p>
                    <p><strong>IP:</strong> {{ result.ip }}</p>
                    <p><strong>Phishing Suspected:</strong> <span class="{% if result.phishing %}text-orange-custom{% else %}text-green-600{% endif %} font-semibold">{{ "Yes" if result.phishing else "No" }}</span></p>
                    <p><strong>Google Safe Browsing:</strong> <span class="{% if result.gsbl_status == "SAFE" %}text-green-600{% else %}text-red-custom{% endif %} font-semibold">{{ result.gsbl_status }}</span></p>
                    <p><strong>CA (Issuer):</strong> {{ result.ca }}</p>
                    <p><strong>Signature Hash Algorithm:</strong> {{ result.sig_hash_algo }}</p>
                    {% if result.qr_code %}
                    <div class="mt-4">
                        <img src="data:image/png;base64,{{ result.qr_code }}" alt="QR code" class="mx-auto rounded-lg border border-gray-300" />
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p class="text-gray-600 italic">No URLs scanned yet.</p>
            {% endif %}
        </div>

    </form>

    <!-- Phishing Link Generator Section -->
    <form method="post" class="max-w-4xl mx-auto mt-16 bg-white border border-gray-300 p-8 rounded-xl shadow-lg">
        <h2 class="text-3xl font-semibold mb-6 text-red-600">🎯 Phishing Link Generator</h2>
        <label class="block mb-3 font-medium text-gray-700">Target URL:</label>
        <input type="text" name="target_url" value="{{ target_url }}" class="w-full border border-gray-300 p-4 rounded focus:outline-none focus:ring-4 focus:ring-red-300" placeholder="https://originalsite.com/login" />
        <button type="submit" name="generate" value="1" class="mt-6 w-full bg-red-custom hover:bg-red-700 text-white font-semibold py-3 px-6 rounded transition duration-300">Generate Phishing Link</button>

        {% if phishing_link %}
        <div class="mt-6 bg-gray-100 p-5 rounded border border-gray-400 text-center">
            <strong>Generated Phishing Link:</strong><br/>
            <a href="{{ phishing_link }}" target="_blank" class="text-blue-600 underline break-all">{{ phishing_link }}</a>
            <div class="mt-4">
                <img src="data:image/png;base64,{{ phishing_qr }}" alt="QR code" class="mx-auto rounded-lg border border-gray-300" />
            </div>
        </div>
        {% endif %}
    </form>
</body>
</html>
""")

def get_cert_info(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert_bin = s.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
            ca = ", ".join(f"{name.decode()}={value.decode()}" for name, value in x509.get_issuer().get_components())
            algo = x509.get_signature_algorithm().decode()
            return ca, algo
    except Exception:
        return "N/A", "N/A"

def check_google_safe_browsing(url: str) -> str:
    """Returns 'SAFE' or 'PHISHING'"""
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(api_url, json=body, timeout=5)
        if resp.status_code == 200 and resp.json().get("matches"):
            return "PHISHING"
        else:
            return "SAFE"
    except Exception:
        return "UNKNOWN"

def generate_qr_code(data: str) -> str:
    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

@app.get("/", response_class=HTMLResponse)
def form():
    return HTML_TEMPLATE.render(urls="", results=[], target_url="", phishing_link="", phishing_qr="")

@app.post("/", response_class=HTMLResponse)
async def handle(
    request: Request,
    urls: str = Form(default=""),
    target_url: str = Form(default=""),
    generate: str = Form(default="")
):
    results = []
    phishing_link = ""
    phishing_qr = ""
    headers = {"User-Agent": "Mozilla/5.0"}

    # Generate phishing link & QR
    if generate == "1" and target_url.strip():
        try:
            encoded = base64.urlsafe_b64encode(target_url.encode()).decode()
            phishing_link = f"https://fake-login.com/redirect?site={encoded}"
            phishing_qr = generate_qr_code(phishing_link)
        except Exception:
            phishing_link = "Error generating phishing link"

    # Process URL scanning
    url_list = [u.strip() for u in urls.strip().splitlines() if u.strip()]
    for url in url_list:
        result = {
            "url": url,
            "invalid": False,
            "safe": False,
            "active": False,
            "domain": "N/A",
            "registered": "N/A",
            "ip": "N/A",
            "phishing": False,
            "ca": "N/A",
            "sig_hash_algo": "N/A",
            "gsbl_status": "UNKNOWN",
            "qr_code": None,
        }

        if not re.match(r'https?://', url):
            result["invalid"] = True
            results.append(result)
            continue

        try:
            ext = tldextract.extract(url)
            if not ext.suffix:
                # Invalid domain if no suffix (like .com, .net)
                result["invalid"] = True
                results.append(result)
                continue

            domain = f"{ext.domain}.{ext.suffix}"
            result["domain"] = domain

            # WHOIS info
            try:
                whois_info = whois.whois(domain)
                if isinstance(whois_info.creation_date, list):
                    whois_info.creation_date = whois_info.creation_date[0]
                if whois_info.creation_date:
                    result["registered"] = str(whois_info.creation_date.date())
            except Exception:
                result["registered"] = "N/A"

            # Resolve IP
            try:
                result["ip"] = socket.gethostbyname(domain)
            except Exception:
                result["ip"] = "N/A"

            # Check URL active
            try:
                r = requests.get(url, timeout=7, headers=headers, allow_redirects=True)
                result["active"] = r.status_code < 400
            except Exception:
                result["active"] = False

            # Check phishing keywords (simple heuristic)
            phishing_keywords = ["login", "verify", "update", "confirm", "secure", "account", "bank", "password"]
            if any(k in url.lower() for k in phishing_keywords):
                result["phishing"] = True

            # Google Safe Browsing check
            gsbl_status = check_google_safe_browsing(url)
            result["gsbl_status"] = gsbl_status
            if gsbl_status == "PHISHING":
                result["phishing"] = True

            # Get SSL cert info if https
            if url.lower().startswith("https://"):
                try:
                    ca, algo = get_cert_info(domain)
                    result["ca"] = ca
                    result["sig_hash_algo"] = algo
                except Exception:
                    result["ca"] = "N/A"
                    result["sig_hash_algo"] = "N/A"

            # Generate QR code for URL
            try:
                result["qr_code"] = generate_qr_code(url)
            except Exception:
                result["qr_code"] = None

            result["safe"] = not result["phishing"] and result["active"] and gsbl_status == "SAFE"

        except Exception:
            result["invalid"] = True

        results.append(result)

    return HTML_TEMPLATE.render(
        urls=urls,
        results=results,
        target_url=target_url,
        phishing_link=phishing_link,
        phishing_qr=phishing_qr
    )

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
