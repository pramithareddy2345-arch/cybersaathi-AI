from flask import Flask, render_template, request, jsonify, session, redirect, url_for, render_template_string
import sqlite3
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DATABASE = "cybersaathi.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    connection = get_db()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE,
            complaint_type TEXT,
            description TEXT,
            incident_date TEXT,
            created_at TEXT
        )
    """)
    connection.commit()
    connection.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "service": "CyberSaathi API",
        "status": "ok"
    }
        )

@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "status": "Invalid URL",
            "message": "Please enter a valid URL."
        }), 400

    result = scan_url(url)
    return jsonify(result)
    

@app.route("/api/scam-check", methods=["POST"])
def scam_check():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "Please enter a message"}), 400

    keywords = [
        "urgent", "otp", "password", "bank account",
        "send money", "prize", "winner", "click here",
        "verify account", "limited time"
    ]

    found = [word for word in keywords if word in message.lower()]

    return jsonify({
        "warning_signs": found,
        "message": (
            "This message contains common scam warning signs. Verify it independently."
            if found else
            "No common scam keywords detected. Still be careful with unknown messages."
        )
    })


@app.route("/api/tips")
def tips():
    return jsonify({
        "tips": [
            "Never share your OTP, PIN or password.",
            "Avoid clicking unknown links.",
            "Use strong and unique passwords.",
            "Enable two-factor authentication.",
            "Keep your phone and apps updated.",
            "Verify payment requests before sending money.",
            "Use official websites for online services."
        ]
    })


@app.route("/api/assistant", methods=["POST"])
def assistant():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "").strip().lower()

    if not question:
        return jsonify({"error": "Please enter a question"}), 400

    if any(word in question for word in ["phishing", "fake link"]):
        answer = "Phishing is an attempt to trick people into revealing personal information. Check website addresses and avoid unknown links."

    elif any(word in question for word in ["otp", "password"]):
        answer = "Never share your OTP or password with anyone. Use unique passwords and enable two-factor authentication."

    elif any(word in question for word in ["fraud", "scam", "money"]):
        answer = "Be careful with unexpected payment requests. In India, report financial cyber fraud through the official portal or call 1930."

    elif "social media" in question:
        answer = "Use privacy settings, avoid unknown links and never share sensitive personal information publicly."

    else:
        answer = "Stay alert online. Never share OTPs or passwords, verify suspicious messages independently and use official websites. Ask me about phishing, passwords, online fraud or social media safety."

    return jsonify({"answer": answer})


@app.route("/api/complaints", methods=["POST"])
def submit_complaint():
    data = request.get_json(silent=True) or {}

    complaint_type = data.get("type", "").strip()
    description = data.get("description", "").strip()
    incident_date = data.get("date", "").strip()

    if not complaint_type or not description:
        return jsonify({"error": "Complaint type and description are required"}), 400

    reference = "CS-" + uuid.uuid4().hex[:8].upper()

    connection = get_db()
    connection.execute("""
        INSERT INTO complaints
        (reference, complaint_type, description, incident_date, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        reference,
        complaint_type,
        description,
        incident_date,
        datetime.now().isoformat()
    ))
    connection.commit()
    connection.close()

    return jsonify({
        "message": "Complaint summary saved in the CyberSaathi demo database.",
        "reference": reference,
        "official_portal": "https://cybercrime.gov.in/"
    })


@app.route("/api/complaints/<reference>")
def track_complaint(reference):
    connection = get_db()
    complaint = connection.execute(
        "SELECT reference, complaint_type, incident_date, created_at FROM complaints WHERE reference = ?",
        (reference,)
    ).fetchone()
    connection.close()

    if complaint is None:
        return jsonify({"error": "Reference not found"}), 404

    return jsonify(dict(complaint))


create_database()

# URL SCANNER API

def scan_url(url):
    import re
    from urllib.parse import urlparse

    url = url.strip()

    if not url or any(char.isspace() for char in url):
        return {
            "status": "Invalid URL",
            "message": "Please enter a valid URL."
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # Validate hostname
        if (
            not hostname
            or "." not in hostname
            or not re.fullmatch(r"[a-z0-9.-]+", hostname)
            or ".." in hostname
            or hostname.startswith(".")
            or hostname.endswith(".")
        ):
            return {
                "status": "Invalid URL",
                "message": "The URL format is invalid."
            }

        # Reject URLs containing embedded login credentials
        if parsed.username or parsed.password:
            return {
                "status": "Potential Warning Signs Found",
                "message": "This URL contains embedded login credentials. Check it carefully."
            }

        # Check for suspicious domain patterns
        if hostname.startswith("xn--") or ".xn--" in hostname:
            return {
                "status": "Potential Warning Signs Found",
                "message": "This domain uses encoded characters. Verify it carefully."
            }

        trusted_domains = [
            "youtube.com",
            "google.com",
            "microsoft.com",
            "wikipedia.org"
        ]

        recognized = any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in trusted_domains
        )

        if parsed.scheme != "https":
            return {
                "status": "Potential Warning Signs Found",
                "message": "This URL does not use HTTPS encryption."
            }

        if not recognized:
            return {
                "status": "Potential Warning Signs Found",
                "message": "This domain is not in the scanner's recognized-domain list. Verify it before visiting."
            }

        return {
            "status": "No Basic Warning Signs Detected",
            "message": "No basic warning signs detected. This does not prove the website is safe."
        }

    except ValueError:
        return {
            "status": "Invalid URL",
            "message": "Unable to process this URL."
        }
        
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
