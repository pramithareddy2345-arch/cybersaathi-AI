from flask import Flask, render_template, request, jsonify
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
    })


@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL"}), 400

    suspicious_terms = [
        "login-verify", "free-prize", "account-suspended",
        "claim-reward", "password-reset"
    ]

    warnings = []

    if not url.startswith(("http://", "https://")):
        warnings.append("URL does not start with HTTP or HTTPS.")

    if any(term in url.lower() for term in suspicious_terms):
        warnings.append("URL contains wording commonly used in scams.")

    if "@" in url:
        warnings.append("URL contains an unusual @ character.")

    return jsonify({
        "status": "warning" if warnings else "review",
        "warnings": warnings,
        "message": (
            "Potential warning signs found. Avoid entering personal details."
            if warnings else
            "No basic warning signs detected. This does not prove the website is safe."
        )
    })


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
@app.route("/api/scan-url", methods=["POST"])
def scan_url_api():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Please enter a valid URL"
        }), 400

    result = scan_url(url)
    return jsonify(result)
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
