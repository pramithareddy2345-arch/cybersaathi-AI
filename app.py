import os
import re
import hmac
import uuid
import secrets
import sqlite3

from datetime import datetime
from urllib.parse import urlparse
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, render_template_string
)

app = Flask(__name__)

# SECURITY SETTINGS
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true"
)

# DATABASE
DATABASE = os.environ.get("DATABASE_PATH", "cybersaathi.db")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    folder = os.path.dirname(os.path.abspath(DATABASE))
    os.makedirs(folder, exist_ok=True)

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


# HOME PAGE
@app.route("/")
def home():
    return render_template("index.html")


# API STATUS
@app.route("/api/status")
def status():
    return jsonify({
        "service": "CyberSaathi API",
        "status": "ok"
    })


# PHISHING URL SCANNER
def scan_url(url):
    url = url.strip()

    if not url or any(char.isspace() for char in url):
        return {
            "status": "Invalid URL",
            "message": "Please enter a valid URL.",
            "warnings": []
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

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
                "message": "The URL format is invalid.",
                "warnings": []
            }

        warnings = []

        if parsed.username or parsed.password:
            warnings.append("URL contains embedded login credentials.")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            warnings.append("Domain uses encoded characters.")

        if parsed.scheme != "https":
            warnings.append("URL does not use HTTPS encryption.")

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

        if not recognized:
            warnings.append(
                "Domain is not in the recognized-domain list."
            )

        if warnings:
            return {
                "status": "Potential Warning Signs Found",
                "message": "Check this URL carefully before visiting.",
                "warnings": warnings
            }

        return {
            "status": "No Basic Warning Signs Detected",
            "message": "No basic warning signs detected. This does not guarantee that the website is safe.",
            "warnings": []
        }

    except ValueError:
        return {
            "status": "Invalid URL",
            "message": "Unable to process this URL.",
            "warnings": []
        }


@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Please enter a valid URL."}), 400

    return jsonify(scan_url(url))


# SCAM MESSAGE CHECKER
@app.route("/api/scam-check", methods=["POST"])
def scam_check():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Please enter a message."}), 400

    keywords = [
        "urgent", "otp", "password", "bank account",
        "send money", "prize", "winner", "click here",
        "verify account", "limited time"
    ]

    found = [
        word for word in keywords
        if word in message.lower()
    ]

    return jsonify({
        "warning_signs": found,
        "message": (
            "This message contains common scam warning signs. Verify it independently."
            if found else
            "No common scam keywords detected. Still be careful with unknown messages."
        )
    })


# DAILY CYBER TIPS
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


# CYBER ASSISTANT
@app.route("/api/assistant", methods=["POST"])
def assistant():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "")

    if not isinstance(question, str) or not question.strip():
        return jsonify({"error": "Please enter a question."}), 400

    question = question.lower()

    if any(word in question for word in ["phishing", "fake link"]):
        answer = (
            "Phishing is an attempt to trick people into revealing "
            "personal information. Check website addresses and avoid unknown links."
        )

    elif any(word in question for word in ["otp", "password"]):
        answer = (
            "Never share your OTP or password with anyone. "
            "Use unique passwords and enable two-factor authentication."
        )

    elif any(word in question for word in ["fraud", "scam", "money"]):
        answer = (
            "Be careful with unexpected payment requests. "
            "In India, report financial cyber fraud through the official portal "
            "or call 1930."
        )

    elif "social media" in question:
        answer = (
            "Use privacy settings, avoid unknown links and never "
            "share sensitive personal information publicly."
        )

    else:
        answer = (
            "Stay alert online. Never share OTPs or passwords, "
            "verify suspicious messages independently and use official websites."
        )

    return jsonify({"answer": answer})


# SUBMIT COMPLAINT
@app.route("/api/complaints", methods=["POST"])
def submit_complaint():
    data = request.get_json(silent=True) or {}

    complaint_type = data.get("type", "")
    description = data.get("description", "")
    incident_date = data.get("date", "")

    if not all(isinstance(value, str) for value in [
        complaint_type, description, incident_date
    ]):
        return jsonify({"error": "Invalid complaint details."}), 400

    complaint_type = complaint_type.strip()
    description = description.strip()
    incident_date = incident_date.strip()

    allowed_types = [
        "Online Financial Fraud",
        "Phishing",
        "Social Media Harassment",
        "Identity Theft",
        "Other Cybercrime"
    ]

    if complaint_type not in allowed_types:
        return jsonify({"error": "Please select a valid complaint type."}), 400

    if not description:
        return jsonify({"error": "Description is required."}), 400

    if len(description) > 5000:
        return jsonify({"error": "Description is too long."}), 400

    reference = "CS-" + uuid.uuid4().hex[:8].upper()

    connection = get_db()

    try:
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

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Complaint saving failed")
        return jsonify({"error": "Unable to save complaint."}), 500

    finally:
        connection.close()

    return jsonify({
        "message": "Complaint successfully saved in the CyberSaathi database.",
        "reference": reference,
        "official_portal": "https://cybercrime.gov.in/"
    })


# TRACK COMPLAINT
@app.route("/api/complaints/<reference>")
def track_complaint(reference):
    connection = get_db()

    complaint = connection.execute("""
        SELECT reference, complaint_type, incident_date, created_at
        FROM complaints
        WHERE reference = ?
    """, (reference,)).fetchone()

    connection.close()

    if complaint is None:
        return jsonify({"error": "Reference not found."}), 404

    return jsonify(dict(complaint))


# ADMIN LOGIN
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if not ADMIN_PASSWORD:
        return "Admin password is not configured in Render.", 503

    if request.method == "POST":
        password = request.form.get("password", "")
        csrf_token = request.form.get("csrf_token", "")

        if not hmac.compare_digest(
            csrf_token,
            session.get("login_csrf", "")
        ):
            return "Invalid request. Please refresh and try again.", 400

        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin_logged_in"] = True
            return redirect(url_for("admin"))

        return render_template_string("""
            <h3>Incorrect password.</h3>
            <a href="{{ url_for('admin_login') }}">Try again</a>
        """), 401

    token = secrets.token_urlsafe(32)
    session["login_csrf"] = token

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSaathi Admin Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { box-sizing: border-box; }
            body {
                background: #0b1628;
                color: white;
                font-family: Arial;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
            }
            form {
                background: #172a43;
                padding: 30px;
                border-radius: 12px;
                width: 100%;
                max-width: 350px;
                border: 1px solid #38bdf8;
            }
            h2 { color: #38bdf8; }
            input {
                width: 100%;
                padding: 13px;
                margin: 15px 0;
                border-radius: 6px;
                border: none;
            }
            button {
                background: #0284c7;
                color: white;
                padding: 13px;
                border: none;
                border-radius: 6px;
                width: 100%;
                cursor: pointer;
            }
        </style>
    </head>
    <body>
        <form method="POST">
            <h2>CyberSaathi Admin</h2>
            <p>Enter administrator password.</p>
            <input type="hidden" name="csrf_token" value="{{ token }}">
            <input type="password" name="password"
                   placeholder="Admin Password" required>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """, token=token)


# ADMIN DASHBOARD
@app.route("/admin")
def admin():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    connection = get_db()

    complaints = connection.execute("""
        SELECT *
        FROM complaints
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSaathi Admin Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <style>
            * { box-sizing: border-box; }

            body {
                font-family: Arial, sans-serif;
                background: #0b1628;
                color: white;
                padding: 20px;
                margin: 0;
            }

            h1 { color: #38bdf8; }

            .top {
                background: #172a43;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }

            .complaint {
                background: #172a43;
                padding: 20px;
                margin: 15px 0;
                border-radius: 10px;
                border: 1px solid #38bdf8;
                overflow-wrap: anywhere;
            }

            .complaint h3 { color: #67e8f9; }

            .logout {
                display: inline-block;
                background: #0284c7;
                color: white;
                padding: 12px 20px;
                border-radius: 6px;
                text-decoration: none;
            }

            .empty { color: #fbbf24; }
        </style>
    </head>

    <body>
        <h1>CyberSaathi Admin Dashboard</h1>

        <div class="top">
            <h2>Total Complaints: {{ complaints|length }}</h2>
            <a class="logout" href="{{ url_for('admin_logout') }}">
                Logout
            </a>
        </div>

        {% if complaints %}

            {% for c in complaints %}

                <div class="complaint">
                    <h3>Complaint #{{ c.id }}</h3>

                    <p><b>Reference ID:</b> {{ c.reference }}</p>

                    <p><b>Complaint Type:</b> {{ c.complaint_type }}</p>

                    <p><b>Description:</b> {{ c.description }}</p>

                    <p><b>Incident Date:</b>
                        {{ c.incident_date or 'Not provided' }}
                    </p>

                    <p><b>Submitted At:</b> {{ c.created_at }}</p>
                </div>

            {% endfor %}

        {% else %}

            <div class="complaint">
                <p class="empty">No complaints submitted yet.</p>
            </div>

        {% endif %}

    </body>
    </html>
    """, complaints=complaints)


# ADMIN LOGOUT
@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# CREATE DATABASE
create_database()


# START APPLICATION
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
