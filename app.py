        
import os
import re
import hmac
import csv
import io
import uuid
import secrets
import sqlite3
import ipaddress

from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, render_template_string,
    make_response
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# 1. CONFIGURATION & SECURITY
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

DATABASE = os.environ.get("DATABASE_PATH", "cybersaathi.db")

STATUSES = [
    "Pending",
    "Under Review",
    "Resolved",
    "Rejected"
]

COMPLAINT_TYPES = [
    "Online Financial Fraud",
    "Phishing",
    "Social Media Harassment",
    "Identity Theft",
    "Other Cybercrime"
]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true",
    MAX_CONTENT_LENGTH=1024 * 1024,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24
)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


def is_admin():
    return session.get("admin_logged_in") is True


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = get_db()

    user = connection.execute("""
        SELECT id, name, email
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    connection.close()

    return user


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


def verify_csrf(token):
    saved = session.get("csrf_token", "")

    return bool(saved) and hmac.compare_digest(
        saved,
        token or ""
    )


# ==========================================
# 2. DATABASE
# ==========================================

def get_db():
    connection = sqlite3.connect(
        DATABASE,
        timeout=15
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def create_database():
    folder = os.path.dirname(os.path.abspath(DATABASE))
    os.makedirs(folder, exist_ok=True)

    connection = get_db()

    # USER TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # COMPLAINT TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE,
            complaint_type TEXT NOT NULL,
            description TEXT NOT NULL,
            incident_date TEXT,
            created_at TEXT,
            status TEXT DEFAULT 'Pending',
            admin_note TEXT DEFAULT '',
            user_id INTEGER REFERENCES users(id)
        )
    """)

    # MIGRATE EXISTING DATABASE
    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(complaints)"
        ).fetchall()
    }

    if "status" not in columns:
        connection.execute("""
            ALTER TABLE complaints
            ADD COLUMN status TEXT DEFAULT 'Pending'
        """)

    if "admin_note" not in columns:
        connection.execute("""
            ALTER TABLE complaints
            ADD COLUMN admin_note TEXT DEFAULT ''
        """)

    if "user_id" not in columns:
        connection.execute("""
            ALTER TABLE complaints
            ADD COLUMN user_id INTEGER REFERENCES users(id)
        """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaint_reference
        ON complaints(reference)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaint_status
        ON complaints(status)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaint_user
        ON complaints(user_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_user_email
        ON users(email)
    """)

    connection.commit()
    connection.close()


# ==========================================
# 3. HOME PAGE & API STATUS
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "service": "CyberSaathi AI",
        "status": "ok",
        "version": "3.0"
    })


# ==========================================
# 4. USER REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user():
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":

        if not verify_csrf(request.form.get("csrf_token", "")):
            return "Invalid request. Refresh and try again.", 400

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or len(name) > 80:
            return "Enter a valid name.", 400

        if len(email) > 254 or not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email
        ):
            return "Enter a valid email address.", 400

        if len(password) < 8 or len(password) > 128:
            return "Password must be between 8 and 128 characters.", 400

        password_hash = generate_password_hash(password)

        connection = get_db()

        try:
            connection.execute("""
                INSERT INTO users (
                    name,
                    email,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                password_hash,
                datetime.now().isoformat(timespec="seconds")
            ))

            connection.commit()

            user = connection.execute("""
                SELECT id FROM users WHERE email = ?
            """, (email,)).fetchone()

        except sqlite3.IntegrityError:
            connection.close()
            return "An account with this email already exists.", 409

        except sqlite3.Error:
            connection.rollback()
            connection.close()

            app.logger.exception("Registration failed")

            return "Unable to create account. Please try again.", 500

        connection.close()

        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        csrf_token()

        return redirect(url_for("user_dashboard"))

    token = csrf_token()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSaathi Registration</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <style>
            * { box-sizing: border-box; }

            body {
                background: #081426;
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
                max-width: 420px;
                border: 1px solid #38bdf8;
            }

            h2 { color: #67e8f9; }

            input {
                width: 100%;
                padding: 13px;
                margin: 9px 0 17px;
                border-radius: 6px;
                border: 0;
            }

            button {
                width: 100%;
                padding: 13px;
                background: #0284c7;
                color: white;
                border: 0;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
            }

            a { color: #67e8f9; }
        </style>
    </head>

    <body>
        <form method="POST">
            <h2>Create Your Account</h2>

            <input
                type="hidden"
                name="csrf_token"
                value="{{ token }}"
            >

            <label>Name</label>
            <input
                name="name"
                maxlength="80"
                required
                autocomplete="name"
                placeholder="Enter your name"
            >

            <label>Email</label>
            <input
                type="email"
                name="email"
                maxlength="254"
                required
                autocomplete="email"
                placeholder="Enter your email"
            >

            <label>Password</label>
            <input
                type="password"
                name="password"
                minlength="8"
                maxlength="128"
                required
                autocomplete="new-password"
                placeholder="At least 8 characters"
            >

            <button type="submit">Register</button>

            <p>
                Already registered?
                <a href="{{ url_for('user_login') }}">Login</a>
            </p>

            <p><a href="/">Back to Home</a></p>
        </form>
    </body>
    </html>
    """, token=token)


# ==========================================
# 5. USER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def user_login():

    if current_user():
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":

        if not verify_csrf(request.form.get("csrf_token", "")):
            return "Invalid request. Refresh and try again.", 400

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        connection.close()

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):
            return render_template_string("""
                <h3>Invalid email or password.</h3>
                <a href="{{ url_for('user_login') }}">Try again</a>
            """), 401

        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        csrf_token()

        return redirect(url_for("user_dashboard"))

    token = csrf_token()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSaathi Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <style>
            * { box-sizing: border-box; }

            body {
                background: #081426;
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
                max-width: 420px;
                border: 1px solid #38bdf8;
            }

            h2 { color: #67e8f9; }

            input {
                width: 100%;
                padding: 13px;
                margin: 9px 0 17px;
                border-radius: 6px;
                border: 0;
            }

            button {
                width: 100%;
                padding: 13px;
                background: #0284c7;
                color: white;
                border: 0;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
            }

            a { color: #67e8f9; }
        </style>
    </head>

    <body>
        <form method="POST">
            <h2>CyberSaathi Login</h2>

            <input
                type="hidden"
                name="csrf_token"
                value="{{ token }}"
            >

            <label>Email</label>
            <input
                type="email"
                name="email"
                required
                autocomplete="email"
                placeholder="Enter your email"
            >

            <label>Password</label>
            <input
                type="password"
                name="password"
                required
                autocomplete="current-password"
                placeholder="Enter your password"
            >

            <button type="submit">Login</button>

            <p>
                New user?
                <a href="{{ url_for('register') }}">Create account</a>
            </p>

            <p><a href="/">Back to Home</a></p>
        </form>
    </body>
    </html>
    """, token=token)


# ==========================================
# 6. USER DASHBOARD
# ==========================================

@app.route("/dashboard")
def user_dashboard():

    user = current_user()

    if user is None:
        return redirect(url_for("user_login"))

    connection = get_db()

    complaints = connection.execute("""
        SELECT
            reference,
            complaint_type,
            incident_date,
            created_at,
            status
        FROM complaints
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()

    connection.close()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My CyberSaathi Dashboard</title>

        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <style>
            * { box-sizing: border-box; }

            body {
                background: #081426;
                color: white;
                font-family: Arial;
                margin: 0;
                padding: 22px;
            }

            .panel {
                background: #172a43;
                padding: 24px;
                border-radius: 12px;
                margin: 15px auto;
                max-width: 850px;
                border: 1px solid #294765;
                overflow-wrap: anywhere;
            }

            h1, h2 { color: #67e8f9; }

            .btn {
                display: inline-block;
                background: #0284c7;
                color: white;
                padding: 11px 16px;
                text-decoration: none;
                border-radius: 6px;
                margin: 5px 5px 5px 0;
            }

            .complaint {
                background: #0b3854;
                padding: 16px;
                margin: 12px 0;
                border-radius: 8px;
            }

            .muted { color: #cbd5e1; }

            .empty {
                color: #fbbf24;
                padding: 15px;
            }
        </style>
    </head>

    <body>

        <div class="panel">

            <h1>Welcome, {{ user["name"] }}</h1>

            <p class="muted">{{ user["email"] }}</p>

            <a class="btn" href="/">Home</a>

            <a class="btn" href="#history">My Complaints</a>

            <a class="btn" href="{{ url_for('user_logout') }}">
                Logout
            </a>

            <h2 id="history">My Complaint History</h2>

            {% if complaints %}

                {% for c in complaints %}

                    <div class="complaint">

                        <p>
                            <b>Reference:</b>
                            {{ c["reference"] }}
                        </p>

                        <p>
                            <b>Type:</b>
                            {{ c["complaint_type"] }}
                        </p>

                        <p>
                            <b>Incident Date:</b>
                            {{ c["incident_date"] or "Not provided" }}
                        </p>

                        <p>
                            <b>Submitted:</b>
                            {{ c["created_at"] }}
                        </p>

                        <p>
                            <b>Status:</b>
                            {{ c["status"] }}
                        </p>

                        <a
                            class="btn"
                            href="{{ url_for(
                                'track_complaint',
                                reference=c['reference']
                            ) }}"
                        >
                            Track Complaint
                        </a>

                    </div>

                {% endfor %}

            {% else %}

                <p class="empty">
                    No complaints have been submitted through this account yet.
                </p>

                <a class="btn" href="/#complaint">
                    Submit a Complaint
                </a>

            {% endif %}

        </div>

    </body>
    </html>
    """, user=user, complaints=complaints)


# ==========================================
# 7. USER LOGOUT
# ==========================================

@app.route("/logout")
def user_logout():
    session.clear()
    return redirect(url_for("home"))


# ==========================================
# 8. PHISHING URL SCANNER
# ==========================================

TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "microsoft.com",
    "wikipedia.org"
]


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

        if not hostname:
            raise ValueError("Missing hostname")

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported scheme")

        if parsed.username or parsed.password:
            return {
                "status": "Potential Warning Signs Found",
                "message": "This URL contains embedded login credentials.",
                "warnings": [
                    "URL contains embedded login credentials."
                ]
            }

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            hostname = hostname.encode("idna").decode("ascii")

            if (
                "." not in hostname
                or not re.fullmatch(r"[a-z0-9.-]+", hostname)
                or ".." in hostname
                or hostname.startswith(".")
                or hostname.endswith(".")
            ):
                raise ValueError("Invalid domain")

        warnings = []

        if parsed.scheme != "https":
            warnings.append(
                "URL does not use HTTPS encryption."
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:
            warnings.append(
                "Domain uses encoded characters."
            )

        if is_ip:
            warnings.append(
                "URL uses an IP address instead of a domain name."
            )

        trusted = any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in TRUSTED_DOMAINS
        )

        if not trusted:
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
            "message": (
                "No basic warning signs detected. "
                "This does not guarantee that the website is safe."
            ),
            "warnings": []
        }

    except (ValueError, UnicodeError):
        return {
            "status": "Invalid URL",
            "message": "The URL format is invalid.",
            "warnings": []
        }


@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Please enter a valid URL."
        }), 400

    return jsonify(scan_url(url))


# ==========================================
# 9. SCAM MESSAGE DETECTOR
# ==========================================

@app.route("/api/scam-check", methods=["POST"])
def scam_check():

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str) or not message.strip():
        return jsonify({
            "error": "Please enter a message."
        }), 400

    if len(message) > 5000:
        return jsonify({
            "error": "Message is too long."
        }), 400

    keywords = [
        "urgent",
        "otp",
        "password",
        "bank account",
        "send money",
        "prize",
        "winner",
        "click here",
        "verify account",
        "limited time",
        "account blocked",
        "kyc update",
        "claim reward",
        "free gift"
    ]

    found = [
        word for word in keywords
        if word in message.lower()
    ]

    return jsonify({
        "warning_signs": found,
        "risk_level": (
            "Needs Attention"
            if found else
            "No Common Keywords Found"
        ),
        "message": (
            "This message contains common scam warning signs. "
            "Verify it independently."
            if found else
            "No common scam keywords detected. "
            "Still be careful with unknown messages."
        )
    })


# ==========================================
# 10. DAILY CYBER TIPS
# ==========================================

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
            "Use official websites for online services.",
            "Never install unknown APK files.",
            "Check website addresses before logging in.",
            "Report suspicious online financial transactions."
        ]
    })


# ==========================================
# 11. CYBERSAATHI ASSISTANT
# ==========================================

@app.route("/api/assistant", methods=["POST"])
def assistant():

    data = request.get_json(silent=True) or {}
    question = data.get("question", "")

    if not isinstance(question, str) or not question.strip():
        return jsonify({
            "error": "Please enter a question."
        }), 400

    if len(question) > 2000:
        return jsonify({
            "error": "Question is too long."
        }), 400

    question = question.lower()

    if any(word in question for word in [
        "phishing", "fake link", "suspicious link"
    ]):
        answer = (
            "Phishing is an attempt to trick people into revealing "
            "personal information. Check website addresses and "
            "avoid unknown links."
        )

    elif any(word in question for word in [
        "otp", "password", "pin"
    ]):
        answer = (
            "Never share your OTP, PIN or password with anyone. "
            "Use unique passwords and enable two-factor authentication."
        )

    elif any(word in question for word in [
        "fraud", "scam", "money", "payment"
    ]):
        answer = (
            "Be careful with unexpected payment requests. "
            "For financial cyber fraud in India, contact 1930 "
            "or use the official cybercrime portal."
        )

    elif "social media" in question:
        answer = (
            "Use privacy settings, avoid unknown links and never "
            "share sensitive personal information publicly."
        )

    elif "cybercrime" in question or "complaint" in question:
        answer = (
            "You can submit a report through CyberSaathi for "
            "platform tracking. For an official Indian cybercrime "
            "complaint, visit https://cybercrime.gov.in/"
        )

    elif "hacked" in question or "hack" in question:
        answer = (
            "Secure your accounts using official recovery options, "
            "change compromised passwords from a trusted device, "
            "and enable two-factor authentication."
        )

    else:
        answer = (
            "Welcome to CyberSaathi AI! Stay alert online. "
            "Never share OTPs or passwords, verify suspicious "
            "messages independently and use official websites."
        )

    return jsonify({"answer": answer})


# ==========================================
# 12. SUBMIT COMPLAINT
# ==========================================

@app.route("/api/complaints", methods=["POST"])
def submit_complaint():

    data = request.get_json(silent=True) or {}

    complaint_type = data.get("type", "")
    description = data.get("description", "")
    incident_date = data.get("date", "")

    if not all(
        isinstance(value, str)
        for value in [
            complaint_type,
            description,
            incident_date
        ]
    ):
        return jsonify({
            "error": "Invalid complaint details."
        }), 400

    complaint_type = complaint_type.strip()
    description = description.strip()
    incident_date = incident_date.strip()

    if complaint_type not in COMPLAINT_TYPES:
        return jsonify({
            "error": "Please select a valid complaint type."
        }), 400

    if not description:
        return jsonify({
            "error": "Description is required."
        }), 400

    if len(description) > 5000:
        return jsonify({
            "error": "Description is too long."
        }), 400

    if incident_date:
        try:
            datetime.strptime(incident_date, "%Y-%m-%d")
        except ValueError:
            return jsonify({
                "error": "Invalid incident date."
            }), 400

    reference = "CS-" + uuid.uuid4().hex[:8].upper()

    # Associate the complaint with the logged-in account, if any.
    user = current_user()
    user_id = user["id"] if user else None

    connection = get_db()

    try:
        connection.execute("""
            INSERT INTO complaints (
                reference,
                complaint_type,
                description,
                incident_date,
                created_at,
                status,
                user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            reference,
            complaint_type,
            description,
            incident_date,
            datetime.now().isoformat(timespec="seconds"),
            "Pending",
            user_id
        ))

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Complaint saving failed")

        return jsonify({
            "error": "Unable to save complaint."
        }), 500

    finally:
        connection.close()

    return jsonify({
        "message": "Complaint successfully submitted.",
        "reference": reference,
        "status": "Pending",
        "official_portal": "https://cybercrime.gov.in/"
    }), 201


# ==========================================
# 13. TRACK COMPLAINT
# ==========================================

@app.route("/api/complaints/<reference>")
def track_complaint(reference):

    connection = get_db()

    complaint = connection.execute("""
        SELECT
            reference,
            complaint_type,
            incident_date,
            created_at,
            status
        FROM complaints
        WHERE reference = ?
    """, (reference.strip().upper(),)).fetchone()

    connection.close()

    if complaint is None:
        return jsonify({
            "error": "Reference not found."
        }), 404

    return jsonify(dict(complaint))


# ==========================================
# 14. ADMIN LOGIN
# ==========================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if not ADMIN_PASSWORD:
        return (
            "Admin password is not configured. "
            "Set ADMIN_PASSWORD in your deployment environment.",
            503
        )

    if is_admin():
        return redirect(url_for("admin"))

    if request.method == "POST":

        password = request.form.get("password", "")
        token = request.form.get("csrf_token", "")

        if not verify_csrf(token):
            return "Invalid request. Refresh and try again.", 400

        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin_logged_in"] = True
            session.permanent = True
            csrf_token()

            return redirect(url_for("admin"))

        return render_template_string("""
            <h3>Incorrect password.</h3>
            <a href="{{ url_for('admin_login') }}">Try again</a>
        """), 401

    token = csrf_token()

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
                border-radius: 14px;
                width: 100%;
                max-width: 380px;
                border: 1px solid #38bdf8;
            }

            h2 { color: #38bdf8; }

            input {
                width: 100%;
                padding: 14px;
                margin: 15px 0;
                border-radius: 7px;
                border: none;
            }

            button {
                background: #0284c7;
                color: white;
                padding: 14px;
                border: none;
                border-radius: 7px;
                width: 100%;
                cursor: pointer;
            }
        </style>
    </head>

    <body>
        <form method="POST">
            <h2>CyberSaathi Admin</h2>
            <p>Administrator Login</p>

            <input
                type="hidden"
                name="csrf_token"
                value="{{ token }}"
            >

            <input
                type="password"
                name="password"
                placeholder="Admin Password"
                required
                autocomplete="current-password"
            >

            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """, token=token)


# ==========================================
# 15. ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
def admin():

    if not is_admin():
        return redirect(url_for("admin_login"))

    search = request.args.get("search", "").strip()
    selected_status = request.args.get("status", "").strip()

    connection = get_db()

    total = connection.execute("""
        SELECT COUNT(*) FROM complaints
    """).fetchone()[0]

    stats = {}

    for status_name in STATUSES:
        stats[status_name] = connection.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = ?",
            (status_name,)
        ).fetchone()[0]

    query = "SELECT * FROM complaints WHERE 1=1"
    params = []

    if search:
        query += """
            AND (
                reference LIKE ?
                OR complaint_type LIKE ?
                OR description LIKE ?
            )
        """

        keyword = "%" + search + "%"
        params.extend([keyword, keyword, keyword])

    if selected_status in STATUSES:
        query += " AND status = ?"
        params.append(selected_status)

    query += " ORDER BY id DESC"

    complaints = connection.execute(
        query,
        params
    ).fetchall()

    connection.close()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSaathi Admin Dashboard</title>

        <meta name="viewport"
              content="width=device-width, initial-scale=1">

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
                border-radius: 12px;
                margin-bottom: 20px;
            }

            .stats {
                display: grid;
                grid-template-columns:
                    repeat(auto-fit, minmax(145px, 1fr));
                gap: 12px;
                margin-bottom: 25px;
            }

            .stat {
                background: #172a43;
                padding: 18px;
                border-radius: 10px;
                border: 1px solid #29445f;
            }

            .stat h2 {
                color: #38bdf8;
                margin: 8px 0;
            }

            .toolbar {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-bottom: 20px;
            }

            input, select {
                padding: 12px;
                border-radius: 7px;
                border: none;
                min-width: 130px;
            }

            button, .btn {
                background: #0284c7;
                color: white;
                padding: 11px 15px;
                border: none;
                border-radius: 7px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }

            .complaint {
                background: #172a43;
                padding: 20px;
                margin: 15px 0;
                border-radius: 12px;
                border: 1px solid #29445f;
                overflow-wrap: anywhere;
            }

            .complaint h3 { color: #67e8f9; }

            .complaint p { line-height: 1.5; }

            .status-form {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 15px;
            }

            .logout { background: #dc2626; }

            .empty { color: #fbbf24; }

            @media(max-width: 500px) {
                body { padding: 12px; }
                .toolbar input { width: 100%; }
            }
        </style>
    </head>

    <body>

        <h1>CyberSaathi Admin Dashboard</h1>

        <div class="top">
            <h2>Welcome, Administrator</h2>
            <p>Manage and monitor submitted complaints.</p>

            <a class="btn" href="{{ url_for('admin_export') }}">
                Export CSV
            </a>

            <a class="btn logout" href="{{ url_for('admin_logout') }}">
                Logout
            </a>
        </div>

        <div class="stats">

            <div class="stat">
                <p>Total Complaints</p>
                <h2>{{ total }}</h2>
            </div>

            <div class="stat">
                <p>Pending</p>
                <h2>{{ stats['Pending'] }}</h2>
            </div>

            <div class="stat">
                <p>Under Review</p>
                <h2>{{ stats['Under Review'] }}</h2>
            </div>

            <div class="stat">
                <p>Resolved</p>
                <h2>{{ stats['Resolved'] }}</h2>
            </div>

            <div class="stat">
                <p>Rejected</p>
                <h2>{{ stats['Rejected'] }}</h2>
            </div>

        </div>

        <h2>Complaint Management</h2>

        <form class="toolbar" method="GET">

            <input
                type="text"
                name="search"
                placeholder="Search complaints..."
                value="{{ search }}"
            >

            <select name="status">
                <option value="">All Statuses</option>

                {% for s in statuses %}
                    <option
                        value="{{ s }}"
                        {% if selected_status == s %}selected{% endif %}
                    >
                        {{ s }}
                    </option>
                {% endfor %}
            </select>

            <button type="submit">Search</button>

            <a class="btn" href="{{ url_for('admin') }}">
                Reset
            </a>

        </form>

        {% if complaints %}

            {% for c in complaints %}

                <div class="complaint">

                    <h3>Complaint #{{ c.id }}</h3>

                    <p>
                        <b>Reference:</b>
                        {{ c.reference }}
                    </p>

                    <p>
                        <b>Type:</b>
                        {{ c.complaint_type }}
                    </p>

                    <p>
                        <b>Description:</b>
                        {{ c.description }}
                    </p>

                    <p>
                        <b>Incident Date:</b>
                        {{ c.incident_date or 'Not provided' }}
                    </p>

                    <p>
                        <b>Submitted:</b>
                        {{ c.created_at }}
                    </p>

                    <p>
                        <b>Account User ID:</b>
                        {{ c.user_id or 'Guest submission' }}
                    </p>

                    <p>
                        <b>Current Status:</b>
                        {{ c.status }}
                    </p>

                    <p>
                        <b>Admin Note:</b>
                        {{ c.admin_note or 'No note' }}
                    </p>

                    <form
                        class="status-form"
                        method="POST"
                        action="{{ url_for(
                            'update_complaint',
                            complaint_id=c.id
                        ) }}"
                    >

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="{{ token }}"
                        >

                        <select name="status" required>
                            {% for s in statuses %}
                                <option
                                    value="{{ s }}"
                                    {% if c.status == s %}selected{% endif %}
                                >
                                    {{ s }}
                                </option>
                            {% endfor %}
                        </select>

                        <input
                            type="text"
                            name="admin_note"
                            placeholder="Admin note (optional)"
                            value="{{ c.admin_note }}"
                            maxlength="500"
                        >

                        <button type="submit">
                            Update Status
                        </button>

                    </form>

                </div>

            {% endfor %}

        {% else %}

            <div class="complaint">
                <p class="empty">No complaints found.</p>
            </div>

        {% endif %}

    </body>
    </html>
    """,
        complaints=complaints,
        total=total,
        stats=stats,
        search=search,
        selected_status=selected_status,
        statuses=STATUSES,
        token=csrf_token()
    )


# ==========================================
# 16. UPDATE COMPLAINT STATUS
# ==========================================

@app.route(
    "/admin/complaint/<int:complaint_id>/update",
    methods=["POST"]
)
def update_complaint(complaint_id):

    if not is_admin():
        return redirect(url_for("admin_login"))

    if not verify_csrf(request.form.get("csrf_token", "")):
        return "Invalid request. Refresh and try again.", 400

    new_status = request.form.get("status", "").strip()
    admin_note = request.form.get("admin_note", "").strip()

    if new_status not in STATUSES:
        return "Invalid complaint status.", 400

    if len(admin_note) > 500:
        return "Admin note is too long.", 400

    connection = get_db()

    result = connection.execute("""
        UPDATE complaints
        SET status = ?, admin_note = ?
        WHERE id = ?
    """, (
        new_status,
        admin_note,
        complaint_id
    ))

    connection.commit()
    connection.close()

    if result.rowcount == 0:
        return "Complaint not found.", 404

    return redirect(url_for("admin"))


# ==========================================
# 17. EXPORT COMPLAINT REPORT
# ==========================================

def safe_csv_cell(value):
    value = "" if value is None else str(value)

    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value

    return value


@app.route("/admin/export")
def admin_export():

    if not is_admin():
        return redirect(url_for("admin_login"))

    connection = get_db()

    complaints = connection.execute("""
        SELECT
            id,
            reference,
            complaint_type,
            description,
            incident_date,
            created_at,
            status,
            admin_note
        FROM complaints
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Reference",
        "Complaint Type",
        "Description",
        "Incident Date",
        "Created At",
        "Status",
        "Admin Note"
    ])

    for c in complaints:
        writer.writerow([
            safe_csv_cell(c["id"]),
            safe_csv_cell(c["reference"]),
            safe_csv_cell(c["complaint_type"]),
            safe_csv_cell(c["description"]),
            safe_csv_cell(c["incident_date"]),
            safe_csv_cell(c["created_at"]),
            safe_csv_cell(c["status"]),
            safe_csv_cell(c["admin_note"])
        ])

    response = make_response("\ufeff" + output.getvalue())

    response.headers["Content-Type"] = (
        "text/csv; charset=utf-8"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=cybersaathi_complaints.csv"
    )

    return response


# ==========================================
# 18. ADMIN LOGOUT
# ==========================================

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ==========================================
# 19. CREATE DATABASE & START APPLICATION
# ==========================================

create_database()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
   
