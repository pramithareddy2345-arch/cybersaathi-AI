 
import os
import re
import csv
import io
import uuid
import sqlite3
import secrets
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, Response, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")

DATABASE = os.environ.get("DATABASE_PATH", "cybersaathi.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeThisAdminPassword123!")

# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL,
            complaint_type TEXT NOT NULL,
            description TEXT NOT NULL,
            incident_date TEXT,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Received',
            admin_note TEXT DEFAULT '',
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Migrate older databases safely.
    columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(complaints)").fetchall()
    ]

    if "user_id" not in columns:
        connection.execute("ALTER TABLE complaints ADD COLUMN user_id INTEGER")

    if "admin_note" not in columns:
        connection.execute("ALTER TABLE complaints ADD COLUMN admin_note TEXT DEFAULT ''")

    if "status" not in columns:
        connection.execute(
            "ALTER TABLE complaints ADD COLUMN status TEXT NOT NULL DEFAULT 'Received'"
        )

    connection.commit()
    connection.close()


create_database()


# --------------------------------------------------
# LOGIN HELPERS
# --------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return function(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "service": "CyberSaathi API",
        "status": "ok"
    })


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        connection = get_db()

        try:
            connection.execute("""
                INSERT INTO users (name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                generate_password_hash(password),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.close()
            flash("This email is already registered. Please log in.", "error")
            return redirect(url_for("register"))

        connection.close()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template_string(AUTH_TEMPLATE, page="register")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db()
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.", "error")
        return redirect(url_for("login"))

    return render_template_string(AUTH_TEMPLATE, page="login")


# --------------------------------------------------
# USER DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    connection = get_db()

    complaints = connection.execute("""
        SELECT * FROM complaints
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()

    connection.close()

    return render_template_string(
        USER_DASHBOARD_TEMPLATE,
        complaints=complaints,
        name=session.get("user_name", "User")
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------
# PHISHING URL CHECKER
# --------------------------------------------------

@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    check_url = url if "://" in url else "https://" + url
    parsed = urlparse(check_url)
    hostname = (parsed.hostname or "").lower()

    if not hostname or "." not in hostname:
        return jsonify({
            "result": "Invalid URL",
            "risk": "Unknown",
            "message": "Please enter a valid website address."
        })

    reasons = []

    if parsed.scheme != "https":
        reasons.append("The URL does not use HTTPS.")

    if "@" in parsed.netloc:
        reasons.append("The URL contains an unusual @ symbol.")

    if re.search(r"\d+\.\d+\.\d+\.\d+", hostname):
        reasons.append("The address uses an IP address instead of a domain name.")

    suspicious_words = [
        "login-verify", "account-update", "free-gift",
        "claim-prize", "password-reset", "banking-alert"
    ]

    if any(word in check_url.lower() for word in suspicious_words):
        reasons.append("The URL contains words often used in suspicious links.")

    if len(hostname) > 45:
        reasons.append("The domain name is unusually long.")

    if hostname.count("-") >= 3:
        reasons.append("The domain contains several hyphens.")

    if reasons:
        return jsonify({
            "result": "Potentially Suspicious",
            "risk": "Warning",
            "message": "This basic check found warning signs. Do not enter passwords or payment details unless you independently verify the website.",
            "reasons": reasons
        })

    return jsonify({
        "result": "No obvious warning signs found",
        "risk": "Not confirmed safe",
        "message": "This basic check cannot guarantee that a website is safe. Verify the domain independently before sharing information.",
        "reasons": []
    })


# --------------------------------------------------
# SCAM MESSAGE CHECKER
# --------------------------------------------------

@app.route("/api/scam-check", methods=["POST"])
def scam_check():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    text = message.lower()

    warning_phrases = [
        "urgent", "click here", "claim your prize",
        "you have won", "send otp", "share otp",
        "verify your account", "account blocked",
        "limited time", "send money", "bank details",
        "password immediately", "lottery winner"
    ]

    found = [phrase for phrase in warning_phrases if phrase in text]

    if found:
        return jsonify({
            "result": "Possible Scam Indicators",
            "risk": "Warning",
            "message": "This message contains language commonly associated with scams. Verify it through an official channel.",
            "indicators": found
        })

    return jsonify({
        "result": "No common scam phrases detected",
        "risk": "Not confirmed safe",
        "message": "This is only a basic keyword check. Scams can use other wording, so verify unexpected requests independently.",
        "indicators": []
    })


# --------------------------------------------------
# DAILY CYBER TIPS
# --------------------------------------------------

@app.route("/api/tips")
@app.route("/api/cyber-tips")
def tips():
    daily_tips = [
        "Never share your OTP, PIN or password with anyone.",
        "Use a different strong password for each important account.",
        "Enable two-factor authentication wherever possible.",
        "Check the website address before entering personal information.",
        "Avoid clicking unexpected links in messages.",
        "Keep your phone and apps updated.",
        "Do not send money to unknown people promising prizes.",
        "Use official apps and websites for banking.",
        "Review privacy settings on social media.",
        "Report suspected cyber financial fraud by calling 1930 promptly."
    ]

    day_index = datetime.now().timetuple().tm_yday % len(daily_tips)

    return jsonify({
        "tip": daily_tips[day_index],
        "tips": daily_tips
    })


# --------------------------------------------------
# CYBERSAATHI ASSISTANT
# --------------------------------------------------

@app.route("/api/assistant", methods=["POST"])
@app.route("/api/cyber-assistant", methods=["POST"])
def assistant():
    data = request.get_json(silent=True) or {}
    question = data.get("message", "").strip().lower()

    if not question:
        return jsonify({"reply": "Please enter your question."}), 400

    if any(word in question for word in ["otp", "one time password"]):
        reply = "Never share your OTP with anyone, even if they claim to be from a bank or government department."

    elif any(word in question for word in ["phishing", "fake link", "suspicious link"]):
        reply = "Phishing is an attempt to steal information through deceptive links or messages. Avoid opening unexpected links and verify the sender independently."

    elif any(word in question for word in ["fraud", "money", "payment", "upi", "bank"]):
        reply = "For suspected cyber financial fraud in India, contact your bank through its official channel and call 1930 promptly. You can also report it at cybercrime.gov.in."

    elif any(word in question for word in ["password", "account hacked", "hacked"]):
        reply = "Use a strong unique password, change compromised passwords through the official website, enable two-factor authentication and review account activity."

    elif any(word in question for word in ["social media", "instagram", "facebook"]):
        reply = "Keep your social media accounts private where appropriate, enable two-factor authentication and never share verification codes."

    elif any(word in question for word in ["report", "complaint"]):
        reply = "You can submit a complaint using the Report section on CyberSaathi. For official reporting in India, visit cybercrime.gov.in."

    else:
        reply = "I can help with cyber safety basics, phishing, suspicious messages, passwords and reporting cybercrime. Please describe your concern."

    return jsonify({"reply": reply})


# --------------------------------------------------
# SUBMIT COMPLAINT
# --------------------------------------------------

@app.route("/api/complaints", methods=["POST"])
def submit_complaint():
    data = request.get_json(silent=True) or request.form

    complaint_type = data.get("complaint_type", "").strip()
    description = data.get("description", "").strip()
    incident_date = data.get("incident_date", "").strip()

    if not complaint_type or not description:
        return jsonify({"error": "Please fill in the complaint type and description."}), 400

    if len(description) < 10:
        return jsonify({"error": "Please provide a little more detail."}), 400

    reference = "CS-" + uuid.uuid4().hex[:8].upper()

    connection = get_db()
    connection.execute("""
        INSERT INTO complaints (
            reference, complaint_type, description,
            incident_date, created_at, status, user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        reference,
        complaint_type,
        description,
        incident_date,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Received",
        session.get("user_id")
    ))

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "reference": reference,
        "message": "Your complaint has been submitted successfully."
    })


# --------------------------------------------------
# TRACK COMPLAINT
# --------------------------------------------------

@app.route("/api/complaints/<reference>")
def track_complaint(reference):
    connection = get_db()

    complaint = connection.execute("""
        SELECT reference, complaint_type, created_at,
               status, admin_note
        FROM complaints
        WHERE reference = ?
    """, (reference.upper(),)).fetchone()

    connection.close()

    if not complaint:
        return jsonify({"error": "Complaint reference not found."}), 404

    return jsonify(dict(complaint))


# --------------------------------------------------
# ADMIN LOGIN
# --------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        password = request.form.get("password", "")

        if secrets.compare_digest(password, ADMIN_PASSWORD):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))

        flash("Incorrect admin password.", "error")
        return redirect(url_for("admin_login"))

    return render_template_string(ADMIN_LOGIN_TEMPLATE)


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()

    connection = get_db()

    query = """
        SELECT complaints.*, users.name AS user_name,
               users.email AS user_email
        FROM complaints
        LEFT JOIN users ON complaints.user_id = users.id
        WHERE 1=1
    """
    params = []

    if search:
        query += """
            AND (
                complaints.reference LIKE ?
                OR complaints.complaint_type LIKE ?
                OR complaints.description LIKE ?
                OR users.email LIKE ?
            )
        """
        term = "%" + search + "%"
        params.extend([term, term, term, term])

    if status_filter:
        query += " AND complaints.status = ?"
        params.append(status_filter)

    query += " ORDER BY complaints.id DESC"

    complaints = connection.execute(query, params).fetchall()

    total = connection.execute(
        "SELECT COUNT(*) FROM complaints"
    ).fetchone()[0]

    received = connection.execute(
        "SELECT COUNT(*) FROM complaints WHERE status='Received'"
    ).fetchone()[0]

    reviewing = connection.execute(
        "SELECT COUNT(*) FROM complaints WHERE status='Under Review'"
    ).fetchone()[0]

    resolved = connection.execute(
        "SELECT COUNT(*) FROM complaints WHERE status='Resolved'"
    ).fetchone()[0]

    connection.close()

    return render_template_string(
        ADMIN_DASHBOARD_TEMPLATE,
        complaints=complaints,
        total=total,
        received=received,
        reviewing=reviewing,
        resolved=resolved,
        search=search,
        status_filter=status_filter
    )


# --------------------------------------------------
# ADMIN UPDATE COMPLAINT
# --------------------------------------------------

@app.route("/admin/complaint/<int:complaint_id>/update", methods=["POST"])
@admin_required
def update_complaint(complaint_id):
    status = request.form.get("status", "Received")
    note = request.form.get("admin_note", "").strip()

    allowed_statuses = ["Received", "Under Review", "Resolved", "Rejected"]

    if status not in allowed_statuses:
        flash("Invalid complaint status.", "error")
        return redirect(url_for("admin_dashboard"))

    connection = get_db()
    connection.execute("""
        UPDATE complaints
        SET status = ?, admin_note = ?
        WHERE id = ?
    """, (status, note, complaint_id))
    connection.commit()
    connection.close()

    flash("Complaint updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN CSV EXPORT
# --------------------------------------------------

@app.route("/admin/export")
@admin_required
def export_complaints():
    connection = get_db()
    complaints = connection.execute("""
        SELECT reference, complaint_type, description,
               incident_date, created_at, status, admin_note
        FROM complaints
        ORDER BY id DESC
    """).fetchall()
    connection.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Reference", "Complaint Type", "Description",
        "Incident Date", "Created At", "Status", "Admin Note"
    ])

    for complaint in complaints:
        writer.writerow(list(complaint))

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=cybersaathi_complaints.csv"
        }
    )


# --------------------------------------------------
# ADMIN LOGOUT
# --------------------------------------------------

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("home"))


# --------------------------------------------------
# SHARED HTML TEMPLATES
# --------------------------------------------------

AUTH_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ 'Register' if page == 'register' else 'Login' }} | CyberSaathi AI</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#081426;color:#fff;font-family:Arial,sans-serif;
min-height:100vh;display:grid;place-items:center;padding:20px}
.card{width:100%;max-width:420px;background:#122640;padding:30px;border-radius:16px}
h1{text-align:center;color:#55c8ff}
input{width:100%;padding:13px;margin:9px 0;border:1px solid #35516e;
border-radius:8px;background:#091a30;color:white}
button{width:100%;padding:13px;background:#168bd2;color:white;border:0;
border-radius:8px;font-weight:bold;cursor:pointer;margin-top:12px}
a{color:#55c8ff}
p{text-align:center}
.flash{padding:10px;background:#263d58;border-radius:8px;margin:8px 0}
</style>
</head>
<body>
<div class="card">
<h1>CyberSaathi AI</h1>
<h2>{{ 'Create Account' if page == 'register' else 'Welcome Back' }}</h2>
{% with messages = get_flashed_messages() %}
{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}
{% endwith %}
<form method="POST">
{% if page == 'register' %}
<input name="name" placeholder="Full name" required>
{% endif %}
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password (minimum 8 characters)" required>
<button type="submit">{{ 'Register' if page == 'register' else 'Login' }}</button>
</form>
{% if page == 'register' %}
<p>Already registered? <a href="{{ url_for('login') }}">Login</a></p>
{% else %}
<p>New user? <a href="{{ url_for('register') }}">Create an account</a></p>
{% endif %}
<p><a href="{{ url_for('home') }}">Back to Home</a></p>
</div>
</body>
</html>
"""


USER_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Dashboard | CyberSaathi AI</title>
<style>
body{margin:0;padding:25px;background:#081426;color:#eef6ff;font-family:Arial}
main{max-width:1000px;margin:auto}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
a{color:#55c8ff}
.card{background:#122640;padding:20px;border-radius:12px;margin:16px 0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse}
td,th{padding:12px;border-bottom:1px solid #35516e;text-align:left}
small{color:#b9c9da}
</style>
</head>
<body>
<main>
<header>
<h1>My Dashboard</h1>
<nav><a href="{{ url_for('home') }}">Home</a> | <a href="{{ url_for('logout') }}">Logout</a></nav>
</header>
<div class="card">
<h2>Welcome, {{ name }}</h2>
<p>View and track the complaints submitted through your account.</p>
<a href="{{ url_for('home') }}">Submit a complaint</a>
</div>
<div class="card">
<h2>My Complaints</h2>
{% if complaints %}
<table>
<tr><th>Reference</th><th>Type</th><th>Date</th><th>Status</th></tr>
{% for c in complaints %}
<tr>
<td>{{ c.reference }}</td>
<td>{{ c.complaint_type }}</td>
<td>{{ c.created_at }}</td>
<td>{{ c.status }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>You have not submitted any complaints yet.</p>
{% endif %}
</div>
</main>
</body>
</html>
"""


ADMIN_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Login | CyberSaathi</title>
<style>
body{background:#081426;color:white;font-family:Arial;display:grid;place-items:center;
min-height:100vh;margin:0;padding:20px}
.card{background:#122640;padding:30px;border-radius:15px;width:100%;max-width:400px}
input,button{width:100%;padding:13px;margin-top:12px;border-radius:8px}
input{background:#091a30;border:1px solid #35516e;color:white}
button{background:#168bd2;color:white;border:0;cursor:pointer}
a{color:#55c8ff}
</style>
</head>
<body>
<div class="card">
<h1>Admin Login</h1>
{% with messages = get_flashed_messages() %}
{% for message in messages %}<p>{{ message }}</p>{% endfor %}
{% endwith %}
<form method="POST">
<input type="password" name="password" placeholder="Admin password" required>
<button type="submit">Login</button>
</form>
<p><a href="{{ url_for('home') }}">Back to Home</a></p>
</div>
</body>
</html>
"""


ADMIN_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Dashboard | CyberSaathi</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:22px;background:#081426;color:#eef6ff;font-family:Arial}
main{max-width:1200px;margin:auto}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
a{color:#55c8ff}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:#122640;padding:18px;border-radius:12px;margin:14px 0}
.stat{font-size:28px;color:#55c8ff;font-weight:bold}
input,select,textarea,button{padding:10px;border-radius:7px;margin:4px}
input,select,textarea{background:#091a30;color:white;border:1px solid #35516e}
button{background:#168bd2;color:white;border:0;cursor:pointer}
table{width:100%;border-collapse:collapse}
th,td{padding:12px;border-bottom:1px solid #35516e;text-align:left;vertical-align:top}
textarea{width:100%;min-height:55px}
.complaint{overflow-wrap:anywhere}
@media(max-width:700px){table{font-size:12px}th,td{padding:7px}}
</style>
</head>
<body>
<main>
<header>
<h1>CyberSaathi Admin Dashboard</h1>
<nav><a href="{{ url_for('home') }}">Home</a> |
<a href="{{ url_for('export_complaints') }}">Export CSV</a> |
<a href="{{ url_for('admin_logout') }}">Logout</a></nav>
</header>

<div class="stats">
<div class="card"><small>Total complaints</small><div class="stat">{{ total }}</div></div>
<div class="card"><small>Received</small><div class="stat">{{ received }}</div></div>
<div class="card"><small>Under Review</small><div class="stat">{{ reviewing }}</div></div>
<div class="card"><small>Resolved</small><div class="stat">{{ resolved }}</div></div>
</div>

<div class="card">
<h2>Search and Filter</h2>
<form method="GET">
<input name="search" placeholder="Search reference, type, description or email" value="{{ search }}">
<select name="status">
<option value="">All statuses</option>
{% for s in ['Received','Under Review','Resolved','Rejected'] %}
<option value="{{ s }}" {% if status_filter == s %}selected{% endif %}>{{ s }}</option>
{% endfor %}
</select>
<button type="submit">Apply</button>
<a href="{{ url_for('admin_dashboard') }}">Clear</a>
</form>
</div>

<h2>Complaints</h2>
{% for c in complaints %}
<div class="card complaint">
<h3>{{ c.reference }} — {{ c.complaint_type }}</h3>
<p><b>Description:</b> {{ c.description }}</p>
<p><b>Incident date:</b> {{ c.incident_date or 'Not provided' }}</p>
<p><b>Submitted:</b> {{ c.created_at }}</p>
<p><b>User:</b> {{ c.user_name or 'Guest' }} ({{ c.user_email or 'No account email' }})</p>
<p><b>Current status:</b> {{ c.status }}</p>
<form method="POST" action="{{ url_for('update_complaint', complaint_id=c.id) }}">
<select name="status">
{% for s in ['Received','Under Review','Resolved','Rejected'] %}
<option value="{{ s }}" {% if c.status == s %}selected{% endif %}>{{ s }}</option>
{% endfor %}
</select>
<textarea name="admin_note" placeholder="Admin note">{{ c.admin_note or '' }}</textarea>
<button type="submit">Save Update</button>
</form>
</div>
{% else %}
<div class="card">No complaints found.</div>
{% endfor %}
</main>
</body>
</html>
"""


# --------------------------------------------------
# RUN LOCALLY
# --------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
 
    
