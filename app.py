from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from functools import wraps
from dotenv import load_dotenv
import os
from authlib.integrations.flask_client import OAuth

from utils.ai_analyzer import analyze_email, extract_eml_content
from utils.url_scanner import scan_urls
from utils.db import save_scan, get_scan_history, sign_up_user, sign_in_user, upsert_google_user

load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "phishguard-super-secret-key-2024")

# --- Google OAuth Setup ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# --- Auth Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze")
def analyze_page():
    return render_template("analyze.html")


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            return render_template("register.html", error="Email and password are required")
        
        # Call Supabase
        res, err = sign_up_user(email, password)
        if res and hasattr(res, 'user') and res.user:
            session['user_id'] = res.user.id
            session['email'] = res.user.email
            return redirect(url_for('dashboard_page'))
        else:
            return render_template("register.html", error=f"Registration failed: {err}")
            
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        res, err = sign_in_user(email, password)
        if res and hasattr(res, 'user') and res.user:
            session['user_id'] = res.user.id
            session['email'] = res.user.email
            return redirect(url_for('dashboard_page'))
        else:
            return render_template("login.html", error=f"Login failed: {err}")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))


# --- Google OAuth Routes ---
@app.route("/auth/google")
def google_login():
    # Use APP_BASE_URL env var in production, fallback to 127.0.0.1 for local dev
    base_url = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000')
    redirect_uri = base_url.rstrip('/') + '/auth/google/callback'
    print(f"[DEBUG] Google redirect_uri: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        if not user_info:
            return redirect(url_for('login_page') + '?error=Google+login+failed')

        google_id = user_info['sub']
        email = user_info['email']
        name = user_info.get('name', '')

        res, err = upsert_google_user(google_id, email, name)
        if res and res.user:
            session['user_id'] = res.user.id
            session['email'] = res.user.email
            return redirect(url_for('dashboard_page'))
        else:
            return render_template('login.html', error=f'Google login failed: {err}')
    except Exception as e:
        print(f'Google callback error: {e}')
        return render_template('login.html', error='Google login failed. Please try again.')

@app.route("/dashboard")
@login_required
def dashboard_page():
    user_id = session.get("user_id")
    scans = get_scan_history(user_id=user_id, limit=50)
    
    # Calculate simple stats for the dashboard
    total_scans = len(scans)
    high_risk = sum(1 for s in scans if s.get('risk_level') == 'HIGH')
    safe_emails = sum(1 for s in scans if s.get('risk_level') == 'SAFE')
    
    stats = {
        "total": total_scans,
        "high_risk": high_risk,
        "safe": safe_emails
    }
    
    return render_template("dashboard.html", scans=scans, stats=stats)


@app.route("/api/scan", methods=["POST"])
def scan_email():
    try:
        email_text = ""

        # Handle .eml file upload
        if "eml_file" in request.files and request.files["eml_file"].filename:
            file = request.files["eml_file"]
            if not file.filename.endswith(".eml"):
                return jsonify({"error": "Only .eml files are supported"}), 400
            email_text = extract_eml_content(file.read())

        # Handle pasted text
        elif request.form.get("email_text"):
            email_text = request.form.get("email_text").strip()

        else:
            return jsonify({"error": "No email content provided"}), 400

        if len(email_text) < 20:
            return jsonify({"error": "Email content too short to analyze"}), 400

        # Step 1: AI analysis
        analysis = analyze_email(email_text)

        # Step 2: URL scanning
        urls = analysis.get("urls_found", [])
        url_results = scan_urls(urls) if urls else []

        # Step 3: Save to Supabase (attached to user if logged in)
        user_id = session.get('user_id')
        save_scan(
            email_preview=email_text[:300],
            risk_level=analysis.get("risk_level", "UNKNOWN"),
            risk_score=analysis.get("risk_score", 0),
            summary=analysis.get("summary", ""),
            red_flags=analysis.get("red_flags", []),
            url_results=url_results,
            action=analysis.get("action_guide", {}).get("primary_action", ""),
            user_id=user_id
        )

        return jsonify({
            "success": True,
            "analysis": analysis,
            "url_results": url_results,
            "is_logged_in": user_id is not None
        })

    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)