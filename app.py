from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os

from utils.ai_analyzer import analyze_email, extract_eml_content
from utils.url_scanner import scan_urls
from utils.db import save_scan, get_scan_history

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "phishguard-dev-secret")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze")
def analyze_page():
    return render_template("analyze.html")


@app.route("/history")
def history_page():
    scans = get_scan_history(limit=20)
    return render_template("history.html", scans=scans)


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

        # Step 3: Save to Supabase
        save_scan(
            email_preview=email_text[:300],
            risk_level=analysis.get("risk_level", "UNKNOWN"),
            risk_score=analysis.get("risk_score", 0),
            summary=analysis.get("summary", ""),
            red_flags=analysis.get("red_flags", []),
            url_results=url_results,
            action=analysis.get("action_guide", {}).get("primary_action", "")
        )

        return jsonify({
            "success": True,
            "analysis": analysis,
            "url_results": url_results
        })

    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)