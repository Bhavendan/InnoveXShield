from feature import FeatureExtraction
from email_analyzer import investigate_email, analyze_single_url
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
import numpy as np
import pickle
import os
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Load trained Gradient Boosting Classifier model
model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
if not os.path.exists(model_path):
    model_path = os.path.join(os.path.dirname(__file__), "pickle", "model.pkl")

with open(model_path, "rb") as f:
    gbc = pickle.load(f)
print(f"[InnoveXShield] Successfully loaded trained ML model from {model_path}")

def predict_url_safety(url):
    if not url or not url.strip():
        return 0.0
    url = url.strip()
    try:
        fe = FeatureExtraction(url)
        features = fe.getFeaturesList()
        probs = gbc.predict_proba([features])[0]
        # classes: [-1, 1] where 1 is Legitimate (index 1)
        safe_prob = round(float(probs[1]), 4)
        return safe_prob
    except Exception as e:
        print(f"[InnoveXShield] Error predicting for {url}: {e}")
        return 0.50

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Check if email investigation form was submitted
        if "email_body" in request.form or "email_subject" in request.form:
            email_data = {
                "sender": request.form.get("email_sender", ""),
                "subject": request.form.get("email_subject", ""),
                "body": request.form.get("email_body", ""),
                "html": request.form.get("email_html", "")
            }
            investigation = investigate_email(email_data, gbc)
            return render_template("index.html", investigation=investigation, active_tab="email")

        # URL Scanner form submission
        if request.is_json:
            data = request.get_json() or {}
            url = data.get("url", "")
        else:
            url = request.form.get("url", "")

        xx = predict_url_safety(url)
        print(f"[Prediction] URL: {url} -> Safety Score: {xx}")

        is_browser_nav = (
            request.headers.get("Sec-Fetch-Dest") == "document" or
            ("text/html" in request.headers.get("Accept", "") and request.headers.get("Sec-Fetch-Dest") != "empty")
        )
        if is_browser_nav:
            url_analysis = analyze_single_url(url, "", gbc) if url else None
            return render_template("index.html", xx=xx, url=url, url_analysis=url_analysis, active_tab="url")

        return jsonify(xx)

    return render_template("index.html", xx="", url="", active_tab="email")

@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    try:
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form.to_dict()

        result = investigate_email(data, gbc)
        return jsonify(result)
    except Exception as e:
        print(f"Error in api_analyze_email: {e}")
        return jsonify({
            "emailVerdict": "SUSPICIOUS",
            "confidence": 50,
            "riskLevel": "MEDIUM",
            "overallRiskScore": 50,
            "senderAnalysis": {"email": "", "domain": "", "suspicious": False, "reasons": []},
            "detectedLinks": [],
            "indicators": ["Error parsing email payload"],
            "reasons": [str(e)],
            "explanation": f"Investigation failed with error: {str(e)}"
        }), 400

@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    try:
        if request.is_json:
            data = request.get_json() or {}
            url = data.get("url", "")
            anchor = data.get("anchorText", "")
        else:
            url = request.form.get("url", "")
            anchor = request.form.get("anchorText", "")

        analysis = analyze_single_url(url, anchor, gbc)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/predict", methods=["POST"])
def predict():
    if request.is_json:
        data = request.get_json() or {}
        url = data.get("url", "")
    else:
        url = request.form.get("url", "")

    xx = predict_url_safety(url)
    return jsonify({
        "url": url,
        "safe_score": xx,
        "is_safe": bool(xx >= 0.50),
        "label": "Safe" if xx >= 0.50 else "Unsafe/Phishing"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"Starting Phishing Attack Detection Server on http://127.0.0.1:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=True)

