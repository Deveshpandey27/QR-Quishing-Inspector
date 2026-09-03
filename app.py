from flask import Flask, render_template, request, jsonify
from utils.security_rules import analyze_url_security
from utils.ml_model import predict_url


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "No data received."
        }), 400

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "success": False,
            "error": "Please provide a URL."
        }), 400

    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        rule_result = analyze_url_security(url)
        ml_result = predict_url(url)

        rule_score = rule_result["score"]
        ml_score = ml_result["suspicious_probability"]

        # Combine cybersecurity rules + ML
        final_score = round(
            (rule_score * 0.60) +
            (ml_score * 0.40)
        )

        final_score = min(max(final_score, 0), 100)

        # Final classification
        if final_score >= 70:
            status = "dangerous"
            title = "Dangerous QR Code"
            message = "This URL shows strong indicators of phishing or quishing."

        elif final_score >= 40:
            status = "suspicious"
            title = "Suspicious QR Code"
            message = "This URL contains some characteristics commonly associated with suspicious websites."

        else:
            status = "safe"
            title = "Looks Safe"
            message = "No major phishing indicators were detected by this prototype."

        reasons = rule_result["reasons"]

        if ml_score >= 60:
            reasons.append(
                "The machine-learning model considers this URL suspicious."
            )

        if not reasons:
            reasons.append(
                "No significant suspicious indicators were detected."
            )

        return jsonify({
            "success": True,
            "url": url,
            "hostname": rule_result["hostname"],
            "score": final_score,
            "ml_score": round(ml_score),
            "rule_score": rule_score,
            "status": status,
            "title": title,
            "message": message,
            "reasons": reasons
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )