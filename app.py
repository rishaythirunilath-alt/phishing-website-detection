from flask import Flask, render_template, request
import re

app = Flask(__name__)

def check_url_security(url):
    score = 0

    # Check HTTPS
    if url.startswith("https://"):
        score += 30

    # Check @ symbol
    if "@" not in url:
        score += 20

    # Check URL length
    if len(url) < 75:
        score += 20

    # Check IP address in URL
    ip_pattern = r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}"
    if not re.search(ip_pattern, url):
        score += 30

    return score

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    status = ""
    risk_score = 0
    details = []
    url = None

    if request.method == "POST":
        url = request.form["url"]
        percentage = check_url_security(url)

        if percentage >= 60:
            result = "Safe"
            status = "safe"
            risk_score = 100 - percentage
            details = ["No major phishing indicators detected."]
        else:
            result = "Unsafe"
            status = "unsafe"
            risk_score = percentage
            details = ["Suspicious URL structure detected."]

    return render_template("index.html",
                           result=result,
                           status=status,
                           risk_score=risk_score,
                           details=details,
                           url=url)
if __name__ == "__main__":
    app.run(debug=True)

