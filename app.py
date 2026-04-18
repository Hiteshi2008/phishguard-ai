"""
PhishGuard AI — Flask Backend
POST /api/scan  →  { prediction, result, confidence, reasons, email_sent, url }
GET  /api/health → { status, model }
"""

import os, re, time, pickle, smtplib
import numpy as np
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {
    "origins": "*",
    "allow_headers": ["Content-Type"],
    "methods": ["GET", "POST", "OPTIONS"],
}})

# ── Email config (set via env or edit defaults) ───────────────────────────────
EMAIL_SENDER   = os.environ.get("EMAIL_SENDER",   "hiteshikadian20@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "xasm oddi bbmy nzzm")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER", "hiteshikadian20@gmail.com")
SMTP_HOST, SMTP_PORT = "smtp.gmail.com", 587

# Per-URL email cooldown (5 min)
_email_sent: dict[str, float] = {}
EMAIL_COOLDOWN = 300

# ── Load model ────────────────────────────────────────────────────────────────
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
try:
    with open(_MODEL_PATH, "rb") as f:
        _model = pickle.load(f)
    print(f"[PhishGuard] Model loaded from {_MODEL_PATH}")
except FileNotFoundError:
    _model = None
    print("[PhishGuard] No model file found — using heuristic fallback.")

# ── Phishing keywords ─────────────────────────────────────────────────────────
KEYWORDS = [
    "login","signin","verify","secure","account","update","confirm",
    "banking","password","credential","paypal","ebay","amazon","apple",
    "google","microsoft","support","alert","suspend","click","free",
    "prize","winner","urgent","limited","offer","gift","claim",
]

# ── Feature extraction (12 features) ─────────────────────────────────────────
def extract_features(url: str) -> tuple[list[float], list[str]]:
    """
    Returns (feature_vector, reasons_list).
    12 features:
      0  url_length
      1  dot_count
      2  hyphen_count
      3  slash_count
      4  at_count
      5  question_count
      6  equals_count
      7  digit_count
      8  uses_https          (1=yes)
      9  keyword_count
      10 subdomain_depth
      11 tld_suspicious      (1 if TLD is in known-bad list)
    """
    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    full     = url.lower()
    reasons  = []

    url_len        = len(url)
    dot_count      = url.count(".")
    hyphen_count   = url.count("-")
    slash_count    = url.count("/")
    at_count       = url.count("@")
    question_count = url.count("?")
    equals_count   = url.count("=")
    digit_count    = sum(c.isdigit() for c in url)
    uses_https     = 1 if parsed.scheme == "https" else 0
    keyword_count  = sum(1 for kw in KEYWORDS if kw in full)

    labels          = hostname.replace("www.", "").split(".")
    subdomain_depth = max(0, len(labels) - 2)

    SUSPICIOUS_TLDS = {".xyz",".tk",".ml",".ga",".cf",".gq",".top",
                       ".pw",".cc",".info",".biz",".click",".link",".work"}
    tld_suspicious = 1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0

    # Build human-readable reasons for UI
    if url_len > 75:
        reasons.append(f"Unusually long URL ({url_len} chars)")
    if at_count:
        reasons.append("Contains @ symbol (credential redirect risk)")
    if hyphen_count > 3:
        reasons.append(f"Excessive hyphens ({hyphen_count}) — common in spoofed domains")
    if subdomain_depth > 2:
        reasons.append(f"Deep subdomain nesting (depth {subdomain_depth})")
    if keyword_count >= 2:
        reasons.append(f"Contains {keyword_count} phishing keyword(s)")
    if not uses_https:
        reasons.append("No HTTPS — plain HTTP connection")
    if digit_count > 8:
        reasons.append(f"High digit count ({digit_count}) — often used to obscure domains")
    if tld_suspicious:
        reasons.append(f"Suspicious TLD detected")
    if dot_count > 5:
        reasons.append(f"Many dots ({dot_count}) — possible subdomain abuse")

    features = [
        url_len, dot_count, hyphen_count, slash_count,
        at_count, question_count, equals_count, digit_count,
        uses_https, keyword_count, subdomain_depth, tld_suspicious,
    ]
    return features, reasons


# ── Heuristic fallback ────────────────────────────────────────────────────────
def heuristic(features: list) -> tuple[int, float]:
    (url_len, dot_count, hyphen_count, slash_count,
     at_count, question_count, equals_count, digit_count,
     uses_https, keyword_count, subdomain_depth, tld_suspicious) = features

    score = 0
    if url_len > 75:         score += 2
    if url_len > 100:        score += 2
    if at_count:             score += 4
    if hyphen_count > 3:     score += 2
    if subdomain_depth > 2:  score += 2
    if keyword_count >= 2:   score += 3
    if keyword_count >= 4:   score += 2
    if not uses_https:       score += 1
    if digit_count > 8:      score += 1
    if dot_count > 5:        score += 2
    if tld_suspicious:       score += 3

    MAX_SCORE = 24
    confidence = min(score / MAX_SCORE, 0.99)
    prediction = 1 if score >= 5 else 0
    if prediction == 0:
        confidence = round(1.0 - confidence, 4)
    else:
        confidence = round(confidence, 4)
    return prediction, confidence


# ── Email alert ───────────────────────────────────────────────────────────────
def send_alert(url: str, confidence: float, reasons: list) -> bool:
    now = time.time()
    if now - _email_sent.get(url, 0) < EMAIL_COOLDOWN:
        print(f"[Email] Cooldown active for {url}")
        return False
    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = "🚨 PhishGuard: Phishing URL Detected"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER

        reasons_html = "".join(f"<li>{r}</li>" for r in reasons) if reasons else "<li>Heuristic flags triggered</li>"
        html = f"""
<html><body style="font-family:monospace;background:#0a0c10;color:#cdd6e8;padding:24px;">
  <div style="max-width:600px;margin:auto;background:#141a24;border:1px solid #ff2050;
              border-radius:8px;padding:28px;">
    <h2 style="color:#ff2050;margin:0 0 16px;font-family:sans-serif;">
      ⚠️ Phishing URL Detected
    </h2>
    <p style="margin-bottom:8px;color:#7a8ba0;font-size:12px;">FLAGGED URL</p>
    <div style="background:#0a0c10;border:1px solid #253040;border-radius:4px;
                padding:12px;word-break:break-all;color:#ff2050;margin-bottom:16px;">
      {url}
    </div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
      <tr>
        <td style="padding:8px;color:#7a8ba0;font-size:12px;">CONFIDENCE</td>
        <td style="padding:8px;color:#ff2050;font-weight:bold;">{round(confidence*100,1)}%</td>
      </tr>
      <tr style="background:#0c1018;">
        <td style="padding:8px;color:#7a8ba0;font-size:12px;">DETECTED AT</td>
        <td style="padding:8px;">{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</td>
      </tr>
    </table>
    <p style="color:#7a8ba0;font-size:12px;margin-bottom:8px;">THREAT INDICATORS</p>
    <ul style="color:#cdd6e8;font-size:13px;line-height:1.8;padding-left:20px;">
      {reasons_html}
    </ul>
    <p style="margin-top:20px;color:#3d4f62;font-size:11px;">
      Sent by PhishGuard AI — Do NOT visit this URL.
    </p>
  </div>
</body></html>"""

        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo(); s.starttls()
            s.login(EMAIL_SENDER, EMAIL_PASSWORD)
            s.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        _email_sent[url] = now
        print(f"[Email] Alert sent for {url}")
        return True
    except Exception as e:
        print(f"[Email] Failed: {e}")
        return False


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    raw = str(body["url"]).strip()
    if not raw:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Normalise
    url = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw

    try:
        features, reasons = extract_features(url)

        if _model is not None:
            arr        = np.array(features).reshape(1, -1)
            prediction = int(_model.predict(arr)[0])
            proba      = _model.predict_proba(arr)[0]
            confidence = round(float(max(proba)), 4)
        else:
            prediction, confidence = heuristic(features)

        result     = "PHISHING" if prediction == 1 else "SAFE"
        email_sent = False

        if prediction == 1:
            email_sent = send_alert(url, confidence, reasons)

        return jsonify({
            "url":        url,
            "prediction": prediction,
            "result":     result,
            "confidence": confidence,
            "reasons":    reasons if prediction == 1 else [],
            "email_sent": email_sent,
        })

    except Exception as e:
        print(f"[Error] Scan failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model":  "RandomForest" if _model else "heuristic-fallback",
        "version": "2.0",
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
