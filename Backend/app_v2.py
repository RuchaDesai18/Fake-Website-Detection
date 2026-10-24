from flask import Flask, request, jsonify
from detector_v2 import analyze_url, load
app = Flask(__name__)
ALLOWED_ORIGINS = {"http://127.0.0.1:8000", "http://localhost:8000"}   # restrict CORS to the local frontend
@app.after_request
def cors(resp):
    o = request.headers.get("Origin")
    if o in ALLOWED_ORIGINS: resp.headers["Access-Control-Allow-Origin"] = o
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"; resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp
@app.get("/")
def home(): return jsonify({"service": "FraudShield URL Detector v2", "status": "running", "endpoint": "POST /detect_url"})
@app.route("/detect_url", methods=["POST", "OPTIONS"])
def detect_url():
    if request.method == "OPTIONS": return ("", 204)
    url = str((request.get_json(silent=True) or {}).get("url", "")).strip()
    if not url: return jsonify({"error": "Please provide a URL in JSON: {'url': 'https://example.com'}"}), 400
    if len(url) > 2048: return jsonify({"error": "URL too long (max 2048 characters)."}), 400
    try: return jsonify(analyze_url(url))
    except ValueError as e: return jsonify({"error": str(e)}), 400
    except Exception: app.logger.exception("analysis failed"); return jsonify({"error": "URL analysis failed. Check that fraudshield_v2.pkl exists (run train_v2.py)."}), 500
if __name__ == "__main__":
    load(); app.run(host="127.0.0.1", port=5001, debug=False)
