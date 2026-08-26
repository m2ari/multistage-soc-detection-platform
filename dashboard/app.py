from flask import Flask, jsonify, send_file
from pathlib import Path
import requests

app = Flask(__name__)

DETECTION_ENGINE_URL = "http://detection-engine:5000"
ATTACK_SIMULATOR_URL = "http://attack-simulator:5000"

@app.route("/")
def dashboard():
    return send_file(Path(__file__).with_name("index.html"))

@app.route("/api/events")
def events():
    try:
        response = requests.get(
            f"{DETECTION_ENGINE_URL}/events",
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({
            "error": "Detection Engine unavailable",
            "details": str(e)
        }), 503

@app.route("/api/incidents")
def incidents():
    try:
        response = requests.get(
            f"{DETECTION_ENGINE_URL}/incidents",
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({
            "error": "Detection Engine unavailable",
            "details": str(e)
        }), 503

@app.route("/api/stats")
def stats():
    try:
        response = requests.get(
            f"{DETECTION_ENGINE_URL}/stats",
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({
            "error": "Detection Engine unavailable",
            "details": str(e)
        }), 503

@app.route("/health")
def health():
    return jsonify({
        "service": "soc-dashboard",
        "status": "healthy"
    }), 200

@app.route("/api/attack/full", methods=["POST"])
def run_full_attack():
    try:
        response = requests.post(
            f"{ATTACK_SIMULATOR_URL}/simulate/multi-stage",
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({
            "status": "error",
            "message": "Attack Simulator unavailable",
            "details": str(e)
        }), 503
        
if __name__ == "__main__":
    print("SOC Dashboard is running on port 5000...", flush=True)
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )