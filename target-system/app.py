from flask import Flask, request, jsonify
import requests
from datetime import datetime

app = Flask(__name__)

DETECTION_ENGINE_URL = "http://soc-detection-engine:5000/events"

def send_security_event(event_type, username, source):
    event = {
        "event_type": event_type,
        "username": username,
        "source": source,
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        response = requests.post(
            DETECTION_ENGINE_URL,
            json=event,
            timeout=3
        )
        print(
            f"Sent event: {event_type} | "
            f"Detection Engine response: {response.status_code}",
            flush=True
        )
    except requests.exceptions.RequestException as error:
        print(
            f"Failed to send event to Detection Engine: {error}",
            flush=True
        )

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "soc-target-system",
        "status": "healthy"
    }), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "unknown")
    password = data.get("password", "")
    source = data.get("source", request.remote_addr)
    if password == "correct_password":
        send_security_event(
            "SUCCESSFUL_LOGIN",
            username,
            source
        )
        return jsonify({
            "status": "login_successful"
        }), 200
    send_security_event(
        "FAILED_LOGIN",
        username,
        source
    )
    return jsonify({
        "status": "login_failed"
    }), 401

@app.route("/privilege-escalation", methods=["POST"])
def privilege_escalation():
    data = request.get_json() or {}
    username = data.get("username", "unknown")
    source = data.get("source", request.remote_addr)
    send_security_event(
        "PRIVILEGE_ESCALATION",
        username,
        source
    )
    return jsonify({
        "status": "privilege_escalation_detected"
    }), 200

@app.route("/sensitive-file", methods=["GET"])
def sensitive_file():
    username = request.args.get("username", "unknown")
    source = request.args.get("source", request.remote_addr)
    send_security_event(
        "SENSITIVE_FILE_ACCESS",
        username,
        source
    )
    return jsonify({
        "status": "sensitive_file_access_detected"
    }), 200

if __name__ == "__main__":
    print(
        "SOC Target System is running on port 5000...",
        flush=True
    )
    app.run(
        host="0.0.0.0",
        port=5000
    )