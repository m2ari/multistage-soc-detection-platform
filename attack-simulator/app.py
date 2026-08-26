from flask import Flask, jsonify
import threading
import time
import requests

app = Flask(__name__)

TARGET_SYSTEM_URL = "http://soc-target-system:5000"
SIMULATED_USERNAME = "test_user"
SIMULATED_SOURCE = "192.168.1.50"

def send_login_attempt(password):
    payload = {
        "username": SIMULATED_USERNAME,
        "password": password,
        "source": SIMULATED_SOURCE
    }
    try:
        response = requests.post(
            f"{TARGET_SYSTEM_URL}/login",
            json=payload,
            timeout=5
        )
        print(
            f"Login attempt | "
            f"Status: {response.status_code} | "
            f"Response: {response.text}",
            flush=True
        )
        return response.status_code
    except requests.exceptions.RequestException as error:
        print(
            f"Failed to connect to Target System: {error}",
            flush=True
        )
        return 500

def send_privilege_escalation():
    payload = {
        "username": SIMULATED_USERNAME,
        "source": SIMULATED_SOURCE
    }
    try:
        response = requests.post(
            f"{TARGET_SYSTEM_URL}/privilege-escalation",
            json=payload,
            timeout=5
        )
        print(
            f"Privilege escalation event | "
            f"Status: {response.status_code}",
            flush=True
        )
        return response.status_code
    except requests.exceptions.RequestException as error:
        print(
            f"Failed to generate privilege escalation event: {error}",
            flush=True
        )
        return 500

def send_sensitive_file_access():
    try:
        response = requests.get(
            f"{TARGET_SYSTEM_URL}/sensitive-file",
            params={
                "username": SIMULATED_USERNAME,
                "source": SIMULATED_SOURCE
            },
            timeout=5
        )
        print(
            f"Sensitive file access event | "
            f"Status: {response.status_code}",
            flush=True
        )
        return response.status_code
    except requests.exceptions.RequestException as error:

        print(
            f"Failed to generate sensitive file event: {error}",
            flush=True
        )
        return 500

def run_attack_simulation():
    print(
        "==========================================",
        flush=True
    )
    print(
        "Starting Multi-Stage Attack Simulation",
        flush=True
    )
    print(
        "==========================================",
        flush=True
    )
    for attempt in range(5):
        print(
            f"[Stage 1] Failed login {attempt + 1}/5",
            flush=True
        )
        send_login_attempt(
            "wrong_password"
        )
        time.sleep(1)
    print(
        "[Stage 2] Successful login",
        flush=True
    )
    send_login_attempt(
        "correct_password"
    )
    time.sleep(2)
    print(
        "[Stage 3] Privilege escalation",
        flush=True
    )
    send_privilege_escalation()
    time.sleep(2)
    print(
        "[Stage 4] Sensitive file access",
        flush=True
    )
    send_sensitive_file_access()
    print(
        "==========================================",
        flush=True
    )
    print(
        "Multi-Stage Attack Simulation Completed",
        flush=True
    )
    print(
        "==========================================",
        flush=True
    )

@app.route("/health")
def health():
    return jsonify({
        "service": "attack-simulator",
        "status": "healthy"
    }), 200

@app.route("/simulate/multi-stage", methods=["POST"])
def simulate_multi_stage():
    attack_thread = threading.Thread(
        target=run_attack_simulation,
        daemon=True
    )
    attack_thread.start()
    return jsonify({
        "status": "started",
        "message": "Multi-stage attack simulation started"
    }), 202

if __name__ == "__main__":
    print(
        "SOC Attack Simulator API is running...",
        flush=True
    )
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )