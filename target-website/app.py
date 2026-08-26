from flask import (Flask,send_file,jsonify,request,session)
from datetime import datetime, timezone
import requests
import os

app = Flask(__name__)

app.secret_key = "terrahomes_local_demo_secret"
DETECTION_ENGINE_URL = os.getenv(
    "DETECTION_ENGINE_URL",
    "http://soc-detection-engine:5000/events"
)

USERS = {
    "admin": {
        "email": "admin@terrahomes.local",
        "password": "Admin123!",
        "role": "admin"
    },

    "user": {
        "email": "user@terrahomes.local",
        "password": "User123!",
        "role": "user"
    },

    "sara": {
        "email": "sara@terrahomes.local",
        "password": "Sara123!",
        "role": "user"
    }
}

def forward_security_event(event_type, username):
    event = {
        "event_type": event_type,
        "username": username,
        "source": request.remote_addr,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }
    try:
        response = requests.post(
            DETECTION_ENGINE_URL,
            json=event,
            timeout=5
        )
        print(
            f"EVENT FORWARDED | "
            f"{event_type} | "
            f"user={username} | "
            f"status={response.status_code}",
            flush=True
        )
        return True
    except requests.RequestException as error:
        print(
            f"EVENT FORWARD FAILED | "
            f"{event_type} | "
            f"user={username} | "
            f"error={error}",
            flush=True
        )
        return False
def send_security_event(
    event_type,
    username,
    source
):
    event = {
        "event_type": event_type,
        "username": username,
        "source": source,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }
    try:
        response = requests.post(
            DETECTION_ENGINE_URL,
            json=event,
            timeout=5
        )
        print(
            f"EVENT FORWARDED | "
            f"{event_type} | "
            f"user={username} | "
            f"status={response.status_code}",
            flush=True
        )
        return True
    except Exception as e:
        print(
            f"EVENT FORWARDING ERROR | "
            f"{event_type} | "
            f"user={username} | "
            f"error={e}",
            flush=True
        )
        return False

@app.route("/")
def home():
    return send_file(
        "/app/index.html"
    )

@app.route("/health")
def health():
    return jsonify({
        "service": "target-website",
        "status": "healthy"
    }), 200

@app.route(
    "/login",
    methods=["POST"]
)
def login():
    data = request.get_json(
        silent=True)
    if not data:
        return jsonify({"status": "error","message": "Invalid request"}), 400
    identifier = data.get("username","").strip().lower()
    password = data.get("password","")
    source = request.remote_addr
    matched_username = None
    user = None
    for username, user_data in USERS.items():
        if (username.lower() == identifier or user_data.get("email","").lower() == identifier):
            matched_username = username
            user = user_data
            break
    if (not user or user["password"] != password):
        print(f"FAILED_LOGIN | " f"identifier={identifier}", flush=True)
        send_security_event(
            "FAILED_LOGIN",
            matched_username or identifier,
            source
        )
        return jsonify({"status": "failed", "message": "Invalid username/email or password"}), 401
    session["username"] = matched_username
    session["email"] = user.get("email")
    session["role"] = user["role"]
    print(f"SUCCESSFUL_LOGIN | " f"user={matched_username} | " f"email={user.get('email')} | "
        f"role={user['role']}", flush=True)
    send_security_event( "SUCCESSFUL_LOGIN", matched_username, source)
    return jsonify({"status": "success", "message": "Login successful", "username": matched_username,
        "email": user.get("email"), "role": user["role"]}), 200

@app.route(
    "/api/privilege-escalation",
    methods=["POST"]
)
def privilege_escalation():
    if "username" not in session:
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401
    username = session["username"]
    current_role = session.get(
        "role",
        "user"
    )
    if current_role != "admin":
        print(
            f"PRIVILEGE_ESCALATION | "
            f"user={username} | "
            f"from_role={current_role} | "
            f"to_role=admin",
            flush=True
        )
        session["role"] = "admin"
        forward_security_event(
            "PRIVILEGE_ESCALATION",
            username
        )
        return jsonify({
            "status": "success",
            "message": "Privilege escalation simulated",
            "username": username,
            "role": "admin"
        }), 200
    return jsonify({
        "status": "info",
        "message": "User already has admin privileges"
    }), 200

@app.route(
    "/api/sensitive-file",
    methods=["GET"]
)
def sensitive_file_access():
    if "username" not in session:
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401
    username = session["username"]
    print(
        f"SENSITIVE_FILE_ACCESS | "
        f"user={username}",
        flush=True
    )
    forward_security_event(
        "SENSITIVE_FILE_ACCESS",
        username
    )
    return jsonify({
        "status": "success",
        "message": "Sensitive file accessed",
        "file": "confidential_financial_data.txt"
    }), 200

@app.route("/logout")
def logout():
    username = session.get(
        "username"
    )
    session.clear()
    print(
        f"LOGOUT | "
        f"user={username}",
        flush=True
    )
    return jsonify({
        "status": "success",
        "message": "Logged out successfully"
    }), 200

@app.route("/api/session")
def get_session():
    if "username" not in session:
        return jsonify({
            "authenticated":
                False}), 200
    return jsonify({
        "authenticated":
            True,
        "username":
            session.get("username"),
        "email":
            session.get("email"),
        "role":
          session.get("role")}), 200

@app.route("/admin-panel")
def admin_panel():
    if "username" not in session:
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401
    username = session.get("username")
    role = session.get("role")
    if role != "admin":
        print(
            f"PRIVILEGE_ESCALATION | user={username} | attempted_role=admin",
            flush=True
        )
        forward_security_event(
            "PRIVILEGE_ESCALATION",
            username
        )
        return jsonify({
            "status": "denied",
            "message": "Unauthorized access attempt detected"
        }), 403
    return jsonify({
        "status": "success",
        "message": "Welcome to the admin panel",
        "username": username,
        "role": role
    }), 200

@app.route("/sensitive-file")
def sensitive_file():
    if "username" not in session:
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401
    username = session.get("username")
    role = session.get("role")
    print(
        f"SENSITIVE_FILE_ACCESS | user={username} | file=financial_records.txt",
        flush=True
    )
    forward_security_event(
        "SENSITIVE_FILE_ACCESS",
        username
    )
    if role != "admin":
        return jsonify({
            "status": "denied",
            "message": "Access to sensitive file denied"
        }), 403
    return jsonify({
        "status": "success",
        "message": "Sensitive file accessed",
        "file": "financial_records.txt"
    }), 200

if __name__ == "__main__":
    print(
        "Target Website is running on port 5000...",
        flush=True
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )