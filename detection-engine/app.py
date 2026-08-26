from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import os
import json

app = Flask(__name__)

DATABASE_CONFIG = {
    "host": os.getenv("DB_HOST", "postgres"),
    "database": os.getenv("DB_NAME", "soc_platform"),
    "user": os.getenv("DB_USER", "soc_user"),
    "password": os.getenv("DB_PASSWORD", "soc_secure_password"),
    "port": os.getenv("DB_PORT", "5432")
}

def get_db_connection():
    return psycopg2.connect(**DATABASE_CONFIG)

def initialize_database():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            username VARCHAR(100),
            source VARCHAR(100),
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            received_at TIMESTAMP WITH TIME ZONE NOT NULL,
            event_data JSONB
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_incidents (
            id SERIAL PRIMARY KEY,
            incident_id VARCHAR(50) UNIQUE NOT NULL,
            incident_type VARCHAR(100),
            severity VARCHAR(50),
            username VARCHAR(100),
            source VARCHAR(100),
            status VARCHAR(50),
            created_at TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE,
            incident_data JSONB
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()
    print(
        "PostgreSQL database initialized successfully.",
        flush=True
    )

def save_event_to_database(event):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO security_events
            (
                event_type,
                username,
                source,
                timestamp,
                received_at,
                event_data
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                event.get("event_type"),
                event.get("username"),
                event.get("source"),
                event.get("timestamp"),
                event.get("received_at"),
                json.dumps(event)
            )
        )
        connection.commit()
        cursor.close()
        connection.close()
        print(
            f"DATABASE: Event saved successfully | "
            f"{event.get('event_type')} | "
            f"user={event.get('username')}",
            flush=True
        )
    except Exception as e:
        print(
            f"DATABASE ERROR: Failed to save event: {e}",
            flush=True
        )

def save_incident_to_database(incident):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO security_incidents
        (
            incident_id,
            incident_type,
            severity,
            username,
            source,
            status,
            created_at,
            updated_at,
            incident_data
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (incident_id)
        DO UPDATE SET
            incident_type = EXCLUDED.incident_type,
            severity = EXCLUDED.severity,
            status = EXCLUDED.status,
            updated_at = EXCLUDED.updated_at,
            incident_data = EXCLUDED.incident_data
    """, (
        incident["incident_id"],
        incident["incident_type"],
        incident["severity"],
        incident["username"],
        incident["source"],
        incident["status"],
        incident["created_at"],
        incident["updated_at"],
        Json(incident)
    ))
    connection.commit()
    cursor.close()
    connection.close()
received_events = []
detected_incidents = []
FAILED_LOGIN_THRESHOLD = 5
CORRELATION_WINDOW_SECONDS = 60
ATTACK_STAGE_ORDER = {
    "Brute Force": 1,
    "Successful Login": 2,
    "Privilege Escalation": 3,
    "Sensitive Data Access": 4
}
def utc_now():
    return datetime.now(timezone.utc)

def normalize_datetime(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.replace("Z", "+00:00")
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)    

def parse_timestamp(timestamp):
    return normalize_datetime(timestamp)

def get_related_events(username, source, current_time):
    current_time = normalize_datetime(current_time)
    window_start = current_time - timedelta(
        seconds=CORRELATION_WINDOW_SECONDS
    )
    window_end = current_time + timedelta(
        seconds=CORRELATION_WINDOW_SECONDS
    )
    related_events = []
    for event in received_events:
        if event.get("username") != username:
            continue
        if event.get("source") != source:
            continue
        event_timestamp = event.get("timestamp")
        if not event_timestamp:
            continue
        event_time = normalize_datetime(event_timestamp)
        if window_start <= event_time <= window_end:
            related_events.append(event)
    return related_events

def find_existing_incident(username, source, current_time):
    current_time = normalize_datetime(current_time)
    for incident in reversed(detected_incidents):
        if (
            incident["username"] == username
            and incident["source"] == source
            and incident["status"] == "OPEN"
        ):
            incident_updated_at = normalize_datetime(
                incident["updated_at"]
            )
            time_difference = (
                current_time - incident_updated_at
            ).total_seconds()
            if time_difference <= CORRELATION_WINDOW_SECONDS:
                return incident
    return None

def remove_duplicate_stages(incident):
    stages_by_name = {}
    for stage in incident["attack_stages"]:
        stages_by_name[stage["stage"]] = stage
    incident["attack_stages"] = sorted(
        stages_by_name.values(),
        key=lambda stage: ATTACK_STAGE_ORDER.get(
            stage["stage"],
            len(ATTACK_STAGE_ORDER) + 1
        )
    )

def get_next_incident_id():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
        """)
        incident_count = cursor.fetchone()[0]
        return f"INC-{incident_count + 1:03}"
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def create_incident(username, source):
    incident = {
        "incident_id": get_next_incident_id(),
        "incident_type": "SUSPICIOUS_LOGIN_SEQUENCE",
        "severity": "HIGH",
        "username": username,
        "source": source,
        "status": "OPEN",
        "created_at": utc_now().isoformat(),
        "updated_at": utc_now().isoformat(),
        "attack_stages": [],
        "timeline": [],
        "mitre_attack": []
    }
    detected_incidents.append(incident)
    save_incident_to_database(incident)
    print(
        f"INCIDENT CREATED: "
        f"{incident['incident_id']} | "
        f"SUSPICIOUS_LOGIN_SEQUENCE",
        flush=True
    )
    return incident

def add_stage(incident, stage, event, count, mitre_id):
    existing_stage = next(
        (
            existing
            for existing in incident["attack_stages"]
            if existing["stage"] == stage
        ),
        None
    )
    stage_data = {
        "stage": stage,
        "event": event,
        "count": count,
        "mitre_id": mitre_id
    }
    if existing_stage is None:
        incident["attack_stages"].append(stage_data)
    else:
        existing_stage.update(stage_data)
    remove_duplicate_stages(incident)

def create_or_update_incident(current_event):
    username = current_event["username"]
    source = current_event["source"]
    current_time = parse_timestamp(
        current_event["timestamp"]
    )
    related_events = get_related_events(
        username,
        source,
        current_time
    )
    event_types = [
        event["event_type"]
        for event in related_events
    ]
    failed_login_count = event_types.count(
        "FAILED_LOGIN"
    )
    has_successful_login = (
        "SUCCESSFUL_LOGIN" in event_types
    )
    has_privilege_escalation = (
        "PRIVILEGE_ESCALATION" in event_types
    )
    has_sensitive_file_access = (
        "SENSITIVE_FILE_ACCESS" in event_types
    )
    incident = find_existing_incident(
        username,
        source,
        current_time
    )
    if (
        failed_login_count >= FAILED_LOGIN_THRESHOLD
        and has_successful_login
    ):
        if incident is None:
            incident = create_incident(
                username,
                source
            )
        add_stage(
            incident,
            "Brute Force",
            "FAILED_LOGIN",
            failed_login_count,
            "T1110"
        )
        add_stage(
            incident,
            "Successful Login",
            "SUCCESSFUL_LOGIN",
            1,
            "T1078"
        )
        incident["updated_at"] = utc_now().isoformat()
    if incident is not None and has_privilege_escalation:
        add_stage(
            incident,
            "Privilege Escalation",
            "PRIVILEGE_ESCALATION",
            1,
            "T1548"
        )
        incident["updated_at"] = utc_now().isoformat()
        print(
            f"ATTACK STAGE DETECTED: "
            f"{incident['incident_id']} | "
            f"PRIVILEGE_ESCALATION",
            flush=True
        )
    if incident is not None and has_sensitive_file_access:
        add_stage(
            incident,
            "Sensitive Data Access",
            "SENSITIVE_FILE_ACCESS",
            1,
            "T1005"
        )
        incident["updated_at"] = utc_now().isoformat()
        print(
            f"ATTACK STAGE DETECTED: "
            f"{incident['incident_id']} | "
            f"SENSITIVE_FILE_ACCESS",
            flush=True
        )
    if incident is not None:
        remove_duplicate_stages(incident)
        save_incident_to_database(incident)
    if (
        incident is not None
        and failed_login_count >= FAILED_LOGIN_THRESHOLD
        and has_successful_login
        and has_privilege_escalation
        and has_sensitive_file_access
    ):
        incident["incident_type"] = "MULTI_STAGE_ATTACK"
        incident["severity"] = "CRITICAL"
        incident["timeline"] = [
            {
                "stage": "1",
                "name": "Brute Force",
                "event": "FAILED_LOGIN",
                "description": (
                    f"{failed_login_count} failed "
                    f"login attempts detected."
                )
            },
            {
                "stage": "2",
                "name": "Successful Login",
                "event": "SUCCESSFUL_LOGIN",
                "description": (
                    "Authentication succeeded after "
                    "repeated failures."
                )
            },
            {
                "stage": "3",
                "name": "Privilege Escalation",
                "event": "PRIVILEGE_ESCALATION",
                "description": (
                    "Suspicious privilege escalation "
                    "activity detected."
                )
            },
            {
                "stage": "4",
                "name": "Sensitive File Access",
                "event": "SENSITIVE_FILE_ACCESS",
                "description": (
                    "Access to a sensitive resource "
                    "was detected."
                )
            }
        ]
        incident["mitre_attack"] = [
            {
                "technique": "T1110",
                "name": "Brute Force"
            },
            {
                "technique": "T1078",
                "name": "Valid Accounts"
            },
            {
                "technique": "T1548",
                "name": "Abuse Elevation Control Mechanism"
            },
            {
                "technique": "T1005",
                "name": "Data from Local System"
            }
        ]
        incident["updated_at"] = utc_now().isoformat()
        print(
            f"MULTI-STAGE ATTACK DETECTED: "
            f"{incident['incident_id']} | "
            f"CRITICAL",
            flush=True
        )
        save_incident_to_database(incident)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "soc-detection-engine",
        "status": "healthy"
    }), 200

@app.route("/events", methods=["POST"])
def receive_event():
    event = request.get_json(silent=True)
    if not event:
        return jsonify({
            "error": "Invalid event"
        }), 400
    if event.get("timestamp"):
        event["timestamp"] = normalize_datetime(
            event["timestamp"]
        ).isoformat()
    event["received_at"] = datetime.now(timezone.utc).isoformat()
    required_fields = [
        "event_type",
        "username",
        "source",
        "timestamp"
    ]
    missing_fields = [
        field
        for field in required_fields
        if field not in event
    ]
    if missing_fields:
        return jsonify({
            "error": "Missing required fields",
            "fields": missing_fields
        }), 400
    event["received_at"] = utc_now().isoformat()
    received_events.append(event)
    save_event_to_database(event)
    print(
        f"Received security event: "
        f"{event['event_type']} | "
        f"user={event['username']} | "
        f"source={event['source']}",
        flush=True
    )
    create_or_update_incident(event)
    return jsonify({
        "status": "event_received",
        "event": event
    }), 201

@app.route("/events", methods=["GET"])
def get_events():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                event_type,
                username,
                source,
                timestamp,
                received_at
            FROM security_events
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        events = []
        for row in rows:
            events.append({
                "event_type": row[0],
                "username": row[1],
                "source": row[2],
                "timestamp": (
                    row[3].isoformat()
                    if row[3] is not None
                    else None
                ),
                "received_at": (
                    row[4].isoformat()
                    if row[4] is not None
                    else None
                )
            })
        return jsonify({
            "count": len(events),
            "events": events
        }), 200
    except Exception as e:
        print(
            f"DATABASE ERROR: Failed to read events: {e}",
            flush=True
        )
        return jsonify({
            "error": "Failed to read events from database",
            "details": str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route("/incidents", methods=["GET"])
def get_incidents():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                incident_data
            FROM security_incidents
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        incidents = []
        for row in rows:
            incident_data = row[0]
            if isinstance(incident_data, str):
                incident_data = json.loads(incident_data)
            incidents.append(incident_data)
        return jsonify({
            "count": len(incidents),
            "incidents": incidents
        }), 200
    except Exception as e:
        print(
            f"DATABASE ERROR: Failed to read incidents: {e}",
            flush=True
        )
        return jsonify({
            "error": "Failed to read incidents from database",
            "details": str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route("/stats", methods=["GET"])
def get_stats():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        # Total events
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_events
        """)
        total_events = cursor.fetchone()[0]
        # Total incidents
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
        """)
        total_incidents = cursor.fetchone()[0]
        # Critical incidents
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
            WHERE severity = 'CRITICAL'
        """)
        critical_incidents = cursor.fetchone()[0]
        # High incidents
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
            WHERE severity = 'HIGH'
        """)
        high_incidents = cursor.fetchone()[0]
        # Open incidents
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
            WHERE status = 'OPEN'
        """)
        open_incidents = cursor.fetchone()[0]
        return jsonify({
            "total_events": total_events,
            "total_incidents": total_incidents,
            "critical_incidents": critical_incidents,
            "high_incidents": high_incidents,
            "open_incidents": open_incidents
        }), 200
    except Exception as e:
        print(
            f"DATABASE ERROR: Failed to read stats: {e}",
            flush=True
        )
        return jsonify({
            "error": "Failed to read stats from database",
            "details": str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

if __name__ == "__main__":
    print(
        "SOC Detection Engine is running on port 5000...",
        flush=True
    )
    initialize_database()
    app.run(
        host="0.0.0.0",
        port=5000
    )