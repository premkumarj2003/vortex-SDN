"""
VORTEX-SDN Audit Trail Service
Records and retrieves tamper-evident system logs for logins, flow edits, security mitigations, and QoS changes.
Append-only log storage. No delete or update operations exist.
"""

import json
import uuid
from datetime import datetime, timezone
from backend.models.database import get_db_connection

def log_audit_event(username: str, role: str, action: str, resource: str, result: str = "SUCCESS", details: dict = None, client_ip: str = "127.0.0.1"):
    """Appends an immutable audit log entry."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        audit_id = f"aud_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details or {})
        cursor.execute("""
        INSERT INTO audit_logs (id, timestamp, user_id, username, role, action, resource, result, details_json, client_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (audit_id, now, username, username, role, action, resource, result, details_str, client_ip))
        conn.commit()
        conn.close()
        return audit_id
    except Exception as e:
        print(f"[Audit Service] Error: {e}")
        return None

def get_audit_logs(limit: int = 100, action_filter: str = None, user_filter: str = None, date_filter: str = None, result_filter: str = None) -> list[dict]:
    """Retrieves audit log entries with optional multi-criteria filters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if action_filter and action_filter.upper() != "ALL":
        query += " AND action LIKE ?"
        params.append(f"%{action_filter}%")

    if user_filter and user_filter.strip():
        query += " AND (username LIKE ? OR user_id LIKE ?)"
        params.extend([f"%{user_filter.strip()}%", f"%{user_filter.strip()}%"])

    if date_filter and date_filter.strip():
        query += " AND timestamp LIKE ?"
        params.append(f"{date_filter.strip()}%")

    if result_filter and result_filter.upper() != "ALL":
        query += " AND result = ?"
        params.append(result_filter.upper())

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
