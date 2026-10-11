"""
VORTEX-SDN Notification Service
Manages real-time notification alerts across categories: Security, QoS, Controller, Telemetry, AI, System.
"""

import uuid
from datetime import datetime, timezone
from backend.models.database import get_db_connection

def get_notifications(limit=30, unread_only=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    if unread_only:
        cursor.execute("SELECT * FROM notifications WHERE is_read = 0 ORDER BY timestamp DESC LIMIT ?", (limit,))
    else:
        cursor.execute("SELECT * FROM notifications ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM notifications WHERE is_read = 0")
    unread_count = cursor.fetchone()[0]
    conn.close()
    return {"notifications": [dict(r) for r in rows], "unread_count": unread_count}

def mark_notification_read(notif_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    if notif_id == "all":
        cursor.execute("UPDATE notifications SET is_read = 1, read_at = ? WHERE is_read = 0", (now,))
    else:
        cursor.execute("UPDATE notifications SET is_read = 1, read_at = ? WHERE id = ?", (now, notif_id))
    conn.commit()
    conn.close()
    return True

def create_notification(category: str, title: str, message: str, severity: str = "INFO", link: str = None) -> str:
    """Inserts a persistent notification into SQLite with unread deduplication."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Normalize category
        cat_map = {
            "sec": "Security", "security": "Security",
            "qos": "QoS",
            "controller": "Controller", "ctl": "Controller",
            "telemetry": "Telemetry", "tel": "Telemetry",
            "ai": "AI",
            "sys": "System", "system": "System"
        }
        norm_cat = cat_map.get(str(category).lower(), "System")
        
        # Normalize severity
        sev_map = {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "warning": "MEDIUM", "danger": "HIGH"
        }
        norm_sev = sev_map.get(str(severity).lower(), "INFO")

        # Deduplication check: prevent multiple identical unread notifications
        cursor.execute("""
        SELECT id FROM notifications 
        WHERE title = ? AND message = ? AND is_read = 0
        LIMIT 1
        """, (title, message))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            return existing[0]

        notif_id = f"notif_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
        INSERT INTO notifications (id, timestamp, category, title, message, severity, is_read, read_at, link)
        VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?)
        """, (notif_id, now, norm_cat, title, message, norm_sev, link))
        conn.commit()
        conn.close()
        return notif_id
    except Exception as e:
        print(f"[Notification Service] Error creating notification: {e}")
        return None
