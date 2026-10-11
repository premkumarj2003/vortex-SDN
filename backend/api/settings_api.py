"""
VORTEX-SDN User Settings & Profile API
Persists personalized preferences: Appearance (Dark/Light/Compact), Dashboard Density,
Refresh Intervals (5s, 10s, 15s, 30s, 60s), Notifications, and Preferred Network Units.
"""

import json
from flask import Blueprint, request, jsonify
from backend.models.database import get_db_connection
from backend.api.auth import get_current_user, ACTIVE_SESSIONS
from backend.services.audit_service import log_audit_event

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/api/user/settings", methods=["GET"])
def get_user_settings():
    user = get_current_user()
    if not user:
        # Default settings if unauthenticated
        return jsonify({
            "appearance": {"theme": "dark", "density": "comfortable", "compact_mode": False},
            "dashboard": {"refresh_interval": 5, "default_landing_page": "dashboard", "chart_animation": True},
            "notifications": {"security_alerts": True, "qos_alerts": True, "system_alerts": True, "ai_alerts": True, "browser_notifications": False},
            "network": {"telemetry_interval": 5, "preferred_units": "auto", "traffic_display": "both"},
            "security": {"auto_logout_minutes": 60}
        }), 200

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT settings_json FROM users WHERE id = ?", (user["id"],))
    row = cursor.fetchone()
    conn.close()

    settings = json.loads(row["settings_json"]) if row and row["settings_json"] else {}
    return jsonify(settings), 200

@settings_bp.route("/api/user/settings", methods=["PUT", "POST"])
def update_user_settings():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized", "message": "Login required to save preferences."}), 401

    data = request.get_json() or {}
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET settings_json = ? WHERE id = ?", (json.dumps(data), user["id"]))
    conn.commit()
    conn.close()

    # Update in memory session
    user["settings"] = data
    log_audit_event(user["username"], user["role"], "UPDATE_SETTINGS", "User Settings", "SUCCESS")

    return jsonify({"status": "SUCCESS", "message": "Settings saved successfully.", "settings": data}), 200

@settings_bp.route("/api/user/profile", methods=["PUT"])
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    full_name = data.get("full_name", user["full_name"])
    avatar = data.get("avatar", user["avatar"])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET full_name = ?, avatar = ? WHERE id = ?", (full_name, avatar, user["id"]))
    conn.commit()
    conn.close()

    user["full_name"] = full_name
    user["avatar"] = avatar

    log_audit_event(user["username"], user["role"], "UPDATE_PROFILE", "User Profile", "SUCCESS")
    return jsonify({"status": "SUCCESS", "user": user}), 200
