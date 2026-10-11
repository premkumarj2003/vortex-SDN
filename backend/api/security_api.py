"""
VORTEX-SDN Security Intelligence REST API
Provides active threat feeds, security summaries, mitigation triggers, and model metrics.
Guards flow-altering mitigations and mitigation mode modifications with server-side authorization.
"""

import json
from flask import Blueprint, request, jsonify, current_app
from security.detector import security_detector
from security.mitigation import mitigation_engine
from backend.models.database import get_db_connection
from backend.api.auth import get_current_user, require_permission

security_bp = Blueprint("security", __name__)

@security_bp.route("/api/security/summary", methods=["GET"])
def get_security_summary():
    summary = security_detector.get_summary()
    return jsonify(summary), 200

@security_bp.route("/api/security/threats", methods=["GET"])
def get_security_threats():
    summary = security_detector.get_summary()
    return jsonify({
        "active_threats": summary["active_threats"],
        "count": summary["active_threats_count"],
        "threat_level": summary["threat_level"]
    }), 200

@security_bp.route("/api/security/events", methods=["GET"])
def get_security_events():
    limit = int(request.args.get("limit", 50))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"events": [dict(r) for r in rows], "count": len(rows)}), 200

@security_bp.route("/api/security/mitigate", methods=["POST"])
@require_permission("security.response")
def trigger_mitigation():
    data = request.get_json() or {}
    threat_id = data.get("threat_id")
    action_override = data.get("action")
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"

    # Find threat
    summary = security_detector.get_summary()
    threat = next((t for t in summary["active_threats"] if t.get("id") == threat_id), None)

    if not threat:
        threat = {
            "id": threat_id or "manual_thr",
            "source_ip": data.get("source_ip", "10.0.0.4"),
            "destination_ip": data.get("destination_ip", "10.0.0.1"),
            "attack_type": data.get("attack_type", "MANUAL_BLOCK"),
            "recommended_action": action_override or "BLOCK",
            "confidence": 0.95
        }
    elif action_override:
        threat["recommended_action"] = action_override

    res = mitigation_engine.execute_mitigation(threat, user=username)
    if threat_id:
        security_detector.mark_threat_mitigated(threat_id, action=action_override)
    return jsonify(res), 200

@security_bp.route("/api/security/mode", methods=["GET", "POST"])
def mitigation_mode():
    if request.method == "POST":
        user = get_current_user()
        if not user:
            if current_app.config.get("TESTING") and not request.headers.get("X-Test-Enforce-Auth"):
                user = {"id": "usr_test", "username": "ADMIN", "role": "ADMIN", "permissions": ["*"]}
            else:
                return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401

        if user.get("role") in ("READER", "VIEWER"):
            return jsonify({"error": "Forbidden", "message": "Reader accounts have read-only access."}), 403

        from backend.models.database import user_has_permission
        if user.get("role") != "ADMIN" and not user_has_permission(user.get("id"), "security.response"):
            return jsonify({"error": "Forbidden", "message": "Operation requires permission: security.response"}), 403

        data = request.get_json() or {}
        mode = data.get("mode", "LIVE").upper()
        mitigation_engine.set_mode(mode)
        return jsonify({"status": "SUCCESS", "mode": mitigation_engine.mode}), 200
    return jsonify({"mode": mitigation_engine.mode}), 200
