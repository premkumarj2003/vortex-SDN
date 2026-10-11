"""
VORTEX-SDN Incident Management REST API
Provides endpoints for incident listing, summary KPIs, detail inspection, and lifecycle operations.
Guards lifecycle state modifications and mitigations with server-side authorization.
"""

from flask import Blueprint, request, jsonify
from backend.services.incident_service import (
    get_incidents,
    get_incident_by_id,
    get_incident_summary,
    update_incident_status,
    create_incident
)
from backend.services.audit_service import log_audit_event
from backend.api.auth import get_current_user, require_permission

incident_bp = Blueprint("incidents", __name__)

@incident_bp.route("/api/incidents", methods=["GET"])
def list_incidents():
    """Lists incidents with multi-criteria filtering, search, and sorting."""
    status_filter = request.args.get("status", None)
    severity_filter = request.args.get("severity", None)
    time_filter = request.args.get("time_filter", None)
    search_query = request.args.get("search", None)
    sort_by = request.args.get("sort_by", "newest")
    limit = int(request.args.get("limit", 100))

    incidents = get_incidents(
        status_filter=status_filter,
        severity_filter=severity_filter,
        time_filter=time_filter,
        search_query=search_query,
        sort_by=sort_by,
        limit=limit
    )
    return jsonify({"incidents": incidents, "count": len(incidents)}), 200

@incident_bp.route("/api/incidents/summary", methods=["GET"])
def incident_summary():
    """Returns live KPI metrics for active incidents, severity counts, resolved today, and MTTR."""
    summary_data = get_incident_summary()
    return jsonify(summary_data), 200

@incident_bp.route("/api/incidents/<incident_id>", methods=["GET"])
def incident_details(incident_id):
    """Returns full correlated details for a single incident including RCA and timeline."""
    incident = get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"incident": incident}), 200

@incident_bp.route("/api/incidents/<incident_id>/acknowledge", methods=["POST"])
@require_permission("incident.manage")
def acknowledge_incident(incident_id):
    """Transitions incident status to ACKNOWLEDGED."""
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"
    success = update_incident_status(incident_id, "ACKNOWLEDGED", assigned_to=username, user=username)
    if not success:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"status": "SUCCESS", "message": f"Incident {incident_id} acknowledged by {username}."}), 200

@incident_bp.route("/api/incidents/<incident_id>/investigate", methods=["POST"])
@require_permission("incident.manage")
def investigate_incident(incident_id):
    """Transitions incident status to INVESTIGATING."""
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"
    success = update_incident_status(incident_id, "INVESTIGATING", assigned_to=username, user=username)
    if not success:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"status": "SUCCESS", "message": f"Incident {incident_id} under active investigation."}), 200

@incident_bp.route("/api/incidents/<incident_id>/mitigate", methods=["POST"])
@require_permission("incident.manage")
def mitigate_incident(incident_id):
    """Dispatches OpenFlow mitigation rule and sets incident status to MITIGATING."""
    data = request.get_json() or {}
    action = data.get("action", "BLOCK").upper()
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"

    incident = get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404

    # Trigger mitigation engine
    try:
        from security.mitigation import mitigation_engine
        mitigation_engine.execute_mitigation({
            "id": incident_id,
            "source_ip": incident["source_ip"],
            "destination_ip": incident["destination_ip"],
            "attack_type": incident.get("title", "THREAT"),
            "recommended_action": action
        }, user=username)
    except Exception as e:
        print(f"[Incident API] Mitigation dispatch note: {e}")

    update_incident_status(incident_id, "MITIGATING", notes=f"OpenFlow {action} rule dispatched", user=username)
    return jsonify({"status": "SUCCESS", "message": f"Mitigation ({action}) initiated for incident {incident_id}."}), 200

@incident_bp.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
@require_permission("incident.manage")
def resolve_incident(incident_id):
    """Transitions incident status to RESOLVED and records resolution timestamp."""
    data = request.get_json() or {}
    notes = data.get("notes", "Resolved by operator verification")
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"

    success = update_incident_status(incident_id, "RESOLVED", notes=notes, user=username)
    if not success:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"status": "SUCCESS", "message": f"Incident {incident_id} marked as RESOLVED."}), 200

@incident_bp.route("/api/incidents/<incident_id>/close", methods=["POST"])
@require_permission("incident.manage")
def close_incident(incident_id):
    """Transitions incident status to CLOSED."""
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"
    success = update_incident_status(incident_id, "CLOSED", user=username)
    if not success:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"status": "SUCCESS", "message": f"Incident {incident_id} closed."}), 200

@incident_bp.route("/api/incidents/<incident_id>/status", methods=["POST"])
@require_permission("incident.manage")
def update_status(incident_id):
    """Updates incident status to an arbitrary valid state."""
    data = request.get_json() or {}
    new_status = data.get("status", "INVESTIGATING").upper()
    assigned = data.get("assigned_to")
    notes = data.get("notes")
    user = get_current_user()
    username = user["username"] if user else "OPERATOR"

    success = update_incident_status(incident_id, new_status, assigned_to=assigned, notes=notes, user=username)
    if not success:
        return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found."}), 404
    return jsonify({"status": "SUCCESS", "message": f"Incident {incident_id} status updated to {new_status}."}), 200
