"""
VORTEX-SDN Audit Logs REST API
Strictly restricted to Administrator account.
Direct non-admin API requests (Reader, Operator) receive HTTP 403 Forbidden.
Supports comprehensive searching and filtering across actions, users, dates, and outcomes.
"""

from flask import Blueprint, request, jsonify
from backend.services.audit_service import get_audit_logs
from backend.api.auth import require_admin, get_current_user

audit_bp = Blueprint("audit", __name__)

@audit_bp.route("/api/audit", methods=["GET"])
@require_admin
def list_audits():
    action = request.args.get("action", None)
    user_param = request.args.get("user", None)
    date_param = request.args.get("date", None)
    result_param = request.args.get("result", None)
    limit = int(request.args.get("limit", 100))

    logs = get_audit_logs(
        limit=limit,
        action_filter=action,
        user_filter=user_param,
        date_filter=date_param,
        result_filter=result_param
    )
    return jsonify({"logs": logs, "count": len(logs)}), 200
