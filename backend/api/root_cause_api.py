"""
VORTEX-SDN AI Root-Cause Analysis (RCA) REST API
Provides endpoints for real-time root cause diagnostics, evidence signals,
impact assessments, recovery tracking, and historical RCA events.
"""

from flask import Blueprint, jsonify, request
from backend.services.root_cause_service import analyze_root_cause, get_root_cause_history

root_cause_bp = Blueprint("root_cause", __name__)

@root_cause_bp.route("/api/root-cause/analysis", methods=["GET"])
@root_cause_bp.route("/api/root-cause/latest", methods=["GET"])
def get_root_cause_analysis():
    """Returns real-time AI root cause diagnostics based on active data plane signals."""
    analysis = analyze_root_cause()
    return jsonify(analysis), 200

@root_cause_bp.route("/api/root-cause/history", methods=["GET"])
def get_rca_history():
    """Returns recent historical root cause analyses."""
    history = get_root_cause_history()
    return jsonify({"history": history, "count": len(history)}), 200

@root_cause_bp.route("/api/root-cause/reanalyze", methods=["POST"])
def force_reanalyze():
    """Forces an immediate fresh correlation of all telemetry and security sources."""
    # Invalidate cache by clearing cached time
    import backend.services.root_cause_service as rca_srv
    rca_srv._last_rca_time = 0
    analysis = analyze_root_cause()
    return jsonify({"status": "SUCCESS", "analysis": analysis}), 200
