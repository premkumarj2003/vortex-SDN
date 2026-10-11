"""
VORTEX-SDN Digital Twin REST API
Provides endpoints for snapshot capture, virtual what-if simulations,
session history, critical node analysis, and simulation resets.
"""

from flask import Blueprint, request, jsonify
from backend.digital_twin.snapshot import capture_snapshot
from backend.digital_twin.graph import analyze_critical_infrastructure
from backend.digital_twin.simulator import (
    run_what_if_simulation,
    get_simulation_history,
    clear_simulation_history,
    get_simulation_by_id
)

digital_twin_bp = Blueprint("digital_twin", __name__)

@digital_twin_bp.route("/api/digital-twin/snapshot", methods=["GET"])
def get_snapshot():
    """Captures and returns an isolated virtual snapshot of the current network state."""
    snapshot = capture_snapshot()
    critical_analysis = analyze_critical_infrastructure(snapshot["nodes"], snapshot["links"])
    snapshot["critical_analysis"] = critical_analysis
    return jsonify(snapshot), 200

@digital_twin_bp.route("/api/digital-twin/simulate", methods=["POST"])
def simulate():
    """Executes a what-if simulation against the current digital twin snapshot."""
    data = request.get_json() or {}
    scenario = data.get("scenario", "link_failure")
    params = data.get("params", {})

    snapshot = capture_snapshot()
    result = run_what_if_simulation(scenario, params, snapshot)
    return jsonify(result), 200

@digital_twin_bp.route("/api/digital-twin/reset", methods=["POST"])
def reset_simulation():
    """Resets digital twin state back to the fresh live snapshot."""
    snapshot = capture_snapshot()
    return jsonify({
        "status": "SUCCESS",
        "message": "Digital Twin reset to synchronized live snapshot.",
        "snapshot": snapshot
    }), 200

@digital_twin_bp.route("/api/digital-twin/history", methods=["GET"])
def get_history():
    """Returns past simulation runs from the current operator session."""
    history = get_simulation_history()
    return jsonify({"history": history, "count": len(history)}), 200

@digital_twin_bp.route("/api/digital-twin/history/<sim_id>", methods=["GET"])
def get_single_simulation(sim_id):
    """Retrieves details of a past simulation run by ID."""
    sim = get_simulation_by_id(sim_id)
    if not sim:
        return jsonify({"error": "Not Found", "message": f"Simulation {sim_id} not found."}), 404
    return jsonify({"simulation": sim}), 200

@digital_twin_bp.route("/api/digital-twin/history/clear", methods=["POST"])
def clear_history():
    """Clears the current session simulation history."""
    clear_simulation_history()
    return jsonify({"status": "SUCCESS", "message": "Simulation history cleared."}), 200

@digital_twin_bp.route("/api/digital-twin/critical-nodes", methods=["GET"])
def get_critical_nodes():
    """Returns Critical Node Rankings and Single Point of Failure (SPOF) analysis."""
    snapshot = capture_snapshot()
    analysis = analyze_critical_infrastructure(snapshot["nodes"], snapshot["links"])
    return jsonify(analysis), 200
