"""
VORTEX-SDN Demo & Scenario Control REST API
Allows interactive switching of simulation scenarios (NORMAL, DDOS_ATTACK, PORT_SCAN, BRUTE_FORCE,
NETWORK_CONGESTION, QOS_DEGRADATION, HIGH_LATENCY, RECOVERY).
Guards scenario and telemetry mode switching with server-side authorization.
"""

from flask import Blueprint, request, jsonify
from backend.services.demo_engine import demo_engine
from telemetry.flow_monitor import flow_monitor
from backend.api.auth import require_permission

demo_bp = Blueprint("demo", __name__)

@demo_bp.route("/api/demo/scenario", methods=["POST"])
@require_permission("network.configure")
def set_scenario():
    data = request.get_json() or {}
    scen = data.get("scenario", "NORMAL")
    res = demo_engine.set_scenario(scen)
    return jsonify(res), 200

@demo_bp.route("/api/demo/status", methods=["GET"])
def get_demo_status():
    status = demo_engine.get_status()
    return jsonify(status), 200

@demo_bp.route("/api/demo/mode", methods=["POST"])
@require_permission("network.configure")
def toggle_source_mode():
    data = request.get_json() or {}
    mode = data.get("mode", "DEMO").upper()
    if mode in ("REAL", "DEMO"):
        flow_monitor.source_mode = mode
    return jsonify({"status": "SUCCESS", "source_mode": flow_monitor.source_mode}), 200
