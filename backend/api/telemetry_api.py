"""
VORTEX-SDN Telemetry & Dashboard REST API
Provides live network metrics, dashboard summaries, rolling flow history, and health endpoints.
"""

import time
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from telemetry.flow_monitor import flow_monitor
from backend.services.telemetry_service import get_dashboard_summary

telemetry_bp = Blueprint("telemetry", __name__)

@telemetry_bp.route("/api/status", methods=["GET"])
def get_system_status():
    tel_status = flow_monitor.get_status()
    return jsonify({
        "status": "ONLINE",
        "service": "VORTEX-SDN Controller & Intelligence Platform",
        "telemetry": tel_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@telemetry_bp.route("/api/health", methods=["GET"])
def get_health_check():
    health = flow_monitor.compute_health_scores()
    tel_status = flow_monitor.get_status()
    return jsonify({
        "health": health,
        "telemetry_status": tel_status,
        "uptime_seconds": round(time.time() - (flow_monitor.last_update_time or time.time()), 1),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@telemetry_bp.route("/api/summary", methods=["GET"])
@telemetry_bp.route("/api/dashboard", methods=["GET"])
@telemetry_bp.route("/api/telemetry/summary", methods=["GET"])
def get_summary():
    data = get_dashboard_summary()
    return jsonify(data), 200

@telemetry_bp.route("/api/telemetry", methods=["GET"])
@telemetry_bp.route("/api/telemetry/latest", methods=["GET"])
def get_latest_telemetry():
    limit = int(request.args.get("limit", 50))
    records = flow_monitor.get_latest(limit=limit)
    status = flow_monitor.get_status()
    return jsonify({
        "records": records,
        "count": len(records),
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@telemetry_bp.route("/api/telemetry/history", methods=["GET"])
def get_telemetry_history():
    records = flow_monitor.get_latest(limit=100)
    return jsonify({
        "history": records,
        "total": len(records),
        "source": flow_monitor.source_mode,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@telemetry_bp.route("/api/flows", methods=["GET"])
def get_flows():
    limit = int(request.args.get("limit", 100))
    proto_filter = request.args.get("protocol", None)
    threat_filter = request.args.get("threat", None)
    qos_filter = request.args.get("qos", None)

    records = flow_monitor.get_latest(limit=limit)

    if proto_filter and proto_filter.upper() != "ALL":
        records = [r for r in records if r.get("protocol", "").upper() == proto_filter.upper()]
    if threat_filter and threat_filter.upper() != "ALL":
        records = [r for r in records if r.get("threat_label", "").upper() == threat_filter.upper()]
    if qos_filter and qos_filter.upper() != "ALL":
        records = [r for r in records if r.get("traffic_class", "").upper() == qos_filter.upper()]

    return jsonify({
        "flows": records,
        "total": len(records),
        "source": flow_monitor.source_mode,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@telemetry_bp.route("/api/flows/<flow_id>", methods=["GET"])
def get_flow_detail(flow_id):
    records = flow_monitor.get_latest(limit=100)
    for r in records:
        if r.get("flow_id") == flow_id:
            return jsonify({"flow": r}), 200
    return jsonify({"error": "Not Found", "message": f"Flow {flow_id} not found in recent buffer."}), 404
