"""
VORTEX-SDN QoS Intelligence REST API
Provides traffic classification breakdown, QoS health gauges, active policy listings, and recommendations.
"""

from flask import Blueprint, jsonify
from telemetry.flow_monitor import flow_monitor
from qos.policy_engine import qos_policy_engine

qos_bp = Blueprint("qos", __name__)

@qos_bp.route("/api/qos", methods=["GET"])
@qos_bp.route("/api/qos/summary", methods=["GET"])
def get_qos_summary():
    flows = flow_monitor.get_latest(limit=50)
    qos_data = qos_policy_engine.evaluate_flows(flows)
    health = flow_monitor.compute_health_scores()

    return jsonify({
        "qos_health_score": health["qos_health"],
        "average_latency_ms": health["average_latency_ms"],
        "jitter_ms": health["jitter_ms"],
        "packet_loss_pct": health["packet_loss_pct"],
        "throughput_mbps": health["total_throughput_mbps"],
        "bandwidth_utilization_pct": health["bandwidth_utilization_pct"],
        "distribution": qos_data["distribution"],
        "violations": qos_data["violations"],
        "violations_count": qos_data["violations_count"],
        "recommendations": qos_data["recommendations"],
        "active_policies_count": qos_data["active_policies_count"]
    }), 200

@qos_bp.route("/api/qos/policies", methods=["GET"])
def get_qos_policies():
    policies = qos_policy_engine.get_active_policies()
    return jsonify({"policies": policies, "count": len(policies)}), 200

@qos_bp.route("/api/qos/classifications", methods=["GET"])
def get_qos_classifications():
    flows = flow_monitor.get_latest(limit=50)
    qos_data = qos_policy_engine.evaluate_flows(flows)
    return jsonify({"classes": qos_data["distribution"]}), 200
