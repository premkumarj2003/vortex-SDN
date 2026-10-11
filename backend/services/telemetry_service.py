"""
VORTEX-SDN Backend Telemetry Service
Provides high-level aggregated summary, dashboard KPI metrics, and rolling history.
"""

import time
from datetime import datetime, timezone
from telemetry.flow_monitor import flow_monitor
from security.detector import security_detector
from qos.policy_engine import qos_policy_engine
from backend.models.database import get_db_connection

_last_telemetry_status = None

def check_telemetry_status_transition(current_status: str):
    global _last_telemetry_status
    if _last_telemetry_status is not None and _last_telemetry_status != current_status:
        from backend.services.notification_service import create_notification
        if current_status in ("STALE", "DISCONNECTED") and _last_telemetry_status == "LIVE":
            create_notification("Telemetry", "Telemetry Connection Stale", "Real-time telemetry stream is experiencing delays or stale updates.", "MEDIUM", "health")
        elif current_status == "LIVE" and _last_telemetry_status in ("STALE", "DISCONNECTED"):
            create_notification("Telemetry", "Telemetry Connection Restored", "Real-time OpenFlow telemetry stream restored to active state.", "INFO", "health")
    _last_telemetry_status = current_status

def get_dashboard_summary():
    """
    Returns live aggregated KPIs for top dashboard cards:
    - Total Flows, Malicious Flows, Encrypted Traffic %, QoS Policies Active,
    - Average Latency, Throughput, Packet Loss, Bandwidth Utilization, Active Devices, Active Incidents.
    Every metric is calculated dynamically from live telemetry.
    """
    sec_summary = security_detector.get_summary()
    health_metrics = flow_monitor.compute_health_scores(
        active_threats_count=sec_summary["active_threats_count"],
        qos_violations_count=0
    )
    latest_flows = flow_monitor.get_latest(limit=50)
    qos_data = qos_policy_engine.evaluate_flows(latest_flows)
    telemetry_status = flow_monitor.get_status()
    check_telemetry_status_transition(telemetry_status.get("status", "LIVE"))

    # Query Active Incidents Count from DB
    active_incidents = 0
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING')")
        active_incidents = cursor.fetchone()[0]
        conn.close()
    except Exception:
        active_incidents = sec_summary["critical_threats"] + sec_summary["high_threats"]

    # Calculate encrypted traffic fraction (HTTPS/SSH/TLS dst_ports 443, 8443, 22)
    enc_flows = [f for f in latest_flows if int(f.get("destination_port", 0)) in (443, 8443, 22)]
    enc_pct = round((len(enc_flows) / max(1, len(latest_flows))) * 100, 1) if latest_flows else 0.0

    from backend.services.topology_service import get_network_topology
    topo = get_network_topology()
    active_devices_count = len(topo.get("nodes", []))

    return {
        "source": telemetry_status["source"],
        "telemetry_status": telemetry_status["status"],
        "telemetry_label": telemetry_status["label"],
        "last_update_seconds_ago": telemetry_status["last_update_seconds_ago"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        
        # Primary KPI Cards
        "total_flows": len(latest_flows),
        "malicious_flows": health_metrics["malicious_flows_count"],
        "encrypted_traffic_pct": enc_pct,
        "qos_policies_active": qos_data["active_policies_count"],
        "average_latency_ms": health_metrics["average_latency_ms"],
        "throughput_mbps": health_metrics["total_throughput_mbps"],
        "packet_loss_pct": health_metrics["packet_loss_pct"],
        "jitter_ms": health_metrics["jitter_ms"],
        "bandwidth_utilization_pct": health_metrics["bandwidth_utilization_pct"],
        "active_devices": active_devices_count,
        "active_incidents": active_incidents,

        # Health Scores
        "network_health_score": health_metrics["network_health"],
        "network_health": health_metrics["network_health"],
        "security_health_score": health_metrics["security_health"],
        "qos_health_score": health_metrics["qos_health"],
        "health_status": health_metrics["status"],

        # Breakdown distributions
        "qos_distribution": qos_data["distribution"],
        "security_summary": sec_summary,
        "high_severity_anomalies": sec_summary.get("critical_threats", 0) + sec_summary.get("high_threats", 0),
        "recent_flows": latest_flows[:15]
    }
