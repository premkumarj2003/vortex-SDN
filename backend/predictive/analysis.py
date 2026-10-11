"""
VORTEX-SDN Predictive Intelligence Orchestrator & Early Warning Engine
Aggregates baselines, anomalies, forecasts, and risks into a unified intelligence object.
Dispatches early warning notifications with strict cooldown de-duplication.
"""

import time
from datetime import datetime, timezone
from backend.predictive.baseline import calculate_telemetry_baselines
from backend.predictive.anomaly import detect_predictive_anomalies
from backend.predictive.forecast import generate_predictive_forecast
from backend.predictive.risk import calculate_predictive_risk
from backend.services.notification_service import create_notification

# Cooldown tracker for early warning notifications (key: warning_type -> timestamp)
_notification_cooldowns = {}
_acknowledged_warnings = set()

def acknowledge_warning(warning_id: str) -> bool:
    """Marks an early warning as acknowledged by operator."""
    global _acknowledged_warnings
    _acknowledged_warnings.add(warning_id)
    return True

def run_predictive_analysis(time_window: str = "15m") -> dict:
    """
    Executes full predictive intelligence analysis pipeline.
    Does NOT modify live telemetry or health calculations.
    """
    now_epoch = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Compute dynamic baselines
    baselines = calculate_telemetry_baselines(time_window=time_window)

    # 2. Detect statistical anomalies
    anomalies = detect_predictive_anomalies(baselines)

    # 3. Generate statistical forecasts
    forecast_data = generate_predictive_forecast(baselines)

    # 4. Calculate predictive risk & device rankings
    risk_data = calculate_predictive_risk(baselines, anomalies, forecast_data)

    # 5. Formulate Early Warnings
    warnings = []
    w_counter = 1

    # Early Warning: Traffic surge
    tp_stats = baselines.get("metrics", {}).get("throughput", {})
    if tp_stats.get("trend") == "INCREASING":
        w_id = f"WARN-{w_counter:03d}"
        warnings.append({
            "id": w_id,
            "category": "TRAFFIC",
            "title": "Traffic Utilization Increasing",
            "severity": "MEDIUM" if risk_data["traffic_risk"] < 60 else "HIGH",
            "confidence": 82,
            "message": f"Throughput trajectory shows upward trend ({tp_stats.get('current', 52.4)} Mbps). Potential egress queue saturation risk.",
            "recommended_action": "Monitor switch port utilization and evaluate traffic class prioritization.",
            "digital_twin_scenario": "congestion",
            "digital_twin_target": "1.5",
            "is_acknowledged": w_id in _acknowledged_warnings,
            "created_at": now_iso
        })
        w_counter += 1

    # Early Warning: Latency degradation
    lat_stats = baselines.get("metrics", {}).get("latency", {})
    if lat_stats.get("current", 14.5) > 22.0 or lat_stats.get("trend") == "INCREASING":
        w_id = f"WARN-{w_counter:03d}"
        warnings.append({
            "id": w_id,
            "category": "LATENCY",
            "title": "Latency Trend Deteriorating",
            "severity": "HIGH" if lat_stats.get("current", 14.5) > 35.0 else "MEDIUM",
            "confidence": 76,
            "message": f"Fabric latency has elevated to {lat_stats.get('current', 14.5)} ms across core OpenFlow mesh links.",
            "recommended_action": "Inspect inter-switch transit queues and test failover routes in Digital Twin.",
            "digital_twin_scenario": "high_latency",
            "digital_twin_target": "30.0",
            "is_acknowledged": w_id in _acknowledged_warnings,
            "created_at": now_iso
        })
        w_counter += 1

    # Early Warning: Security Anomaly
    sec_stats = baselines.get("metrics", {}).get("security_threats", {})
    if sec_stats.get("current_count", 0) > 0:
        w_id = f"WARN-{w_counter:03d}"
        warnings.append({
            "id": w_id,
            "category": "SECURITY",
            "title": "Elevated Security Threat Activity",
            "severity": "HIGH",
            "confidence": 91,
            "message": f"{sec_stats.get('current_count')} active security anomaly pattern(s) detected across data plane.",
            "recommended_action": "Inspect Security Center and simulate containment in Digital Twin.",
            "digital_twin_scenario": "ddos",
            "digital_twin_target": "h4-s1",
            "is_acknowledged": w_id in _acknowledged_warnings,
            "created_at": now_iso
        })
        w_counter += 1

    # Default nominal warning if clean
    if not warnings:
        warnings.append({
            "id": "WARN-000",
            "category": "SYSTEM",
            "title": "Nominal Baseline Operating State",
            "severity": "LOW",
            "confidence": 95,
            "message": "All flow rates, transit latencies, and security metrics are operating within expected baseline bounds.",
            "recommended_action": "Continue automated telemetry surveillance.",
            "digital_twin_scenario": None,
            "digital_twin_target": None,
            "is_acknowledged": True,
            "created_at": now_iso
        })

    # 6. Cooldown-Protected Notification Dispatch
    # Only dispatch for HIGH/CRITICAL early warnings once every 300 seconds (5 minutes)
    for w in warnings:
        if w["severity"] in ("HIGH", "CRITICAL") and w["id"] != "WARN-000":
            w_type = w["category"]
            last_sent = _notification_cooldowns.get(w_type, 0.0)
            if (now_epoch - last_sent) > 300.0:
                try:
                    create_notification(
                        title=f"Predictive Early Warning: {w['title']}",
                        message=w["message"],
                        severity=w["severity"],
                        category="predictive"
                    )
                    _notification_cooldowns[w_type] = now_epoch
                except Exception:
                    pass

    return {
        "status": "READY" if baselines.get("is_sufficient") else "INSUFFICIENT_DATA",
        "source": baselines.get("source", "DEMO"),
        "timestamp": now_iso,
        "time_window": time_window,
        "is_sufficient": baselines.get("is_sufficient", True),
        "network_risk": risk_data["network_risk"],
        "risk_level": risk_data["risk_level"],
        "traffic_trend": tp_stats.get("trend", "STABLE"),
        "security_risk": risk_data["security_risk"],
        "qos_risk": risk_data["qos_risk"],
        "predicted_anomalies_count": len(anomalies),
        "early_warnings_count": len([w for w in warnings if w["id"] != "WARN-000"]),
        "confidence": forecast_data.get("confidence", 82),
        "confidence_level": forecast_data.get("confidence_level", "HIGH"),
        "baselines": baselines,
        "anomalies": anomalies,
        "forecast": forecast_data,
        "health_forecast": forecast_data.get("health_forecast", {}),
        "security_forecast": forecast_data.get("security_forecast", {}),
        "qos_forecast": forecast_data.get("qos_forecast", {}),
        "metric_forecasts": forecast_data.get("metric_forecasts", {}),
        "risk_assessment": risk_data,
        "early_warnings": warnings,
        "model_info": {
            "algorithm": "Rolling Dynamic Baseline + Holt Linear Trend + Adaptive Z-Score",
            "training_data": "Live & historical OpenFlow telemetry buffers",
            "prediction_window": "1m, 5m, 10m Horizons",
            "confidence": f"{forecast_data.get('confidence', 82)}%"
        }
    }
