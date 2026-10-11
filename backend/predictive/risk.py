"""
VORTEX-SDN Predictive Risk Scoring & Device Assessment Engine
Calculates composite Predictive Network Risk, separates health from risk,
evaluates per-device risk rankings, and surfaces top predictive risk factors.
"""

from backend.services.topology_service import get_network_topology

def get_risk_level(score: float) -> str:
    """Classifies risk score into standard NOC brackets."""
    if score >= 75.0:
        return "CRITICAL"
    elif score >= 50.0:
        return "HIGH"
    elif score >= 25.0:
        return "MODERATE"
    else:
        return "LOW"

def calculate_predictive_risk(baselines: dict, anomalies: list[dict], forecast: dict) -> dict:
    """
    Computes composite Predictive Network Risk and per-device risk matrices.
    Never modifies live health values or controller flow rules.
    """
    if not baselines or not baselines.get("is_sufficient"):
        return {
            "network_risk": 15,
            "risk_level": "LOW",
            "traffic_risk": 12,
            "security_risk": 10,
            "qos_risk": 15,
            "device_risks": [],
            "top_risks": []
        }

    metrics = baselines.get("metrics", {})
    tp_stats = metrics.get("throughput", {})
    lat_stats = metrics.get("latency", {})
    loss_stats = metrics.get("packet_loss", {})
    sec_stats = metrics.get("security_threats", {})

    tp_curr = float(tp_stats.get("current", 52.4))
    lat_curr = float(lat_stats.get("current", 14.5))
    loss_curr = float(loss_stats.get("current", 0.1))
    threat_cnt = int(sec_stats.get("current_count", 0))

    # 1. Traffic Risk Component (0 - 100)
    # Scaled against 100 Mbps edge access / 1000 Mbps mesh capacity
    tp_ratio = min(1.0, tp_curr / 90.0)
    tp_trend = tp_stats.get("trend", "STABLE")
    tp_trend_penalty = 15.0 if tp_trend == "INCREASING" else (20.0 if tp_trend == "VOLATILE" else 0.0)
    traffic_risk = round(min(100.0, tp_ratio * 60.0 + tp_trend_penalty), 1)

    # 2. Security Risk Component (0 - 100)
    security_risk = round(min(100.0, threat_cnt * 38.0 + (15.0 if threat_cnt > 0 else 5.0)), 1)

    # 3. QoS Risk Component (0 - 100)
    lat_risk = min(50.0, max(0.0, (lat_curr - 12.0) * 1.8))
    loss_risk = min(50.0, loss_curr * 10.0)
    qos_risk = round(min(100.0, lat_risk + loss_risk + (10.0 if lat_stats.get("trend") == "INCREASING" else 0.0)), 1)

    # 4. Composite Network Risk Score (0 - 100)
    anomaly_penalty = min(25.0, len(anomalies) * 8.0)
    composite_score = round(
        traffic_risk * 0.30 +
        security_risk * 0.35 +
        qos_risk * 0.25 +
        anomaly_penalty * 0.10,
        1
    )
    composite_score = min(100.0, max(5.0, composite_score))
    risk_level = get_risk_level(composite_score)

    # 5. Device Risk Assessment (S1-S4, H1-H4)
    topo = get_network_topology()
    nodes = topo.get("nodes", [])
    device_risks = []

    for n in nodes:
        d_id = n["id"].upper()
        d_type = n.get("type", "switch")
        d_role = n.get("role", "NODE")
        d_status = n.get("status", "ONLINE")

        dev_score = 10.0
        factors = []

        if d_id == "S2":
            dev_score += (25.0 if tp_trend == "INCREASING" else 10.0)
            factors.append("Core transit switch aggregating North-South traffic")
        elif d_id == "S1":
            dev_score += (30.0 if threat_cnt > 0 else 10.0)
            factors.append("Edge gateway terminating Web/App tenant traffic")
        elif d_id == "S4":
            dev_score += (45.0 if "MALICIOUS" in d_status or threat_cnt > 0 else 10.0)
            factors.append("Edge gateway connected to external traffic ingress")
        elif d_id == "H4":
            dev_score += (55.0 if "MALICIOUS" in d_status or threat_cnt > 0 else 5.0)
            factors.append("External endpoint under active threat surveillance")
        elif d_id == "H1":
            dev_score += (25.0 if "ATTACKED" in d_status else 5.0)
            factors.append("Critical Web application host")
        else:
            dev_score += 5.0
            factors.append("Baseline nominal operation within tolerance")

        if lat_curr > 25.0:
            dev_score += 15.0
            factors.append("Elevated fabric transit latency")

        dev_score = min(98.0, round(dev_score, 1))
        d_risk_lvl = get_risk_level(dev_score)

        device_risks.append({
            "device": d_id,
            "name": n.get("name", d_id),
            "type": d_type,
            "role": d_role,
            "risk_score": dev_score,
            "risk_level": d_risk_lvl,
            "factors": factors,
            "confidence": 85 if d_type == "switch" else 80
        })

    # Sort devices by highest risk first
    device_risks.sort(key=lambda d: d["risk_score"], reverse=True)

    # 6. Top Predictive Risks
    top_risks = []
    if device_risks and device_risks[0]["risk_score"] > 25.0:
        top_d = device_risks[0]
        top_risks.append({
            "target": top_d["device"],
            "risk": f"{top_d['device']} — {top_d['factors'][0]}",
            "risk_level": top_d["risk_level"],
            "confidence": f"{top_d['confidence']}%",
            "recommended_action": f"Inspect {top_d['device']} queue buffers and verify OpenFlow rate policies."
        })

    if tp_trend == "INCREASING":
        top_risks.append({
            "target": "Core Mesh Fabric",
            "risk": "Bandwidth Utilization — Upward trajectory detected",
            "risk_level": "MODERATE" if tp_curr < 70.0 else "HIGH",
            "confidence": "82%",
            "recommended_action": "Evaluate ECMP alternate paths or schedule rate-limiting."
        })

    if lat_stats.get("trend") == "INCREASING":
        top_risks.append({
            "target": "Mesh Links (S1-S4)",
            "risk": "Transit Latency — Gradual delay deterioration",
            "risk_level": "MODERATE",
            "confidence": "76%",
            "recommended_action": "Check inter-switch port congestion and DSCP EF priority queueing."
        })

    if not top_risks:
        top_risks.append({
            "target": "Network Fabric",
            "risk": "Baseline Stable — No critical predictive anomalies detected",
            "risk_level": "LOW",
            "confidence": "90%",
            "recommended_action": "Continue automated telemetry monitoring."
        })

    return {
        "network_risk": int(composite_score),
        "risk_level": risk_level,
        "traffic_risk": int(traffic_risk),
        "security_risk": int(security_risk),
        "qos_risk": int(qos_risk),
        "device_risks": device_risks,
        "top_risks": top_risks
    }
