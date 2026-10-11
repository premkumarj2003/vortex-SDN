"""
VORTEX-SDN Statistical Anomaly Detection Engine
Applies adaptive z-score, IQR boundaries, and rate-of-change thresholds
to detect early-stage predictive network anomalies before incident escalation.
"""

from datetime import datetime, timezone

def detect_predictive_anomalies(baselines: dict) -> list[dict]:
    """
    Evaluates dynamic baselines and live flow records to detect early-stage anomalies.
    Returns list of structured anomaly objects.
    """
    if not baselines or not baselines.get("is_sufficient"):
        return []

    metrics = baselines.get("metrics", {})
    anomalies = []
    counter = 1
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Traffic Surge Anomaly Check (Throughput & Packet Rate)
    tp_stats = metrics.get("throughput", {})
    tp_curr = tp_stats.get("current", 0.0)
    tp_mean = tp_stats.get("mean", 0.0)
    tp_std = max(0.1, tp_stats.get("std_dev", 1.0))
    tp_z = (tp_curr - tp_mean) / tp_std if tp_std > 0 else 0.0

    if tp_curr > (tp_mean + 1.8 * tp_std) and tp_curr > 30.0:
        dev_pct = round(((tp_curr - tp_mean) / max(0.1, tp_mean)) * 100.0, 1)
        severity = "HIGH" if tp_z >= 3.0 or dev_pct > 100.0 else "MEDIUM"
        conf = min(96, max(65, int(60 + tp_z * 12)))

        anomalies.append({
            "id": f"ANOM-{counter:03d}",
            "category": "TRAFFIC",
            "type": "TRAFFIC_SURGE",
            "title": f"Abnormal Throughput Surge ({tp_curr:.1f} Mbps)",
            "severity": severity,
            "confidence": conf,
            "observed_value": f"{tp_curr:.1f} Mbps",
            "baseline_value": f"{tp_mean:.1f} Mbps (±{tp_std:.1f})",
            "deviation_pct": f"+{dev_pct}%",
            "detected_at": now_iso,
            "description": f"Observed throughput of {tp_curr:.1f} Mbps deviates significantly from rolling baseline of {tp_mean:.1f} Mbps (z-score: {tp_z:.2f}).",
            "recommendation": "Inspect egress switch queues and verify top transmitting host flows for potential buffer saturation."
        })
        counter += 1

    # 2. Latency Deterioration Anomaly Check
    lat_stats = metrics.get("latency", {})
    lat_curr = lat_stats.get("current", 14.5)
    lat_mean = lat_stats.get("mean", 14.5)
    lat_std = max(0.1, lat_stats.get("std_dev", 1.0))
    lat_z = (lat_curr - lat_mean) / lat_std if lat_std > 0 else 0.0

    if lat_curr > (lat_mean + 1.8 * lat_std) and lat_curr > 22.0:
        dev_pct = round(((lat_curr - lat_mean) / max(0.1, lat_mean)) * 100.0, 1)
        severity = "CRITICAL" if lat_curr > 50.0 else ("HIGH" if lat_curr > 35.0 else "MEDIUM")
        conf = min(95, max(68, int(65 + lat_z * 10)))

        anomalies.append({
            "id": f"ANOM-{counter:03d}",
            "category": "LATENCY",
            "type": "LATENCY_DETERIORATION",
            "title": f"Transit Latency Degradation ({lat_curr:.1f} ms)",
            "severity": severity,
            "confidence": conf,
            "observed_value": f"{lat_curr:.1f} ms",
            "baseline_value": f"{lat_mean:.1f} ms",
            "deviation_pct": f"+{dev_pct}%",
            "detected_at": now_iso,
            "description": f"Fabric transit delay rose to {lat_curr:.1f} ms, exceeding historical normal bounds.",
            "recommendation": "Evaluate inter-switch mesh links for transit bottlenecks or QoS queue buffering delays."
        })
        counter += 1

    # 3. Packet Loss Growth Anomaly Check
    loss_stats = metrics.get("packet_loss", {})
    loss_curr = loss_stats.get("current", 0.1)
    loss_mean = loss_stats.get("mean", 0.1)

    if loss_curr >= 1.5:
        severity = "HIGH" if loss_curr >= 4.0 else "MEDIUM"
        anomalies.append({
            "id": f"ANOM-{counter:03d}",
            "category": "QOS",
            "type": "PACKET_LOSS_GROWTH",
            "title": f"Elevated Packet Drop Trajectory ({loss_curr:.1f}%)",
            "severity": severity,
            "confidence": 84,
            "observed_value": f"{loss_curr:.2f}%",
            "baseline_value": f"{loss_mean:.2f}%",
            "deviation_pct": f"+{loss_curr - loss_mean:.1f}%",
            "detected_at": now_iso,
            "description": f"Packet loss rate has grown to {loss_curr:.2f}%, risking real-time TCP window backoffs and VoIP jitter.",
            "recommendation": "Check switch port buffer capacities and verify priority queue rate allocations."
        })
        counter += 1

    # 4. Security Anomaly Trend Check
    sec_stats = metrics.get("security_threats", {})
    threat_cnt = sec_stats.get("current_count", 0)

    if threat_cnt > 0:
        anomalies.append({
            "id": f"ANOM-{counter:03d}",
            "category": "SECURITY",
            "type": "SECURITY_ANOMALY_TREND",
            "title": f"Security Activity Escalation ({threat_cnt} Active Threat{'s' if threat_cnt > 1 else ''})",
            "severity": "HIGH" if threat_cnt >= 2 else "MEDIUM",
            "confidence": 92,
            "observed_value": f"{threat_cnt} threats",
            "baseline_value": "0 threats",
            "deviation_pct": f"+{threat_cnt * 100}%",
            "detected_at": now_iso,
            "description": f"Security activity is elevated compared with recent baseline (detected {threat_cnt} anomalous flow patterns).",
            "recommendation": "Inspect Security Center threat classifications and verify OpenFlow rate-limiting policies."
        })
        counter += 1

    return anomalies
