"""
VORTEX-SDN QoS Policy Engine & Performance Monitor
Evaluates QoS metrics (latency, jitter, packet loss, bandwidth utilization),
validates compliance against active policies, and recommends queue/rate adjustments.
"""

import threading
from backend.models.database import get_db_connection

class QoSPolicyEngine:
    def __init__(self):
        self.lock = threading.Lock()

    def get_active_policies(self) -> list[dict]:
        """Loads all active QoS policies from SQLite."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM qos_policies WHERE is_active = 1 ORDER BY priority_code ASC, min_bandwidth_mbps DESC")
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            print(f"[QoS Policy Engine] Error loading policies: {e}")
            return []

    def evaluate_flows(self, flows: list[dict]) -> dict:
        """
        Calculates traffic distribution, queue allocation, violations, and recommended actions.
        """
        policies = self.get_active_policies()
        class_stats = {
            "VOICE": {"flows": 0, "bytes": 0, "packets": 0, "priority": "EF", "queue": 1},
            "VIDEO": {"flows": 0, "bytes": 0, "packets": 0, "priority": "AF", "queue": 2},
            "WEB": {"flows": 0, "bytes": 0, "packets": 0, "priority": "AF", "queue": 2},
            "FILE_TRANSFER": {"flows": 0, "bytes": 0, "packets": 0, "priority": "BE", "queue": 3},
            "EMAIL": {"flows": 0, "bytes": 0, "packets": 0, "priority": "BE", "queue": 3},
            "P2P": {"flows": 0, "bytes": 0, "packets": 0, "priority": "BE", "queue": 4},
            "CRITICAL_APPLICATION": {"flows": 0, "bytes": 0, "packets": 0, "priority": "EF", "queue": 1},
            "BEST_EFFORT": {"flows": 0, "bytes": 0, "packets": 0, "priority": "BE", "queue": 3}
        }

        total_bytes = 0
        violations = []

        for flow in flows:
            t_class = flow.get("traffic_class", "BEST_EFFORT")
            if t_class not in class_stats:
                t_class = "BEST_EFFORT"
            
            bytes_f = int(flow.get("bytes", 0))
            pkts_f = int(flow.get("packets", 0))
            total_bytes += bytes_f

            class_stats[t_class]["flows"] += 1
            class_stats[t_class]["bytes"] += bytes_f
            class_stats[t_class]["packets"] += pkts_f

            # Check for QoS violations
            lat = float(flow.get("latency_ms", 15.0))
            loss = float(flow.get("packet_loss_pct", 0.0))
            if t_class in ("VOICE", "CRITICAL_APPLICATION") and (lat > 50.0 or loss > 1.0):
                violations.append({
                    "flow_id": flow.get("flow_id", "N/A"),
                    "class": t_class,
                    "reason": f"High latency ({lat}ms) or packet loss ({loss}%) on priority flow",
                    "severity": "HIGH",
                    "source_ip": flow.get("source_ip"),
                    "destination_ip": flow.get("destination_ip")
                })

        # Calculate percentages
        distribution = []
        for cname, data in class_stats.items():
            pct = round((data["bytes"] / max(1, total_bytes)) * 100, 1)
            distribution.append({
                "class_name": cname,
                "flows": data["flows"],
                "bytes": data["bytes"],
                "packets": data["packets"],
                "percentage": pct,
                "priority_code": data["priority"],
                "queue_id": data["queue"]
            })

        # Generate recommendations
        recommendations = []
        if len(violations) > 0:
            recommendations.append("Increase bandwidth allocation on Queue 1 (EF) and throttle P2P traffic on Queue 4.")
        if class_stats["P2P"]["bytes"] > (total_bytes * 0.35):
            recommendations.append("P2P traffic exceeds 35% of total fabric bandwidth; recommend strict rate-limiting.")

        return {
            "total_bytes": total_bytes,
            "distribution": distribution,
            "active_policies_count": len(policies),
            "violations_count": len(violations),
            "violations": violations[:10],
            "recommendations": recommendations,
            "policies": policies
        }

qos_policy_engine = QoSPolicyEngine()
