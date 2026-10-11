"""
VORTEX-SDN Simulation & Demo Scenario Engine
Provides 8 dynamic stateful simulation scenarios for evaluating SDN intelligence:
1. NORMAL NETWORK (Benign baseline traffic)
2. DDoS ATTACK (Flood from h4 to h1, AI critical alert, incident creation, mitigation recommendation)
3. PORT SCAN (Rapid multi-port probe, AI high alert)
4. BRUTE FORCE (SSH authentication burst, AI high alert)
5. NETWORK CONGESTION (Bandwidth saturation, packet loss, high latency)
6. QOS DEGRADATION (Jitter spikes, priority voice/video degradation)
7. HIGH LATENCY (Link transit delay spike)
8. RECOVERY (Mitigation applied, health restoration)

Explicitly stamps all generated data with "source": "DEMO" and feeds into Telemetry & AI pipelines.
"""

import time
import random
import threading
from datetime import datetime, timezone
from telemetry.flow_monitor import flow_monitor
from security.detector import security_detector
from security.mitigation import mitigation_engine
from qos.classifier import qos_classifier
from qos.policy_engine import qos_policy_engine
from backend.services.incident_service import create_incident
from backend.services.notification_service import create_notification
from backend.services.audit_service import log_audit_event

class DemoSimulationEngine:
    def __init__(self):
        self.current_scenario = "NORMAL"
        self.is_running = True
        self.lock = threading.Lock()
        self.scenario_start_time = time.time()
        self.worker_thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self.worker_thread.start()

    def set_scenario(self, scenario_name: str) -> dict:
        """Switches the active simulation scenario and triggers matching security/QoS events."""
        valid_scenarios = [
            "NORMAL", "DDOS_ATTACK", "PORT_SCAN", "BRUTE_FORCE",
            "NETWORK_CONGESTION", "QOS_DEGRADATION", "HIGH_LATENCY", "RECOVERY"
        ]
        scenario_name = scenario_name.upper().replace(" ", "_")
        if scenario_name not in valid_scenarios:
            scenario_name = "NORMAL"

        with self.lock:
            self.current_scenario = scenario_name
            self.scenario_start_time = time.time()

            if scenario_name == "RECOVERY" or scenario_name == "NORMAL":
                security_detector.clear_threats()
                mitigation_engine.clear_mitigations()
                flow_monitor.reset_health(98.0, 95.0, 92.0)
                if scenario_name == "RECOVERY":
                    create_notification("System", "Network Recovery Completed", "Mitigation policies enforced. Baseline flow health restored to 99.8%.", "INFO", "dashboard")
            elif scenario_name == "DDOS_ATTACK":
                mitigation_engine.clear_mitigations()
                create_incident("CRITICAL", "Security", "10.0.0.4", "10.0.0.1", "DDoS UDP flood anomaly detected by Random Forest model (18,000 pps)", 0.94, 94.5, "BLOCK")
                create_notification("Security", "CRITICAL: DDoS UDP Flood Detected", "High-rate flood from 10.0.0.4 targeting 10.0.0.1 (18,000 pps).", "CRITICAL", "security")
            elif scenario_name == "PORT_SCAN":
                mitigation_engine.clear_mitigations()
                create_incident("HIGH", "Security", "10.0.0.4", "10.0.0.2", "Rapid port reconnaissance probe detected across ports 20-8080", 0.88, 82.0, "ISOLATE")
                create_notification("Security", "HIGH: Port Scanning Detected", "Host 10.0.0.4 probing multiple switch ports rapidly.", "HIGH", "security")
            elif scenario_name == "BRUTE_FORCE":
                mitigation_engine.clear_mitigations()
                create_incident("HIGH", "Security", "10.0.0.4", "10.0.0.2", "SSH authentication burst failure on port 22", 0.85, 78.0, "BLOCK")
                create_notification("Security", "HIGH: SSH Brute Force Detected", "Repetitive auth burst on host 10.0.0.2:22.", "HIGH", "security")
            elif scenario_name == "NETWORK_CONGESTION":
                mitigation_engine.clear_mitigations()
                create_incident("MEDIUM", "QoS", "10.0.0.3", "10.0.0.1", "Bulk FTP transfer saturating core link bandwidth (92%)", 0.90, 65.0, "RATE_LIMIT")
                create_notification("QoS", "MEDIUM: Network Congestion Warning", "Link bandwidth saturation at 92%, latency climbing.", "MEDIUM", "qos")
            elif scenario_name == "QOS_DEGRADATION":
                mitigation_engine.clear_mitigations()
                create_incident("MEDIUM", "QoS", "10.0.0.1", "10.0.0.3", "VoIP and video jitter degradation (28ms) violating SLA", 0.86, 60.0, "ALERT")
                create_notification("QoS", "MEDIUM: Voice/Video QoS SLA Degradation", "Jitter increased to 28ms on voice/video queues.", "MEDIUM", "qos")

            log_audit_event("OPERATOR", "OPERATOR", "SCENARIO_SWITCH", f"Simulation scenario set to {scenario_name}", "SUCCESS", {"scenario": scenario_name})

        return {
            "status": "SUCCESS",
            "active_scenario": self.current_scenario,
            "message": f"Simulation scenario changed to: {self.current_scenario}",
            "source": "DEMO",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def get_status(self) -> dict:
        return {
            "active_scenario": self.current_scenario,
            "elapsed_seconds": round(time.time() - self.scenario_start_time, 1),
            "source": "DEMO",
            "is_running": self.is_running
        }

    def _simulation_loop(self):
        """Continuously generates realistic telemetry batches every 3-5 seconds."""
        # Initial benign seed
        time.sleep(1.0)
        while self.is_running:
            try:
                flows = self._generate_flows_for_scenario(self.current_scenario)
                
                # Ingest into Telemetry Monitor
                processed = flow_monitor.ingest_observations(flows, source_type="DEMO")

                # Evaluate through Security AI & QoS AI
                for flow in processed:
                    security_detector.evaluate_flow(flow)
                    qos_classifier.classify_flow(flow)

            except Exception as e:
                print(f"[Demo Engine] Error in simulation loop: {e}")

            time.sleep(3.5)

    def _generate_flows_for_scenario(self, scenario: str) -> list[dict]:
        """Generates realistic flow observations matching the selected scenario and active mitigation rules."""
        now_iso = datetime.now(timezone.utc).isoformat()
        flows = []

        is_h4_blocked = mitigation_engine.is_ip_blocked("10.0.0.4") or mitigation_engine.is_ip_isolated("10.0.0.4")
        is_h4_rate_limited = mitigation_engine.is_ip_rate_limited("10.0.0.4")
        is_h1_congested_blocked = mitigation_engine.is_ip_blocked("10.0.0.1") or mitigation_engine.is_ip_rate_limited("10.0.0.3")

        # 1. Base Benign Flows (Always present in background)
        # Flow A: VoIP Call (h2 -> h3, UDP port 5060)
        voip_lat = 12.5 if (scenario not in ("HIGH_LATENCY", "QOS_DEGRADATION") or is_h4_blocked) else 85.0
        flows.append({
            "flow_id": "flw_voip_01",
            "dpid": "0000000000000003",
            "in_port": 1,
            "source_mac": "00:00:00:00:00:02",
            "destination_mac": "00:00:00:00:00:03",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.3",
            "source_port": 5060,
            "destination_port": 5060,
            "protocol": "UDP",
            "protocol_num": 17,
            "packets": int(random.uniform(220, 260) * 10),
            "bytes": int(random.uniform(220, 260) * 10 * 160),
            "duration": 45.0,
            "packet_size": 160,
            "latency_ms": voip_lat,
            "jitter_ms": 1.8 if (scenario != "QOS_DEGRADATION" or is_h4_blocked) else 28.5,
            "packet_loss_pct": 0.01 if (scenario != "QOS_DEGRADATION" or is_h4_blocked) else 4.8,
            "unique_destinations": 1,
            "connection_frequency": 1.0,
            "destination_frequency": 2.0,
            "source_frequency": 2.0
        })

        # Flow B: Video Stream (h3 -> h1, TCP port 1935 / 8080)
        video_lat = 22.0 if (scenario not in ("HIGH_LATENCY", "QOS_DEGRADATION") or is_h4_blocked) else 75.0
        flows.append({
            "flow_id": "flw_video_02",
            "dpid": "0000000000000002",
            "in_port": 1,
            "source_mac": "00:00:00:00:00:03",
            "destination_mac": "00:00:00:00:00:01",
            "source_ip": "10.0.0.3",
            "destination_ip": "10.0.0.1",
            "source_port": 49152,
            "destination_port": 1935,
            "protocol": "TCP",
            "protocol_num": 6,
            "packets": int(random.uniform(380, 420) * 15),
            "bytes": int(random.uniform(380, 420) * 15 * 1350),
            "duration": 60.0,
            "packet_size": 1350,
            "latency_ms": video_lat,
            "jitter_ms": 4.2 if (scenario != "QOS_DEGRADATION" or is_h4_blocked) else 19.4,
            "packet_loss_pct": 0.05 if (scenario != "QOS_DEGRADATION" or is_h4_blocked) else 3.2,
            "unique_destinations": 1,
            "connection_frequency": 2.0,
            "destination_frequency": 5.0,
            "source_frequency": 5.0
        })

        # Flow C: Web Traffic (h2 -> h1, TCP port 443)
        web_lat = 16.0 if (scenario != "HIGH_LATENCY" or is_h4_blocked) else 92.0
        flows.append({
            "flow_id": "flw_web_03",
            "dpid": "0000000000000001",
            "in_port": 2,
            "source_mac": "00:00:00:00:00:02",
            "destination_mac": "00:00:00:00:00:01",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "protocol_num": 6,
            "packets": int(random.uniform(40, 80) * 8),
            "bytes": int(random.uniform(40, 80) * 8 * 850),
            "duration": 20.0,
            "packet_size": 850,
            "latency_ms": web_lat,
            "jitter_ms": 2.5,
            "packet_loss_pct": 0.02,
            "unique_destinations": 1,
            "connection_frequency": 3.0,
            "destination_frequency": 8.0,
            "source_frequency": 8.0
        })

        # 2. Scenario-Specific Flows (Suppressed or normalized if attacker IP is mitigated/blocked)
        if scenario == "DDOS_ATTACK" and not is_h4_blocked:
            rate_mult = 0.02 if is_h4_rate_limited else 1.0
            flows.append({
                "flow_id": "flw_atk_ddos_01",
                "dpid": "0000000000000004",
                "in_port": 1,
                "source_mac": "00:00:00:00:00:04",
                "destination_mac": "00:00:00:00:00:01",
                "source_ip": "10.0.0.4",
                "destination_ip": "10.0.0.1",
                "source_port": random.randint(10000, 65000),
                "destination_port": 80,
                "protocol": "UDP",
                "protocol_num": 17,
                "packets": int(random.uniform(28000, 35000) * 10 * rate_mult),
                "bytes": int(random.uniform(28000, 35000) * 10 * 512 * rate_mult),
                "duration": 30.0,
                "packet_size": 512,
                "latency_ms": 65.0 if not is_h4_rate_limited else 18.0,
                "jitter_ms": 14.0 if not is_h4_rate_limited else 2.5,
                "packet_loss_pct": 2.5 if not is_h4_rate_limited else 0.02,
                "unique_destinations": 1,
                "connection_frequency": 65.0,
                "destination_frequency": 120.0,
                "source_frequency": 110.0
            })

        elif scenario == "PORT_SCAN" and not is_h4_blocked:
            for p in random.sample([21, 22, 23, 25, 80, 110, 443, 3389, 8080], 4):
                flows.append({
                    "flow_id": f"flw_atk_scan_{p}",
                    "dpid": "0000000000000004",
                    "in_port": 1,
                    "source_mac": "00:00:00:00:00:04",
                    "destination_mac": "00:00:00:00:00:01",
                    "source_ip": "10.0.0.4",
                    "destination_ip": "10.0.0.1",
                    "source_port": random.randint(30000, 60000),
                    "destination_port": p,
                    "protocol": "TCP",
                    "protocol_num": 6,
                    "packets": int(random.uniform(1800, 2400) * 2),
                    "bytes": int(random.uniform(1800, 2400) * 2 * 60),
                    "duration": 3.0,
                    "packet_size": 60,
                    "latency_ms": 18.0,
                    "jitter_ms": 3.0,
                    "packet_loss_pct": 0.0,
                    "unique_destinations": 35,
                    "connection_frequency": 35.0,
                    "destination_frequency": 1.0,
                    "source_frequency": 45.0
                })

        elif scenario == "BRUTE_FORCE" and not is_h4_blocked:
            flows.append({
                "flow_id": "flw_atk_brute_01",
                "dpid": "0000000000000004",
                "in_port": 1,
                "source_mac": "00:00:00:00:00:04",
                "destination_mac": "00:00:00:00:00:02",
                "source_ip": "10.0.0.4",
                "destination_ip": "10.0.0.2",
                "source_port": random.randint(40000, 60000),
                "destination_port": 22,
                "protocol": "TCP",
                "protocol_num": 6,
                "packets": int(random.uniform(450, 700) * 5),
                "bytes": int(random.uniform(450, 700) * 5 * 120),
                "duration": 12.0,
                "packet_size": 120,
                "latency_ms": 25.0,
                "jitter_ms": 4.5,
                "packet_loss_pct": 0.05,
                "unique_destinations": 1,
                "connection_frequency": 25.0,
                "destination_frequency": 18.0,
                "source_frequency": 22.0
            })

        elif scenario == "NETWORK_CONGESTION" and not is_h1_congested_blocked:
            flows.append({
                "flow_id": "flw_cong_ftp_01",
                "dpid": "0000000000000001",
                "in_port": 1,
                "source_mac": "00:00:00:00:00:01",
                "destination_mac": "00:00:00:00:00:03",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.3",
                "source_port": 21,
                "destination_port": 50000,
                "protocol": "TCP",
                "protocol_num": 6,
                "packets": int(random.uniform(8500, 11000) * 10),
                "bytes": int(random.uniform(8500, 11000) * 10 * 1460),
                "duration": 90.0,
                "packet_size": 1460,
                "latency_ms": 78.0,
                "jitter_ms": 16.0,
                "packet_loss_pct": 3.8,
                "unique_destinations": 1,
                "connection_frequency": 5.0,
                "destination_frequency": 15.0,
                "source_frequency": 15.0
            })

        return flows

demo_engine = DemoSimulationEngine()

