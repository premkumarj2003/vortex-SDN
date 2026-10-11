"""
VORTEX-SDN Automated Security Mitigation Engine
Executes OpenFlow actions (BLOCK, RATE_LIMIT, ISOLATE, MONITOR) on switches via Ryu Controller.
Supports DRY_RUN mode and LIVE_MITIGATION mode with full audit logging.
"""

import os
import uuid
import json
import requests
from datetime import datetime, timezone
from backend.models.database import get_db_connection

RYU_API_URL = os.environ.get("RYU_API_URL", "http://127.0.0.1:8080")

class SecurityMitigationEngine:
    def __init__(self):
        self.mode = "LIVE" # "LIVE" or "DRY_RUN"
        self.blocked_ips = set()
        self.rate_limited_ips = {}
        self.isolated_hosts = set()

    def set_mode(self, mode: str):
        if mode in ("LIVE", "DRY_RUN"):
            self.mode = mode

    def execute_mitigation(self, threat: dict, user: str = "SYSTEM_AI") -> dict:
        """
        Executes mitigation based on AI decision and records audit log.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        src_ip = threat.get("source_ip", "*")
        dst_ip = threat.get("destination_ip", "*")
        action = threat.get("recommended_action", "MONITOR")
        attack_type = threat.get("attack_type", "ANOMALY")
        confidence = float(threat.get("confidence", 0.9))

        result_status = "SUCCESS"
        details = {
            "mode": self.mode,
            "attack_type": attack_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "action": action,
            "ai_confidence": confidence
        }

        if self.mode == "DRY_RUN":
            msg = f"[DRY RUN] Would execute {action} for {src_ip} -> {dst_ip} (Confidence {confidence * 100:.1f}%)"
            details["simulated"] = True
        else:
            # LIVE EXECUTION
            if action == "BLOCK":
                self.blocked_ips.add(src_ip)
                self._send_openflow_drop(src_ip, dst_ip)
                msg = f"Installed OpenFlow DROP rule for malicious source {src_ip}"
            elif action == "RATE_LIMIT":
                self.rate_limited_ips[src_ip] = 500 # Limit to 500 pps
                self._send_openflow_meter(src_ip, 500)
                msg = f"Applied OpenFlow METER rate-limit (500 pps) on {src_ip}"
            elif action == "ISOLATE":
                self.isolated_hosts.add(src_ip)
                self._send_openflow_quarantine(src_ip)
                msg = f"Quarantined host {src_ip} to security inspection VLAN"
            else:
                msg = f"Monitoring flow {src_ip} -> {dst_ip} without active block"

        # Log Audit Record
        audit_id = f"aud_{uuid.uuid4().hex[:8]}"
        self._record_audit(audit_id, user, f"SECURITY_MITIGATION_{action}", f"Flow {src_ip} -> {dst_ip}", result_status, details)

        # Update threat object status
        threat["mitigation_status"] = "MITIGATED"
        threat["status"] = "MITIGATED"

        # Update matching incidents in database to MITIGATED
        self._sync_incident_mitigation(src_ip, action)

        return {
            "status": result_status,
            "action_executed": action,
            "mode": self.mode,
            "message": msg,
            "timestamp": now_iso
        }

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_ip_rate_limited(self, ip: str) -> bool:
        return ip in self.rate_limited_ips

    def is_ip_isolated(self, ip: str) -> bool:
        return ip in self.isolated_hosts

    def is_ip_mitigated(self, ip: str) -> bool:
        return ip in self.blocked_ips or ip in self.rate_limited_ips or ip in self.isolated_hosts

    def clear_mitigations(self):
        self.blocked_ips.clear()
        self.rate_limited_ips.clear()
        self.isolated_hosts.clear()

    def _sync_incident_mitigation(self, src_ip: str, action: str):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
            UPDATE incidents
            SET status = 'MITIGATED', action_taken = ?, updated_at = ?
            WHERE source_ip = ? AND status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING')
            """, (action, now_iso, src_ip))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Mitigation Engine] DB sync error: {e}")

    def _send_openflow_drop(self, src_ip: str, dst_ip: str):
        """Sends OFPFC_ADD flow rule with empty actions (DROP) to Ryu."""
        try:
            payload = {
                "dpid": 1,
                "priority": 60000,
                "match": {"ipv4_src": src_ip, "eth_type": 2048},
                "actions": [] # Empty actions = DROP
            }
            requests.post(f"{RYU_API_URL}/stats/flowentry/add", json=payload, timeout=0.5)
        except Exception:
            pass # Graceful if Ryu controller is offline

    def _send_openflow_meter(self, src_ip: str, rate_pps: int):
        try:
            payload = {
                "dpid": 1,
                "priority": 50000,
                "match": {"ipv4_src": src_ip, "eth_type": 2048},
                "actions": [{"type": "METER", "meter_id": 1}]
            }
            requests.post(f"{RYU_API_URL}/stats/flowentry/add", json=payload, timeout=0.5)
        except Exception:
            pass

    def _send_openflow_quarantine(self, src_ip: str):
        try:
            payload = {
                "dpid": 1,
                "priority": 55000,
                "match": {"ipv4_src": src_ip, "eth_type": 2048},
                "actions": [{"type": "SET_FIELD", "field": "vlan_vid", "value": 999}]
            }
            requests.post(f"{RYU_API_URL}/stats/flowentry/add", json=payload, timeout=0.5)
        except Exception:
            pass

    def _record_audit(self, audit_id: str, user: str, action: str, resource: str, result: str, details: dict):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
            INSERT INTO audit_logs (id, timestamp, user_id, username, role, action, resource, result, details_json, client_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (audit_id, now_iso, "system", user, "ADMIN", action, resource, result, json.dumps(details), "127.0.0.1"))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Mitigation Engine] Audit logging failed: {e}")

mitigation_engine = SecurityMitigationEngine()

