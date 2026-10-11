"""
VORTEX-SDN Security Threat Detector
Processes flow streams through the AI Inference Engine, generates security events,
manages threat tables, and automatically raises Incidents & Notifications for high/critical threats.
"""

import os
import uuid
import time
import threading
from datetime import datetime, timezone
from ai.inference import ai_engine
from security.feature_engineering import extract_security_features
from backend.models.database import get_db_connection

class SecurityDetector:
    def __init__(self):
        self.active_threats = {} # key: threat_id -> threat_dict
        self.mitigated_threats = []
        self.lock = threading.Lock()

    def evaluate_flow(self, flow: dict) -> dict:
        """
        Extracts features, runs AI inference, updates flow dictionary with prediction results,
        and creates security events / incidents / auto-mitigates if an attack is detected.
        """
        features = extract_security_features(flow)
        prediction = ai_engine.predict_security(features)

        # Merge prediction into flow
        flow["threat_label"] = prediction["label"]
        flow["attack_type"] = prediction["attack_type"]
        flow["ai_confidence"] = prediction["confidence"]
        flow["risk_score"] = prediction["risk_score"]
        flow["severity"] = prediction["severity"]
        flow["recommended_action"] = prediction["recommended_action"]

        if prediction["label"] == "ATTACK":
            self._handle_detected_threat(flow, prediction)

        return flow

    def _handle_detected_threat(self, flow: dict, prediction: dict):
        threat_key = f"{flow.get('source_ip')}_{flow.get('attack_type')}_{flow.get('destination_ip')}"
        now_iso = datetime.now(timezone.utc).isoformat()
        src_ip = flow.get("source_ip", "Unknown")
        
        with self.lock:
            if threat_key not in self.active_threats:
                threat_id = f"thr_{uuid.uuid4().hex[:8]}"
                threat_record = {
                    "id": threat_id,
                    "timestamp": now_iso,
                    "attack_type": prediction["attack_type"],
                    "source_ip": src_ip,
                    "destination_ip": flow.get("destination_ip", "Unknown"),
                    "protocol": flow.get("protocol", "TCP"),
                    "packet_rate": flow.get("packet_rate", 0),
                    "byte_rate": flow.get("byte_rate", 0),
                    "confidence": prediction["confidence"],
                    "risk_score": prediction["risk_score"],
                    "severity": prediction["severity"],
                    "recommended_action": prediction["recommended_action"],
                    "status": "ACTIVE",
                    "mitigation_status": "ACTIVE",
                    "flow_id": flow.get("flow_id", "N/A"),
                    "created_epoch": time.time()
                }
                self.active_threats[threat_key] = threat_record

                # Record in Database & Create Incident/Notification asynchronously
                threading.Thread(target=self._persist_threat_and_incident, args=(threat_record,), daemon=True).start()

                # Trigger Auto-Mitigation for HIGH and CRITICAL threats
                if prediction["severity"] in ("CRITICAL", "HIGH"):
                    threading.Thread(target=self._auto_mitigate, args=(threat_record,), daemon=True).start()
            else:
                # Update existing threat counters
                self.active_threats[threat_key]["packet_rate"] = flow.get("packet_rate", 0)
                self.active_threats[threat_key]["byte_rate"] = flow.get("byte_rate", 0)
                self.active_threats[threat_key]["risk_score"] = prediction["risk_score"]

    def _auto_mitigate(self, threat: dict):
        """Executes auto-mitigation pipeline for HIGH/CRITICAL threats."""
        try:
            threat["mitigation_status"] = "IN_PROGRESS"
            from security.mitigation import mitigation_engine
            mitigation_engine.execute_mitigation(threat, user="AUTO_MITIGATION_AI")
            with self.lock:
                threat["mitigation_status"] = "MITIGATED"
                threat["status"] = "MITIGATED"
                threat["mitigated_at"] = time.time()
        except Exception as e:
            print(f"[Security Detector] Auto-mitigation error: {e}")

    def mark_threat_mitigated(self, threat_id: str, action: str = None):
        """Marks a threat as MITIGATED by threat_id (for manual or API-driven mitigation)."""
        with self.lock:
            for threat in self.active_threats.values():
                if threat.get("id") == threat_id:
                    threat["status"] = "MITIGATED"
                    threat["mitigation_status"] = "MITIGATED"
                    threat["mitigated_at"] = time.time()
                    if action:
                        threat["recommended_action"] = action

    def verify_and_clear_threats(self):
        """
        Verifies whether mitigated threats have normalized and clears them from active penalty.
        Transitions: MITIGATED -> CLEARED -> moved to mitigated_threats archive.
        """
        now = time.time()
        from security.mitigation import mitigation_engine
        with self.lock:
            to_clear = []
            for key, threat in self.active_threats.items():
                status = threat.get("status", "ACTIVE")
                mit_status = threat.get("mitigation_status", "ACTIVE")
                src_ip = threat.get("source_ip")
                
                is_blocked = mitigation_engine.is_ip_blocked(src_ip)
                mitigated_at = threat.get("mitigated_at", 0)
                elapsed = (now - mitigated_at) if mitigated_at else 0

                # Threat is verified cleared if mitigated & stabilized, or IP is actively blocked with dropped traffic
                if status == "MITIGATED" or mit_status in ("MITIGATED", "IN_PROGRESS") or is_blocked:
                    if elapsed >= 1.5 or is_blocked:
                        threat["status"] = "CLEARED"
                        threat["mitigation_status"] = "CLEARED"
                        threat["cleared_at"] = now
                        to_clear.append(key)
                        self.mitigated_threats.append(threat)

            for key in to_clear:
                del self.active_threats[key]

    def _persist_threat_and_incident(self, threat: dict):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 1. Insert into security_events
            cursor.execute("""
            INSERT INTO security_events (id, timestamp, label, attack_type, source_ip, destination_ip, protocol, packet_rate, byte_rate, confidence, risk_score, severity, recommended_action, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (threat["id"], threat["timestamp"], "ATTACK", threat["attack_type"], threat["source_ip"], threat["destination_ip"], threat["protocol"], threat["packet_rate"], threat["byte_rate"], threat["confidence"], threat["risk_score"], threat["severity"], threat["recommended_action"], threat["status"]))

            # 2. If HIGH or CRITICAL, create an Incident
            if threat["severity"] in ("CRITICAL", "HIGH"):
                inc_id = f"inc_{uuid.uuid4().hex[:8]}"
                desc = f"AI Detector identified {threat['attack_type']} attack from {threat['source_ip']} targeting {threat['destination_ip']} ({threat['packet_rate']} pps, Risk {threat['risk_score']}). Action: {threat['recommended_action']}."
                cursor.execute("""
                INSERT INTO incidents (id, timestamp, severity, category, source_ip, destination_ip, description, ai_confidence, risk_score, status, action_taken, assigned_to, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (inc_id, threat["timestamp"], threat["severity"], "SECURITY", threat["source_ip"], threat["destination_ip"], desc, threat["confidence"], threat["risk_score"], "OPEN", threat["recommended_action"], "Unassigned", threat["timestamp"]))

                # 3. Create High-Priority Notification
                notif_id = f"notif_{uuid.uuid4().hex[:8]}"
                cursor.execute("""
                INSERT INTO notifications (id, timestamp, category, title, message, severity, is_read, link)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """, (notif_id, threat["timestamp"], "Security", f"CRITICAL Threat: {threat['attack_type']} Detected", desc, threat["severity"], "/incidents"))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Security Detector] DB Error logging threat: {e}")

    def get_summary(self) -> dict:
        """Returns security posture summary after verifying and clearing normalized threats."""
        self.verify_and_clear_threats()

        with self.lock:
            active_list = [t for t in self.active_threats.values() if t.get("status") == "ACTIVE"]
            
        critical_count = sum(1 for t in active_list if t.get("severity") == "CRITICAL")
        high_count = sum(1 for t in active_list if t.get("severity") == "HIGH")
        medium_count = sum(1 for t in active_list if t.get("severity") == "MEDIUM")
        low_count = sum(1 for t in active_list if t.get("severity") == "LOW")

        # Top attack types
        type_counts = {}
        for t in active_list:
            atype = t.get("attack_type", "OTHER")
            type_counts[atype] = type_counts.get(atype, 0) + 1

        # Calculate Threat Level strictly based on active unmitigated threats
        if critical_count > 0:
            threat_level = "CRITICAL"
        elif high_count > 0:
            threat_level = "HIGH"
        elif medium_count > 0:
            threat_level = "ELEVATED"
        else:
            threat_level = "NORMAL"

        return {
            "threat_level": threat_level,
            "active_threats_count": len(active_list),
            "critical_threats": critical_count,
            "high_threats": high_count,
            "medium_threats": medium_count,
            "low_threats": low_count,
            "mitigated_count": len(self.mitigated_threats),
            "attack_type_distribution": type_counts,
            "active_threats": active_list[:20]
        }

    def clear_threats(self):
        """Clears active threats upon recovery."""
        with self.lock:
            for t in self.active_threats.values():
                t["status"] = "CLEARED"
                t["mitigation_status"] = "CLEARED"
                self.mitigated_threats.append(t)
            self.active_threats.clear()

security_detector = SecurityDetector()

