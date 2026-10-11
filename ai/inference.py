"""
VORTEX-SDN AI Inference Engine
Thread-safe singleton loader for Security and QoS Machine Learning models.
Provides structured predictions with calibrated risk scores, confidence, severity levels,
and recommended OpenFlow actions.
"""

import os
import time
import joblib
import warnings
import numpy as np
import pandas as pd
import threading
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEC_MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "security_model.joblib")
QOS_MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "qos_model.joblib")

class AIInferenceEngine:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AIInferenceEngine, cls).__new__(cls)
                cls._instance._init_engine()
            return cls._instance

    def _init_engine(self):
        self.sec_model = None
        self.sec_scaler = None
        self.iso_forest = None
        self.sec_features = []
        self.sec_classes = []
        self.sec_loaded = False

        self.qos_model = None
        self.qos_scaler = None
        self.qos_features = []
        self.qos_classes = []
        self.qos_loaded = False

        self.inference_count = 0
        self.last_inference_time = None
        self.load_models()

    def load_models(self):
        """Loads or reloads serialized models from disk."""
        # 1. Load Security Model
        if os.path.exists(SEC_MODEL_PATH):
            try:
                sec_data = joblib.load(SEC_MODEL_PATH)
                self.sec_model = sec_data["classifier"]
                self.sec_scaler = sec_data["scaler"]
                self.iso_forest = sec_data.get("isolation_forest")
                self.sec_features = sec_data["features"]
                self.sec_classes = sec_data["classes"]
                self.sec_loaded = True
            except Exception as e:
                print(f"[AI Engine] Error loading security model: {e}")
                self.sec_loaded = False
        else:
            self.sec_loaded = False

        # 2. Load QoS Model
        if os.path.exists(QOS_MODEL_PATH):
            try:
                qos_data = joblib.load(QOS_MODEL_PATH)
                self.qos_model = qos_data["classifier"]
                self.qos_scaler = qos_data["scaler"]
                self.qos_features = qos_data["features"]
                self.qos_classes = qos_data["classes"]
                self.qos_loaded = True
            except Exception as e:
                print(f"[AI Engine] Error loading QoS model: {e}")
                self.qos_loaded = False
        else:
            self.qos_loaded = False

    def predict_security(self, flow_dict: dict) -> dict:
        """
        Evaluates a flow dictionary against the security classifier and anomaly detector.
        Returns:
            label: "BENIGN" | "ATTACK"
            attack_type: "NORMAL" | "DDOS" | "PORT_SCAN" | "BRUTE_FORCE" | "FLOOD" | "ANOMALY"
            confidence: float (0.0 to 1.0)
            risk_score: float (0 to 100)
            severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            recommended_action: "MONITOR" | "ALERT" | "RATE_LIMIT" | "BLOCK" | "ISOLATE"
            timestamp: ISO8601 string
        """
        self.inference_count += 1
        self.last_inference_time = datetime.now(timezone.utc).isoformat()

        # Fallback heuristic if model is not loaded yet
        if not self.sec_loaded or self.sec_model is None:
            return self._heuristic_security(flow_dict)

        try:
            # Extract features in exact order
            feature_vector = [
                float(flow_dict.get("packet_rate", 0.0)),
                float(flow_dict.get("byte_rate", 0.0)),
                int(flow_dict.get("packets", 0)),
                int(flow_dict.get("bytes", 0)),
                float(flow_dict.get("flow_duration", 1.0)),
                int(flow_dict.get("source_port", 0)),
                int(flow_dict.get("destination_port", 0)),
                int(flow_dict.get("protocol_num", 6)),
                int(flow_dict.get("unique_destinations", 1)),
                float(flow_dict.get("connection_frequency", 1.0)),
                int(flow_dict.get("packet_size", 512)),
                float(flow_dict.get("destination_frequency", 1.0)),
                float(flow_dict.get("source_frequency", 1.0))
            ]

            cols = self.sec_features if self.sec_features else None
            X = pd.DataFrame([feature_vector], columns=cols) if cols is not None else np.array([feature_vector])
            X_scaled = self.sec_scaler.transform(X)

            # Predict attack type and probabilities
            pred_class = self.sec_model.predict(X_scaled)[0]
            probs = self.sec_model.predict_proba(X_scaled)[0]
            class_idx = list(self.sec_classes).index(pred_class)
            confidence = float(probs[class_idx])

            # Anomaly check
            is_anomaly = False
            if self.iso_forest is not None:
                iso_score = self.iso_forest.decision_function(X_scaled)[0]
                if iso_score < -0.15:
                    is_anomaly = True

            # Calibrate label, risk score, severity, and action
            if pred_class == "BENIGN" and not is_anomaly:
                label = "BENIGN"
                attack_type = "BENIGN"
                risk_score = round(max(2.0, (1.0 - confidence) * 25.0), 1)
                severity = "LOW"
                action = "MONITOR"
            else:
                label = "ATTACK"
                pkt_rate = float(flow_dict.get("packet_rate", 0.0))
                if pred_class != "BENIGN":
                    attack_type = pred_class
                else:
                    if pkt_rate > 10000:
                        attack_type = "DDOS"
                    elif pkt_rate > 3000:
                        attack_type = "FLOOD"
                    else:
                        attack_type = "ANOMALY"
                
                # Base risk score calculation
                if attack_type == "DDOS":
                    base_risk = 85.0
                    action = "BLOCK" if (confidence > 0.8 or pkt_rate > 20000) else "RATE_LIMIT"
                elif attack_type == "PORT_SCAN":
                    base_risk = 72.0
                    action = "ISOLATE" if confidence > 0.75 else "ALERT"
                elif attack_type == "BRUTE_FORCE":
                    base_risk = 68.0
                    action = "BLOCK" if confidence > 0.8 else "ALERT"
                elif attack_type == "FLOOD":
                    base_risk = 80.0
                    action = "RATE_LIMIT"
                else: # ANOMALY
                    if pkt_rate > 10000:
                        base_risk = 85.0
                        action = "BLOCK" if (confidence > 0.8 or pkt_rate > 20000) else "RATE_LIMIT"
                    elif pkt_rate > 3000:
                        base_risk = 75.0
                        action = "RATE_LIMIT"
                    else:
                        base_risk = 60.0
                        action = "ALERT"

                risk_score = round(min(100.0, base_risk + (confidence * 15.0)), 1)

                if risk_score >= 85:
                    severity = "CRITICAL"
                elif risk_score >= 70:
                    severity = "HIGH"
                elif risk_score >= 45:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            return {
                "label": label,
                "attack_type": attack_type,
                "confidence": round(confidence, 4),
                "risk_score": risk_score,
                "severity": severity,
                "recommended_action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_status": "ONLINE"
            }

        except Exception as e:
            print(f"[AI Engine] Error during security inference: {e}")
            return self._heuristic_security(flow_dict)

    def _heuristic_security(self, flow: dict) -> dict:
        """Rule-based fallback when ML model is offline."""
        pkt_rate = float(flow.get("packet_rate", 0))
        dst_port = int(flow.get("destination_port", 0))
        
        if pkt_rate > 10000:
            return {
                "label": "ATTACK",
                "attack_type": "DDOS",
                "confidence": 0.88,
                "risk_score": 92.0,
                "severity": "CRITICAL",
                "recommended_action": "BLOCK",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_status": "HEURISTIC_FALLBACK"
            }
        elif pkt_rate > 3000:
            return {
                "label": "ATTACK",
                "attack_type": "FLOOD",
                "confidence": 0.78,
                "risk_score": 75.0,
                "severity": "HIGH",
                "recommended_action": "RATE_LIMIT",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_status": "HEURISTIC_FALLBACK"
            }
        else:
            return {
                "label": "BENIGN",
                "attack_type": "BENIGN",
                "confidence": 0.94,
                "risk_score": 5.0,
                "severity": "LOW",
                "recommended_action": "MONITOR",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_status": "HEURISTIC_FALLBACK"
            }

    def predict_qos(self, flow_dict: dict) -> dict:
        """
        Classifies traffic into QoS categories and calculates priority scores.
        """
        if not self.qos_loaded or self.qos_model is None:
            return self._heuristic_qos(flow_dict)

        try:
            feature_vector = [
                float(flow_dict.get("packet_rate", 50.0)),
                float(flow_dict.get("byte_rate", 40000.0)),
                int(flow_dict.get("packet_size", 800)),
                int(flow_dict.get("protocol_num", 6)),
                int(flow_dict.get("destination_port", 80)),
                float(flow_dict.get("flow_duration", 10.0)),
                float(flow_dict.get("latency_ms", 25.0)),
                float(flow_dict.get("jitter_ms", 4.0)),
                float(flow_dict.get("packet_loss_pct", 0.1)),
                float(flow_dict.get("throughput_mbps", 0.5))
            ]

            X = np.array([feature_vector])
            X_scaled = self.qos_scaler.transform(X)

            pred_class = self.qos_model.predict(X_scaled)[0]
            probs = self.qos_model.predict_proba(X_scaled)[0]
            class_idx = list(self.qos_classes).index(pred_class)
            confidence = float(probs[class_idx])

            # Priority mapping
            priority_map = {
                "VOICE": {"priority": "EF", "queue_id": 1, "dscp": 46, "min_bw": 10.0},
                "CRITICAL": {"priority": "EF", "queue_id": 1, "dscp": 40, "min_bw": 20.0},
                "VIDEO": {"priority": "AF", "queue_id": 2, "dscp": 34, "min_bw": 25.0},
                "WEB": {"priority": "AF", "queue_id": 2, "dscp": 26, "min_bw": 15.0},
                "FILE_TRANSFER": {"priority": "BE", "queue_id": 3, "dscp": 0, "min_bw": 5.0},
                "EMAIL": {"priority": "BE", "queue_id": 3, "dscp": 0, "min_bw": 2.0},
                "P2P": {"priority": "BE", "queue_id": 4, "dscp": 8, "min_bw": 1.0},
                "BEST_EFFORT": {"priority": "BE", "queue_id": 3, "dscp": 0, "min_bw": 5.0}
            }

            p_info = priority_map.get(pred_class, {"priority": "BE", "queue_id": 3, "dscp": 0, "min_bw": 5.0})

            return {
                "traffic_class": pred_class,
                "confidence": round(confidence, 4),
                "priority_code": p_info["priority"],
                "recommended_queue": p_info["queue_id"],
                "dscp_mark": p_info["dscp"],
                "min_bandwidth_mbps": p_info["min_bw"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_status": "ONLINE"
            }

        except Exception as e:
            print(f"[AI Engine] Error during QoS inference: {e}")
            return self._heuristic_qos(flow_dict)

    def _heuristic_qos(self, flow: dict) -> dict:
        port = int(flow.get("destination_port", 80))
        if port in [5060, 5061]:
            t_class, prio, q = "VOICE", "EF", 1
        elif port in [1935, 554, 8554]:
            t_class, prio, q = "VIDEO", "AF", 2
        elif port in [80, 443, 8080]:
            t_class, prio, q = "WEB", "AF", 2
        elif port in [20, 21, 22, 445]:
            t_class, prio, q = "FILE_TRANSFER", "BE", 3
        else:
            t_class, prio, q = "BEST_EFFORT", "BE", 3

        return {
            "traffic_class": t_class,
            "confidence": 0.85,
            "priority_code": prio,
            "recommended_queue": q,
            "dscp_mark": 0,
            "min_bandwidth_mbps": 5.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_status": "HEURISTIC_FALLBACK"
        }

    def get_status(self) -> dict:
        """Returns runtime status of both models."""
        return {
            "security_model_loaded": self.sec_loaded,
            "qos_model_loaded": self.qos_loaded,
            "inference_count": self.inference_count,
            "last_inference_time": self.last_inference_time,
            "security_classes": self.sec_classes,
            "qos_classes": self.qos_classes
        }

# Global singleton accessor
ai_engine = AIInferenceEngine()
