"""
VORTEX-SDN AI & Machine Learning REST API
Provides model statuses, real training evaluation metrics, confusion matrices, and interactive flow prediction.
"""

import os
import json
from flask import Blueprint, request, jsonify
from ai.inference import ai_engine
from ai.train_security_model import METRICS_PATH as SEC_METRICS_PATH
from ai.train_qos_model import METRICS_PATH as QOS_METRICS_PATH

ai_bp = Blueprint("ai", __name__)

@ai_bp.route("/api/ai/status", methods=["GET"])
def get_ai_status():
    status = ai_engine.get_status()
    return jsonify(status), 200

@ai_bp.route("/api/ai/metrics", methods=["GET"])
def get_ai_metrics():
    sec_metrics = {}
    qos_metrics = {}

    if os.path.exists(SEC_METRICS_PATH):
        try:
            with open(SEC_METRICS_PATH, "r", encoding="utf-8") as f:
                sec_metrics = json.load(f)
        except Exception:
            pass

    if os.path.exists(QOS_METRICS_PATH):
        try:
            with open(QOS_METRICS_PATH, "r", encoding="utf-8") as f:
                qos_metrics = json.load(f)
        except Exception:
            pass

    return jsonify({
        "security_model": sec_metrics,
        "qos_model": qos_metrics,
        "status": "ONLINE"
    }), 200

@ai_bp.route("/api/ai/predict", methods=["POST"])
def run_live_prediction():
    """Interactive sandbox API allowing users to submit flow features and receive real ML predictions."""
    data = request.get_json() or {}
    sec_pred = ai_engine.predict_security(data)
    qos_pred = ai_engine.predict_qos(data)

    return jsonify({
        "security_prediction": sec_pred,
        "qos_prediction": qos_pred
    }), 200
