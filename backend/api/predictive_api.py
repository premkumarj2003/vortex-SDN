"""
VORTEX-SDN Predictive Network Intelligence REST API
Provides endpoints for summary KPIs, anomaly detection, statistical forecasts,
device risk rankings, early warnings, and warning acknowledgments.
"""

from flask import Blueprint, request, jsonify
from backend.predictive.analysis import run_predictive_analysis, acknowledge_warning
from backend.services.telemetry_service import get_dashboard_summary

predictive_bp = Blueprint("predictive", __name__)

@predictive_bp.route("/api/predictive/summary", methods=["GET"])
def get_predictive_summary():
    """Returns top KPI cards, risk scores, trend indicators, and health contrast."""
    time_window = request.args.get("window", "15m")
    analysis = run_predictive_analysis(time_window=time_window)
    
    # Retrieve current network health for comparison display
    dash = get_dashboard_summary()
    current_health = dash.get("network_health", 96.0)

    return jsonify({
        "status": analysis.get("status", "READY"),
        "source": analysis.get("source", "DEMO"),
        "timestamp": analysis.get("timestamp"),
        "time_window": time_window,
        "network_risk": analysis.get("network_risk", 23),
        "risk_level": analysis.get("risk_level", "LOW"),
        "current_network_health": current_health,
        "traffic_trend": analysis.get("traffic_trend", "STABLE"),
        "security_risk": analysis.get("security_risk", 10),
        "qos_risk": analysis.get("qos_risk", 15),
        "predicted_anomalies_count": analysis.get("predicted_anomalies_count", 0),
        "early_warnings_count": analysis.get("early_warnings_count", 0),
        "confidence": analysis.get("confidence", 82),
        "confidence_level": analysis.get("confidence_level", "HIGH"),
        "model_info": analysis.get("model_info", {}),
        "is_sufficient": analysis.get("is_sufficient", True),
        "health_forecast": analysis.get("health_forecast", {}),
        "security_forecast": analysis.get("security_forecast", {}),
        "qos_forecast": analysis.get("qos_forecast", {}),
        "metric_forecasts": analysis.get("metric_forecasts", {})
    }), 200

@predictive_bp.route("/api/predictive/anomalies", methods=["GET"])
def get_anomalies():
    """Returns detected statistical anomalies."""
    time_window = request.args.get("window", "15m")
    analysis = run_predictive_analysis(time_window=time_window)
    return jsonify({
        "anomalies": analysis.get("anomalies", []),
        "count": len(analysis.get("anomalies", []))
    }), 200

@predictive_bp.route("/api/predictive/forecast", methods=["GET"])
def get_forecast():
    """Returns near-term statistical forecasts, confidence bounds, and chart series."""
    time_window = request.args.get("window", "15m")
    analysis = run_predictive_analysis(time_window=time_window)
    return jsonify(analysis.get("forecast", {})), 200

@predictive_bp.route("/api/predictive/risks", methods=["GET"])
def get_risks():
    """Returns composite risk metrics, device risk rankings, and early warnings."""
    time_window = request.args.get("window", "15m")
    analysis = run_predictive_analysis(time_window=time_window)
    return jsonify({
        "risk_assessment": analysis.get("risk_assessment", {}),
        "early_warnings": analysis.get("early_warnings", []),
        "top_risks": analysis.get("risk_assessment", {}).get("top_risks", []),
        "device_risks": analysis.get("risk_assessment", {}).get("device_risks", [])
    }), 200

@predictive_bp.route("/api/predictive/refresh", methods=["POST"])
def refresh_predictive_engine():
    """Forces an immediate refresh of predictive analysis."""
    data = request.get_json() or {}
    time_window = data.get("window", "15m")
    analysis = run_predictive_analysis(time_window=time_window)
    return jsonify({"status": "SUCCESS", "analysis": analysis}), 200

@predictive_bp.route("/api/predictive/warnings/<warning_id>/acknowledge", methods=["POST"])
def ack_warning(warning_id):
    """Acknowledges an active early warning."""
    success = acknowledge_warning(warning_id)
    return jsonify({"status": "SUCCESS", "warning_id": warning_id, "acknowledged": success}), 200
