"""
VORTEX-SDN AI Chatbot REST API
Serves isolated chat endpoints for conversational network operations and status checks.
"""

from flask import Blueprint, request, jsonify
from chatbot.assistant import vortex_assistant

chat_bp = Blueprint("chat", __name__)

@chat_bp.route("/api/chat", methods=["POST"])
@chat_bp.route("/api/ai/chat", methods=["POST"])
def chat():
    """Processes conversational network queries against real-time project telemetry."""
    data = request.get_json() or {}
    message = str(data.get("message", "")).strip()
    session_id = str(data.get("session_id", "default"))

    if not message:
        return jsonify({"error": "Empty message", "message": "Please provide a network query."}), 400

    reply = vortex_assistant.process_message(message, session_id=session_id)
    return jsonify(reply), 200

@chat_bp.route("/api/chat/status", methods=["GET"])
@chat_bp.route("/api/ai/status", methods=["GET"])
def chat_status():
    """Returns AI assistant status and model availability."""
    status_info = vortex_assistant.get_status()
    return jsonify(status_info), 200

@chat_bp.route("/api/chat/clear", methods=["POST"])
def clear_chat():
    """Clears chatbot session memory without affecting backend telemetry or audit logs."""
    data = request.get_json() or {}
    session_id = str(data.get("session_id", "default"))
    vortex_assistant.clear_session(session_id)
    return jsonify({"success": True, "message": "Conversation history cleared."}), 200
