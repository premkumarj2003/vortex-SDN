"""
VORTEX-SDN Notifications REST API
"""

from flask import Blueprint, request, jsonify
from backend.services.notification_service import get_notifications, mark_notification_read

notification_bp = Blueprint("notifications", __name__)

@notification_bp.route("/api/notifications", methods=["GET"])
def list_notifications():
    unread_only = request.args.get("unread", "false").lower() == "true"
    limit = int(request.args.get("limit", 30))
    data = get_notifications(limit=limit, unread_only=unread_only)
    return jsonify(data), 200

@notification_bp.route("/api/notifications/<notif_id>/read", methods=["PUT", "POST"])
def read_notification(notif_id):
    mark_notification_read(notif_id)
    return jsonify({"status": "SUCCESS", "message": "Notification marked as read."}), 200

@notification_bp.route("/api/notifications/read-all", methods=["POST"])
def read_all():
    mark_notification_read("all")
    return jsonify({"status": "SUCCESS", "message": "All notifications marked as read."}), 200
