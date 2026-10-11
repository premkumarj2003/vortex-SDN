"""
VORTEX-SDN Main Flask Server
Serves all REST API blueprints and frontend single-page interface on 127.0.0.1:5000.
"""

import os
import secrets
from urllib.parse import quote
from flask import Flask, send_from_directory, render_template_string, jsonify, request, redirect
from flask_cors import CORS

from backend.models.database import init_db
from backend.api.auth import auth_bp
from backend.api.telemetry_api import telemetry_bp
from backend.api.topology_api import topology_bp
from backend.api.security_api import security_bp
from backend.api.qos_api import qos_bp
from backend.api.ai_api import ai_bp
from backend.api.chat_api import chat_bp
from backend.api.incident_api import incident_bp
from backend.api.policy_api import policy_bp
from backend.api.audit_api import audit_bp
from backend.api.settings_api import settings_bp
from backend.api.notification_api import notification_bp
from backend.api.demo_api import demo_bp
from backend.api.digital_twin_api import digital_twin_bp
from backend.api.predictive_api import predictive_bp
from backend.api.root_cause_api import root_cause_bp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

from backend.services.email_service import validate_smtp_on_startup, load_env_file, verify_email_token

# Load environment configuration on server import
load_env_file()

def create_app():
    # Reload environment in case .env was updated
    load_env_file()
    # Initialize SQLite database
    init_db()
    # Validate SMTP configuration safely on startup
    validate_smtp_on_startup()

    app = Flask(__name__, static_folder=FRONTEND_DIR)
    app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("VORTEX_SECRET_KEY") or secrets.token_hex(32)
    app.config["JSON_SORT_KEYS"] = False

    CORS(app, supports_credentials=True)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(telemetry_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(qos_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(notification_bp)
    app.register_blueprint(demo_bp)
    app.register_blueprint(digital_twin_bp)
    app.register_blueprint(predictive_bp)
    app.register_blueprint(root_cause_bp)

    # Static CSS and JS routes
    @app.route("/css/<path:filename>")
    def serve_css(filename):
        return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)

    @app.route("/js/<path:filename>")
    def serve_js(filename):
        return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)

    @app.route("/assets/<path:filename>")
    def serve_assets(filename):
        return send_from_directory(os.path.join(FRONTEND_DIR, "assets"), filename)

    # HTML Page Routes
    @app.route("/login")
    def login_page():
        return send_from_directory(FRONTEND_DIR, "login.html")

    @app.route("/register")
    def register_page():
        return send_from_directory(FRONTEND_DIR, "register.html")

    @app.route("/verify-email", methods=["GET", "POST"])
    def verify_email_page():
        token = request.args.get("token")
        if not token and request.is_json:
            token = (request.get_json() or {}).get("token")

        wants_json = (
            request.is_json
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.accept_mimetypes.best == "application/json" and request.accept_mimetypes["application/json"] > request.accept_mimetypes["text/html"])
        )

        if not token:
            if wants_json:
                return jsonify({
                    "success": False,
                    "status": "ERROR",
                    "message": "This verification link is invalid or has already been used."
                }), 400
            return send_from_directory(FRONTEND_DIR, "verify-email.html")

        try:
            success, message, user = verify_email_token(token)
        except Exception as e:
            print(f"[AUTH] Error verifying email token: {e}")
            if wants_json:
                return jsonify({
                    "success": False,
                    "status": "ERROR",
                    "message": "An error occurred while verifying your email."
                }), 500
            return redirect("/login?error=" + quote("An error occurred while verifying your email."))

        if wants_json:
            if success:
                return jsonify({
                    "success": True,
                    "status": "SUCCESS",
                    "message": message,
                    "user": {
                        "id": user.get("id"),
                        "email": user.get("email"),
                        "full_name": user.get("full_name"),
                        "role": user.get("role")
                    } if user else None
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "status": "ERROR",
                    "message": message
                }), 400

        if success:
            return redirect(f"/login?verified=true&message={quote(message)}")
        else:
            return redirect(f"/login?error={quote(message)}")

    @app.route("/forgot-password")
    def forgot_password_page():
        return send_from_directory(FRONTEND_DIR, "forgot-password.html")

    @app.route("/reset-password")
    def reset_password_page():
        return send_from_directory(FRONTEND_DIR, "reset-password.html")

    @app.route("/")
    @app.route("/<path:path>")
    def index(path=""):
        if path.endswith(".html"):
            return send_from_directory(FRONTEND_DIR, path)
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource Not Found", "message": "The requested API endpoint or resource was not found on this server."}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred in the VORTEX-SDN backend."}), 500

    return app

if __name__ == "__main__":
    print("=" * 60)
    print("VORTEX-SDN: AI-Driven Software-Defined Network Controller")
    print("Security & Quality of Service Intelligence Platform")
    print("Starting Flask Server on http://127.0.0.1:5000")
    print("=" * 60)
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
