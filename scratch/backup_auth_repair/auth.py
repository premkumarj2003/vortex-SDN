"""
VORTEX-SDN Authentication & Authorization API
Provides real user registration, real Gmail email verification, password reset workflows,
salted SHA-256 password hashing, rate limiting, and dynamic session management.
"""

import json
import uuid
import re
import secrets
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, session
from backend.models.database import get_db_connection, hash_password, verify_password
from backend.services.audit_service import log_audit_event
from backend.services.email_service import (
    generate_secure_token,
    send_verification_email,
    send_password_reset_email,
    send_password_changed_email,
    verify_email_token,
    verify_password_reset_token,
    reset_password_with_token,
    check_rate_limit,
    record_rate_limit,
    rollback_rate_limit,
    clear_rate_limit,
    get_rate_limit_cooldown_seconds,
    get_rate_limit_max_requests,
    is_email_verification_required
)

auth_bp = Blueprint("auth", __name__)

# Active in-memory session tokens: token -> {user_id, username, role, full_name, name, email, avatar, settings}
ACTIVE_SESSIONS = {}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def get_current_user():
    """Helper to extract authenticated user from Authorization header Bearer token or session."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
    elif "vortex_token" in session:
        token = session.get("vortex_token")

    if token and token in ACTIVE_SESSIONS:
        return ACTIVE_SESSIONS[token]
    return None

def require_auth(roles=None):
    """Decorator or validation helper for protected endpoints."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized", "message": "Authentication token required or expired."}), 401
            if roles and user.get("role") not in roles:
                return jsonify({"error": "Forbidden", "message": f"Operation requires role: {roles}"}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = str(data.get("email", "")).strip().lower()
    full_name = str(data.get("full_name", "")).strip()
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", data.get("confirm", password)))
    role = str(data.get("role", "OPERATOR")).upper()
    avatar = str(data.get("avatar", "user-astronaut"))

    # Derive username from email or full_name
    username = str(data.get("username", "")).strip().lower()
    if not username and email:
        username = email.split("@")[0]

    # 1. Validation
    if not email or not full_name or not password:
        return jsonify({"success": False, "status": "ERROR", "error": "Validation Error", "message": "All fields are required."}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({"success": False, "status": "ERROR", "error": "Invalid Email", "message": "Please enter a valid email address."}), 400

    if len(password) < 6:
        return jsonify({"success": False, "status": "ERROR", "error": "Weak Password", "message": "Password must be at least 6 characters."}), 400

    if password != confirm_password:
        return jsonify({"success": False, "status": "ERROR", "error": "Password Mismatch", "message": "Passwords do not match."}), 400

    if role not in ("ADMIN", "OPERATOR", "VIEWER"):
        role = "OPERATOR"

    # 2. Check duplicate email or username
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "status": "ERROR", "error": "Conflict", "message": "An account with this email already exists."}), 409

    cursor.execute("SELECT id FROM users WHERE LOWER(username) = ?", (username,))
    if cursor.fetchone():
        username = f"{username}_{secrets.token_hex(2)}"

    # 3. Create user in SQLite with email_verified = 0
    user_id = f"usr_{uuid.uuid4().hex[:8]}"
    pwd_hash, salt = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()

    default_settings = {
        "appearance": {"theme": "dark", "density": "comfortable", "compact_mode": False},
        "dashboard": {"refresh_interval": 5, "default_landing_page": "dashboard", "chart_animation": True},
        "notifications": {"security_alerts": True, "qos_alerts": True, "system_alerts": True, "ai_alerts": True, "browser_notifications": False},
        "network": {"telemetry_interval": 5, "preferred_units": "auto", "traffic_display": "both"},
        "security": {"auto_logout_minutes": 60}
    }

    raw_token, token_hash, expires_at = generate_secure_token()
    email_verified_val = 0

    cursor.execute("""
    INSERT INTO users (id, username, email, full_name, password_hash, salt, role, avatar, email_verified, verification_token_hash, verification_token_expires, settings_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, email, full_name, pwd_hash, salt, role, avatar, email_verified_val, token_hash, expires_at, json.dumps(default_settings), now))
    conn.commit()

    # 4. Dispatch real verification email
    sent, email_msg = send_verification_email(email, full_name, raw_token)

    if not sent:
        # Keep newly inserted account with email_verified = 0 so user can resend verification
        conn.close()
        print(f"\n[Auth API] Registration SMTP delivery issue for user {username} ({email}): {email_msg}\n")
        log_audit_event(username, role, "USER_REGISTER_SMTP_FAILED", f"User {username} register verification email failed: {email_msg}", "WARNING")
        return jsonify({
            "success": False,
            "status": "WARNING",
            "code": "EMAIL_SEND_FAILED",
            "email_sent": False,
            "message": "Your account was created, but the verification email could not be sent. Please try again.",
            "email_verified": False,
            "email": email
        }), 201

    conn.close()
    log_audit_event(username, role, "USER_REGISTER", f"User {username} registered (Verification email sent)", "SUCCESS", {"email": email})

    return jsonify({
        "success": True,
        "status": "SUCCESS",
        "email_sent": True,
        "message": "Verification email sent successfully.",
        "email_verified": False,
        "email": email
    }), 201

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    identifier = str(data.get("username", "") or data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({"success": False, "status": "ERROR", "error": "Invalid Credentials", "message": "Email and Password are required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (identifier, identifier))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        log_audit_event(identifier, "UNKNOWN", "USER_LOGIN_ATTEMPT", "Login failed (user not found)", "FAILURE")
        return jsonify({"success": False, "status": "ERROR", "error": "Authentication Failed", "message": "Invalid email or password."}), 401

    if not verify_password(password, user_row["password_hash"], user_row["salt"]):
        conn.close()
        log_audit_event(user_row["username"], user_row["role"], "USER_LOGIN_ATTEMPT", "Login failed (bad password)", "FAILURE")
        return jsonify({"success": False, "status": "ERROR", "error": "Authentication Failed", "message": "Invalid email or password."}), 401

    # Check if user email is verified - block login if email_verified is 0/false
    if not user_row["email_verified"]:
        conn.close()
        log_audit_event(user_row["username"], user_row["role"], "USER_LOGIN_BLOCKED", "Login blocked (email not verified)", "WARNING")
        return jsonify({
            "success": False,
            "status": "ERROR",
            "error": "Email Not Verified",
            "code": "EMAIL_NOT_VERIFIED",
            "message": "Please verify your email address before signing in.",
            "email_verified": False,
            "email": user_row["email"],
            "username": user_row["username"]
        }), 403

    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_row["id"]))
    conn.commit()
    conn.close()

    # Create session token
    token = f"vtx_{secrets.token_hex(24)}"
    settings = json.loads(user_row["settings_json"]) if user_row["settings_json"] else {}
    user_payload = {
        "id": user_row["id"],
        "username": user_row["username"],
        "email": user_row["email"],
        "name": user_row["full_name"],
        "full_name": user_row["full_name"],
        "role": user_row["role"],
        "avatar": user_row["avatar"] or "user-astronaut",
        "settings": settings
    }
    ACTIVE_SESSIONS[token] = user_payload
    session["vortex_token"] = token

    log_audit_event(user_row["username"], user_row["role"], "USER_LOGIN", "User logged in successfully", "SUCCESS")

    return jsonify({
        "success": True,
        "status": "SUCCESS",
        "message": f"Welcome back, {user_row['full_name']}!",
        "token": token,
        "user": user_payload
    }), 200

@auth_bp.route("/api/auth/verify-email", methods=["GET", "POST"])
def api_verify_email():
    """Validates verification token from query param or JSON body."""
    token = request.args.get("token")
    if not token and request.is_json:
        token = (request.get_json() or {}).get("token")

    if not token:
        return jsonify({"success": False, "status": "ERROR", "message": "This link is invalid or has already been used."}), 400

    success, message, user = verify_email_token(token)
    if not success:
        return jsonify({"success": False, "status": "ERROR", "message": message}), 400

    return jsonify({
        "success": True,
        "status": "SUCCESS",
        "message": message,
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "name": user.get("full_name"),
            "role": user.get("role")
        } if user else None
    }), 200

@auth_bp.route("/api/auth/resend-verification", methods=["POST"])
def resend_verification():
    """Rate-limited resend of verification email."""
    data = request.get_json() or {}
    raw_identifier = str(data.get("email", "") or data.get("username", "")).strip()
    identifier = raw_identifier.lower()
    client_ip = request.remote_addr or "127.0.0.1"

    print(f"[AUTH] Resend verification request received for identifier: {identifier}")

    if not identifier:
        return jsonify({"success": False, "status": "ERROR", "error": "Validation Error", "message": "Email address is required."}), 400

    print(f"[AUTH] Email normalized: {identifier}")

    cooldown_seconds = get_rate_limit_cooldown_seconds()
    max_requests = get_rate_limit_max_requests()

    # Rate limiting: primarily per-account / normalized email (check only, do not record yet)
    res_email = check_rate_limit(f"resend_{identifier}", max_requests=max_requests, window_seconds=cooldown_seconds, record=False)
    ip_limit = 20 if client_ip in ("127.0.0.1", "::1", "localhost") else 10
    res_ip = check_rate_limit(f"resend_ip_{client_ip}", max_requests=ip_limit, window_seconds=cooldown_seconds, record=False)

    if not res_email or not res_ip:
        retry_time = res_email.retry_after_seconds if not res_email else res_ip.retry_after_seconds
        print(f"[AUTH] Rate limit rejected request for {identifier}. Retry after: {retry_time} seconds.")
        return jsonify({
            "success": False,
            "status": "ERROR",
            "error": "Rate Limited",
            "rate_limited": True,
            "retry_after_seconds": retry_time,
            "message": f"Too many requests. Please try again in {retry_time} seconds."
        }), 429

    print(f"[AUTH] Rate limit check passed for {identifier}")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, email_verified FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (identifier, identifier))
    user = cursor.fetchone()

    if not user:
        conn.close()
        # Non-existent user: record rate limit to prevent enumeration, return privacy message
        record_rate_limit(f"resend_{identifier}")
        record_rate_limit(f"resend_ip_{client_ip}")
        return jsonify({"success": True, "status": "SUCCESS", "message": "If an account exists with this email, a verification link has been sent."}), 200

    if user["email_verified"]:
        conn.close()
        return jsonify({"success": True, "status": "INFO", "message": "This email address is already verified. You can sign in directly."}), 200

    raw_token, token_hash, expires_at = generate_secure_token()
    cursor.execute("""
    UPDATE users SET verification_token_hash = ?, verification_token_expires = ?
    WHERE id = ?
    """, (token_hash, expires_at, user["id"]))
    conn.commit()
    conn.close()

    print(f"[AUTH] SMTP send started for {user['email']}")
    sent, msg = send_verification_email(user["email"], user["full_name"], raw_token)
    if not sent:
        print(f"[AUTH] SMTP send failed: {msg}")
        log_audit_event(user["username"], "OPERATOR", "RESEND_VERIFICATION_FAILED", f"To: {user['email']}: {msg}", "FAILURE")
        # IMPORTANT: Failed SMTP attempt does NOT lock the user out from retrying
        return jsonify({
            "success": False,
            "status": "ERROR",
            "email_sent": False,
            "message": f"Unable to send verification email: {msg}"
        }), 502

    # CRITICAL: Record rate limit hit ONLY upon successful SMTP delivery
    record_rate_limit(f"resend_{identifier}")
    record_rate_limit(f"resend_ip_{client_ip}")

    print(f"[AUTH] SMTP send succeeded for {user['email']}")
    log_audit_event(user["username"], "OPERATOR", "RESEND_VERIFICATION_EMAIL", f"To: {user['email']}", "SUCCESS")

    return jsonify({
        "success": True,
        "status": "SUCCESS",
        "email_sent": True,
        "message": "Verification email sent successfully."
    }), 200

@auth_bp.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """
    Privacy-safe password reset request.
    Generates single-use 30-min token and sends email via SMTP.
    """
    data = request.get_json() or {}
    email = str(data.get("email", "")).strip().lower()
    client_ip = request.remote_addr or "127.0.0.1"

    print(f"[AUTH] Forgot password request received for: {email}")

    if not email:
        return jsonify({"success": False, "status": "ERROR", "error": "Validation Error", "message": "Email address is required."}), 400

    cooldown_seconds = get_rate_limit_cooldown_seconds()
    max_requests = get_rate_limit_max_requests()

    res_email = check_rate_limit(f"forgot_{email}", max_requests=max_requests, window_seconds=cooldown_seconds, record=False)
    ip_limit = 20 if client_ip in ("127.0.0.1", "::1", "localhost") else 10
    res_ip = check_rate_limit(f"forgot_ip_{client_ip}", max_requests=ip_limit, window_seconds=cooldown_seconds, record=False)

    if not res_email or not res_ip:
        retry_time = res_email.retry_after_seconds if not res_email else res_ip.retry_after_seconds
        print(f"[AUTH] Rate limit rejected forgot-password for {email}. Retry after: {retry_time} seconds.")
        return jsonify({
            "success": False,
            "status": "ERROR",
            "error": "Rate Limited",
            "rate_limited": True,
            "retry_after_seconds": retry_time,
            "message": f"Too many requests. Please try again in {retry_time} seconds."
        }), 429

    print(f"[AUTH] Rate limit check passed for forgot-password: {email}")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name FROM users WHERE LOWER(email) = ?", (email,))
    user = cursor.fetchone()

    if user:
        raw_token, token_hash, expires_at = generate_secure_token()
        cursor.execute("""
        UPDATE users SET reset_token_hash = ?, reset_token_expires = ?
        WHERE id = ?
        """, (token_hash, expires_at, user["id"]))
        conn.commit()

        # Send password reset email
        print(f"[AUTH] SMTP send started for password reset: {user['email']}")
        sent, err_msg = send_password_reset_email(user["email"], user["full_name"], raw_token)
        if sent:
            print(f"[AUTH] SMTP send succeeded for password reset: {user['email']}")
            record_rate_limit(f"forgot_{email}")
            record_rate_limit(f"forgot_ip_{client_ip}")
        else:
            print(f"[AUTH] SMTP send failed for password reset: {err_msg}")
        log_audit_event(user["username"], "SYSTEM", "PASSWORD_RESET_REQUESTED", f"Email: {email}", "SUCCESS" if sent else "FAILURE")
    else:
        record_rate_limit(f"forgot_{email}")
        record_rate_limit(f"forgot_ip_{client_ip}")

    conn.close()

    # Privacy-safe response: always returns the same message whether email exists or not
    return jsonify({
        "success": True,
        "status": "SUCCESS",
        "message": "If an account exists for that email, a password-reset link has been sent."
    }), 200

@auth_bp.route("/api/auth/reset-rate-limit", methods=["GET", "POST"])
def reset_rate_limit_dev():
    """Safe development/test helper to clear rate limiter state without affecting database or users."""
    data = {}
    if request.is_json:
        data = request.get_json() or {}
    email = str(data.get("email", "") or request.args.get("email", "")).strip().lower()
    if email:
        clear_rate_limit(f"resend_{email}")
        clear_rate_limit(f"forgot_{email}")
    else:
        clear_rate_limit()
    print("[AUTH] Rate limit store cleared by development request.")
    return jsonify({"success": True, "status": "SUCCESS", "message": "Rate limit store cleared."}), 200

@auth_bp.route("/api/auth/verify-reset-token", methods=["GET"])
def api_verify_reset_token():
    """Checks if reset token is valid before showing password reset form."""
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"success": False, "status": "ERROR", "message": "This link is invalid or has already been used."}), 400

    valid, message, user = verify_password_reset_token(token)
    if not valid:
        return jsonify({"success": False, "status": "ERROR", "message": message}), 400

    return jsonify({"success": True, "status": "SUCCESS", "message": "Reset token is valid."}), 200

@auth_bp.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    """Consumes the password reset token and securely updates password."""
    data = request.get_json() or {}
    token = str(data.get("token", "")).strip()
    new_password = str(data.get("new_password", ""))
    confirm_password = str(data.get("confirm_password", data.get("confirm", new_password)))

    if not token:
        return jsonify({"success": False, "status": "ERROR", "error": "Invalid Token", "message": "This link is invalid or has already been used."}), 400

    if not new_password or len(new_password) < 6:
        return jsonify({"success": False, "status": "ERROR", "error": "Weak Password", "message": "Password must be at least 6 characters."}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "status": "ERROR", "error": "Password Mismatch", "message": "Passwords do not match."}), 400

    success, message = reset_password_with_token(token, new_password)
    if not success:
        return jsonify({"success": False, "status": "ERROR", "error": "Reset Failed", "message": message}), 400

    return jsonify({"success": True, "status": "SUCCESS", "message": "Password successfully changed. You can now sign in."}), 200

@auth_bp.route("/api/auth/change-password", methods=["POST"])
def change_password():
    """
    Authenticated password change from Settings.
    Verifies current password server-side, validates new password,
    hashes new password securely, updates database, and sends security notification email.
    """
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "status": "ERROR", "error": "Unauthorized", "message": "Authentication required to change password."}), 401

    data = request.get_json() or {}
    current_password = str(data.get("current_password", "") or data.get("current", ""))
    new_password = str(data.get("new_password", "") or data.get("password", ""))
    confirm_password = str(data.get("confirm_password", data.get("confirm", new_password)))

    if not current_password or not new_password:
        return jsonify({"success": False, "status": "ERROR", "error": "Validation Error", "message": "Current password and new password are required."}), 400

    if len(new_password) < 6:
        return jsonify({"success": False, "status": "ERROR", "error": "Weak Password", "message": "New password must be at least 6 characters."}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "status": "ERROR", "error": "Password Mismatch", "message": "New passwords do not match."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role, password_hash, salt FROM users WHERE id = ?", (user["id"],))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return jsonify({"success": False, "status": "ERROR", "error": "User Not Found", "message": "User account could not be found."}), 404

    # Verify current password server-side
    if not verify_password(current_password, user_row["password_hash"], user_row["salt"]):
        conn.close()
        log_audit_event(user_row["username"], user_row["role"], "PASSWORD_CHANGE_FAILED", "Incorrect current password", "FAILURE")
        return jsonify({"success": False, "status": "ERROR", "error": "Authentication Failed", "message": "Incorrect current password."}), 400

    # Hash new password securely
    pwd_hash, salt = hash_password(new_password)
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("UPDATE users SET password_hash = ?, salt = ?, password_reset_used_at = ? WHERE id = ?", (pwd_hash, salt, now_iso, user["id"]))
    conn.commit()
    conn.close()

    # Send security notification email
    send_password_changed_email(user_row["email"], user_row["full_name"])

    log_audit_event(user_row["username"], user_row["role"], "PASSWORD_CHANGED", "Password changed from user settings", "SUCCESS")

    return jsonify({"success": True, "status": "SUCCESS", "message": "Password changed successfully."}), 200

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    user = get_current_user()
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
    elif "vortex_token" in session:
        token = session.get("vortex_token")

    if token and token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]

    session.pop("vortex_token", None)
    if user:
        log_audit_event(user["username"], user["role"], "USER_LOGOUT", "User logged out", "SUCCESS")

    return jsonify({"success": True, "status": "SUCCESS", "message": "Logged out successfully."}), 200

@auth_bp.route("/api/auth/me", methods=["GET"])
def get_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "success": False, "user": None}), 200
    return jsonify({"authenticated": True, "success": True, "user": user}), 200
