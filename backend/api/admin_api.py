"""
VORTEX-SDN Administration REST API
Enforces strict single-administrator authorization for operator request approval,
user management, account enabling/disabling, operator revocation, and granular permission control.
"""

import os
import json
import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from backend.models.database import (
    get_db_connection,
    DEFAULT_PERMISSIONS,
    DEFAULT_OPERATOR_PERMISSIONS,
    READER_VIEW_PERMISSIONS,
    get_user_permissions
)
from backend.api.auth import get_current_user, require_admin, ACTIVE_SESSIONS
from backend.services.audit_service import log_audit_event

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/api/admin/users", methods=["GET"])
@require_admin
def list_users():
    """Lists all users with their roles, account statuses, and assigned permissions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, username, email, full_name, role, avatar, is_active, email_verified, created_at, last_login
    FROM users ORDER BY created_at DESC
    """)
    users_rows = cursor.fetchall()

    users_list = []
    for r in users_rows:
        u_dict = dict(r)
        u_dict["permissions"] = get_user_permissions(r["id"])
        users_list.append(u_dict)

    conn.close()
    return jsonify({"success": True, "users": users_list, "count": len(users_list)}), 200

@admin_bp.route("/api/admin/operator-requests", methods=["GET"])
@require_admin
def list_operator_requests():
    """Returns all operator access requests, ordered newest first."""
    status_filter = request.args.get("status")
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
    SELECT 
        r.id, r.user_id, r.email, 
        COALESCE(r.full_name, u.full_name, u.username, 'Operator Applicant') AS full_name,
        r.status, r.requested_at, r.reviewed_at, r.reviewed_by, r.review_reason,
        r.client_ip, r.user_agent,
        u.role AS current_role, u.email_verified AS verification_status, u.is_active
    FROM operator_access_requests r
    LEFT JOIN users u ON r.user_id = u.id
    """
    params = []
    if status_filter:
        query += " WHERE UPPER(r.status) = ?"
        params.append(status_filter.strip().upper())
    query += " ORDER BY r.requested_at DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    requests_list = []
    for r in rows:
        d = dict(r)
        d["request_id"] = d.get("id")
        d["name"] = d.get("full_name")
        requests_list.append(d)
    return jsonify({"success": True, "requests": requests_list, "count": len(requests_list)}), 200

@admin_bp.route("/api/admin/operator-requests/<request_id>/approve", methods=["POST"])
@require_admin
def approve_operator_request(request_id):
    """
    Approves a pending operator access request.
    Elevates user.role to OPERATOR, activates account, and assigns default/custom operator permissions.
    Preserves password, salt, email verification, and user settings.
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    data = request.get_json() or {}
    custom_permissions = data.get("permissions") # Optional custom permission list
    reason = str(data.get("reason", "Approved by Administrator")).strip() or "Approved by Administrator"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM operator_access_requests WHERE id = ?", (request_id,))
    req_row = cursor.fetchone()

    if not req_row:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"Operator request {request_id} not found."}), 404

    # Verify request is actually PENDING
    if (req_row["status"] or "").upper() != "PENDING":
        conn.close()
        return jsonify({
            "success": False,
            "error": "Conflict",
            "message": f"Operator request {request_id} is already {req_row['status']} and cannot be approved."
        }), 400

    user_id = req_row["user_id"]
    cursor.execute("SELECT id, username, email, full_name, role FROM users WHERE id = ?", (user_id,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": "Target user record not found."}), 404

    now = datetime.now(timezone.utc).isoformat()

    # 1. Update request status to APPROVED
    cursor.execute("""
    UPDATE operator_access_requests
    SET status = 'APPROVED', reviewed_at = ?, reviewed_by = ?, review_reason = ?
    WHERE id = ?
    """, (now, admin_username, reason, request_id))

    # 2. Update user role to OPERATOR (preserve password, salt, email_verified, settings)
    cursor.execute("UPDATE users SET role = 'OPERATOR', is_active = 1 WHERE id = ?", (user_id,))

    # 3. Grant default or custom operator permissions
    cursor.execute("SELECT id, name FROM permissions")
    perm_map = {r["name"]: r["id"] for r in cursor.fetchall()}

    granted_perms = custom_permissions if custom_permissions is not None else DEFAULT_OPERATOR_PERMISSIONS
    for perm_name in granted_perms:
        if perm_name in perm_map:
            cursor.execute("""
            INSERT OR IGNORE INTO user_permissions (user_id, permission_id, granted_by, granted_at)
            VALUES (?, ?, ?, ?)
            """, (user_id, perm_map[perm_name], admin_username, now))

    conn.commit()
    conn.close()

    # Update active session if user is logged in
    for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
        if sess_user.get("id") == user_id:
            sess_user["role"] = "OPERATOR"
            sess_user["permissions"] = get_user_permissions(user_id)

    log_audit_event(
        admin_username,
        "ADMIN",
        "OPERATOR_APPROVED",
        f"User {req_row['email']}",
        "SUCCESS",
        {
            "request_id": request_id,
            "target_user_id": user_id,
            "target_email": req_row["email"],
            "permissions_granted": granted_perms,
            "reason": reason
        }
    )

    return jsonify({
        "success": True,
        "status": "APPROVED",
        "message": f"Operator access approved for {req_row['full_name']} ({req_row['email']}).",
        "user_id": user_id,
        "role": "OPERATOR"
    }), 200

@admin_bp.route("/api/admin/operator-requests/<request_id>/reject", methods=["POST"])
@require_admin
def reject_operator_request(request_id):
    """
    Rejects a pending operator access request.
    The user remains a non-operator (READER). Existing account and credentials preserved.
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    data = request.get_json() or {}
    reason = str(data.get("reason", "Request rejected by Administrator")).strip() or "Request rejected by Administrator"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM operator_access_requests WHERE id = ?", (request_id,))
    req_row = cursor.fetchone()

    if not req_row:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"Operator request {request_id} not found."}), 404

    # Verify request is actually PENDING
    if (req_row["status"] or "").upper() != "PENDING":
        conn.close()
        return jsonify({
            "success": False,
            "error": "Conflict",
            "message": f"Operator request {request_id} is already {req_row['status']} and cannot be rejected."
        }), 400

    user_id = req_row["user_id"]
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
    UPDATE operator_access_requests
    SET status = 'REJECTED', reviewed_at = ?, reviewed_by = ?, review_reason = ?
    WHERE id = ?
    """, (now, admin_username, reason, request_id))

    # User remains READER (do not touch ADMIN if mislinked)
    cursor.execute("UPDATE users SET role = 'READER' WHERE id = ? AND role != 'ADMIN'", (user_id,))

    conn.commit()
    conn.close()

    # Update active session if user is logged in
    for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
        if sess_user.get("id") == user_id:
            sess_user["role"] = "READER"
            sess_user["permissions"] = get_user_permissions(user_id)

    log_audit_event(
        admin_username,
        "ADMIN",
        "OPERATOR_REJECTED",
        f"User {req_row['email']}",
        "SUCCESS",
        {
            "request_id": request_id,
            "target_user_id": user_id,
            "target_email": req_row["email"],
            "reason": reason
        }
    )

    return jsonify({
        "success": True,
        "status": "REJECTED",
        "message": f"Operator access request rejected for {req_row['email']}.",
        "user_id": user_id
    }), 200

@admin_bp.route("/api/admin/permissions", methods=["GET"])
@require_admin
def get_permissions_catalog():
    """Returns all available permissions in the system."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, category, description FROM permissions ORDER BY category, name")
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"success": True, "permissions": [dict(r) for r in rows], "count": len(rows)}), 200

@admin_bp.route("/api/admin/users/<user_id>/permissions", methods=["GET"])
@require_admin
def get_user_perms(user_id):
    """Returns permission list for a specific user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404

    perms = get_user_permissions(user_id)
    return jsonify({
        "success": True,
        "user_id": user_id,
        "username": user["username"],
        "role": user["role"],
        "permissions": perms
    }), 200

@admin_bp.route("/api/admin/users/<user_id>/permissions", methods=["POST", "PUT"])
@require_admin
def set_user_perms(user_id):
    """
    Updates permissions for a specific operator.
    Only ADMIN can grant or revoke permissions.
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    data = request.get_json() or {}
    new_perms = data.get("permissions", [])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404

    if user["role"] == "ADMIN":
        conn.close()
        return jsonify({"success": False, "error": "Forbidden", "message": "Administrator account automatically possesses all permissions."}), 400

    now = datetime.now(timezone.utc).isoformat()

    # Clear existing granted permissions
    cursor.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))

    # Insert new permissions
    cursor.execute("SELECT id, name FROM permissions")
    perm_map = {r["name"]: r["id"] for r in cursor.fetchall()}

    assigned = []
    for p_name in new_perms:
        if p_name in perm_map:
            cursor.execute("""
            INSERT INTO user_permissions (user_id, permission_id, granted_by, granted_at)
            VALUES (?, ?, ?, ?)
            """, (user_id, perm_map[p_name], admin_username, now))
            assigned.append(p_name)

    conn.commit()
    conn.close()

    # Update active session if target user is logged in
    for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
        if sess_user.get("id") == user_id:
            sess_user["permissions"] = get_user_permissions(user_id)

    log_audit_event(
        admin_username,
        "ADMIN",
        "PERMISSIONS_UPDATED",
        f"User {user['email']}",
        "SUCCESS",
        {
            "target_user_id": user_id,
            "target_email": user["email"],
            "permissions": assigned
        }
    )

    return jsonify({
        "success": True,
        "message": f"Permissions updated for {user['username']}.",
        "user_id": user_id,
        "permissions": assigned
    }), 200

def _set_user_active_status(user_id: str, new_status: int):
    """Internal helper to set user active status with full validation, session revocation, and audit logging."""
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, is_active FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404

    # The system administrator account cannot be disabled
    if user["role"] == "ADMIN" or (admin_email and user["email"].strip().lower() == admin_email):
        conn.close()
        return jsonify({"success": False, "error": "Forbidden", "message": "The system administrator account cannot be disabled."}), 403

    if admin_user and admin_user.get("id") == user_id:
        conn.close()
        return jsonify({"success": False, "error": "Forbidden", "message": "The system administrator account cannot be disabled."}), 403

    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()

    action_label = "USER_ENABLED" if new_status else "USER_DISABLED"

    # If disabled, terminate any active sessions immediately
    if new_status == 0:
        for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
            if sess_user.get("id") == user_id:
                del ACTIVE_SESSIONS[sess_token]

    log_audit_event(
        admin_username,
        "ADMIN",
        action_label,
        f"User {user['email']}",
        "SUCCESS",
        {"target_user_id": user_id, "is_active": new_status}
    )

    return jsonify({
        "success": True,
        "message": f"User account {'enabled' if new_status else 'disabled'}.",
        "user_id": user_id,
        "is_active": new_status,
        "status": "ACTIVE" if new_status else "DISABLED"
    }), 200

@admin_bp.route("/api/admin/users/<user_id>/toggle-status", methods=["POST"])
@require_admin
def toggle_user_status(user_id):
    """Enables or disables a user account (inverts current is_active status)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404
    new_status = 0 if row["is_active"] else 1
    return _set_user_active_status(user_id, new_status)

@admin_bp.route("/api/admin/users/<user_id>/disable", methods=["POST"])
@require_admin
def disable_user(user_id):
    """Explicitly disables a user account."""
    return _set_user_active_status(user_id, 0)

@admin_bp.route("/api/admin/users/<user_id>/enable", methods=["POST"])
@require_admin
def enable_user(user_id):
    """Explicitly enables a user account."""
    return _set_user_active_status(user_id, 1)

@admin_bp.route("/api/admin/users/<user_id>/revoke-operator", methods=["POST"])
@require_admin
def revoke_operator_status(user_id):
    """
    Revokes operator privileges from a user and downgrades their role to READER.
    Updates operator_access_requests status to REVOKED and clears all granted control permissions.
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404

    if user["role"] == "ADMIN":
        conn.close()
        return jsonify({"success": False, "error": "Forbidden", "message": "Cannot revoke administrator privileges."}), 400

    if user["role"] != "OPERATOR":
        conn.close()
        return jsonify({"success": False, "error": "Bad Request", "message": f"User '{user['username']}' is not currently an Operator."}), 400

    now = datetime.now(timezone.utc).isoformat()

    # 1. Update role to READER in database
    cursor.execute("UPDATE users SET role = 'READER' WHERE id = ?", (user_id,))

    # 2. Update operator access requests: transition APPROVED / PENDING to REVOKED
    cursor.execute("""
    UPDATE operator_access_requests
    SET status = 'REVOKED', reviewed_at = ?, reviewed_by = ?, review_reason = 'Privileges revoked by Administrator'
    WHERE user_id = ? AND status IN ('APPROVED', 'PENDING')
    """, (now, admin_username, user_id))

    # If no operator request record existed for this operator, insert a REVOKED record for historical consistency
    cursor.execute("SELECT COUNT(*) as c FROM operator_access_requests WHERE user_id = ?", (user_id,))
    if cursor.fetchone()["c"] == 0:
        req_id = f"req_rev_{uuid.uuid4().hex[:8]}"
        cursor.execute("""
        INSERT INTO operator_access_requests (id, user_id, email, full_name, status, requested_at, reviewed_at, reviewed_by, review_reason)
        VALUES (?, ?, ?, ?, 'REVOKED', ?, ?, ?, 'Privileges revoked by Administrator')
        """, (req_id, user_id, user["email"], user["full_name"], now, now, admin_username))

    # 3. Remove custom / operator-granted control permissions
    cursor.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    # 4. Update active session if user is currently logged in
    for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
        if sess_user.get("id") == user_id:
            sess_user["role"] = "READER"
            sess_user["permissions"] = list(READER_VIEW_PERMISSIONS)

    # 5. Record audit trail
    log_audit_event(
        admin_username,
        "ADMIN",
        "OPERATOR_REVOKED",
        f"User {user['email']}",
        "SUCCESS",
        {"target_user_id": user_id, "target_email": user["email"], "new_role": "READER"}
    )

    return jsonify({
        "success": True,
        "message": f"Operator privileges revoked for {user['username']}. Account downgraded to Reader.",
        "user_id": user_id,
        "role": "READER"
    }), 200

@admin_bp.route("/api/admin/users/<user_id>", methods=["DELETE"])
@require_admin
def delete_user(user_id):
    """
    Deletes a user account.
    The configured ADMIN account cannot be deleted under any circumstances (strictly returns HTTP 403).
    Safely cleans up foreign-key references (operator_access_requests, user_permissions, active sessions).
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    admin_email = os.environ.get("ADMIN_EMAIL", "premkumarj18122003@gmail.com").strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        return jsonify({"success": False, "error": "Not Found", "message": f"User {user_id} not found."}), 404

    target_email = (target["email"] or "").strip().lower()
    # The ADMIN account MUST NOT be deleted - return HTTP 403
    if target["role"] == "ADMIN" or (admin_email and target_email == admin_email) or (admin_user and admin_user.get("id") == user_id):
        conn.close()
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "The system administrator account cannot be deleted."
        }), 403

    # Clean up foreign-key relationships safely
    cursor.execute("DELETE FROM operator_access_requests WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    # Invalidate any active session immediately
    for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
        if sess_user.get("id") == user_id:
            del ACTIVE_SESSIONS[sess_token]

    log_audit_event(
        admin_username,
        "ADMIN",
        "USER_DELETED",
        f"User {target['email']}",
        "SUCCESS",
        {"deleted_user_id": user_id, "deleted_username": target["username"], "deleted_email": target["email"]}
    )

    return jsonify({
        "success": True,
        "message": f"User {target['username']} ({target['email']}) deleted successfully.",
        "user_id": user_id
    }), 200

@admin_bp.route("/api/admin/users/bulk-delete", methods=["POST", "DELETE"])
@require_admin
def bulk_delete_users():
    """
    Bulk deletes users.
    Explicitly filters out and protects the system administrator account (cannot be included).
    """
    admin_user = get_current_user()
    admin_username = (admin_user.get("username") if admin_user else None) or os.environ.get("ADMIN_EMAIL", "admin")
    admin_email = os.environ.get("ADMIN_EMAIL", "premkumarj18122003@gmail.com").strip().lower()
    data = request.get_json() or {}
    user_ids = data.get("user_ids", [])
    if not isinstance(user_ids, list):
        return jsonify({"success": False, "error": "Bad Request", "message": "user_ids must be a list."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    deleted_count = 0
    skipped_admin = False
    for uid in user_ids:
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (uid,))
        target = cursor.fetchone()
        if not target:
            continue
        target_email = (target["email"] or "").strip().lower()
        if target["role"] == "ADMIN" or (admin_email and target_email == admin_email) or (admin_user and admin_user.get("id") == uid):
            skipped_admin = True
            continue

        cursor.execute("DELETE FROM operator_access_requests WHERE user_id = ?", (uid,))
        cursor.execute("DELETE FROM user_permissions WHERE user_id = ?", (uid,))
        cursor.execute("DELETE FROM users WHERE id = ?", (uid,))
        deleted_count += 1

        for sess_token, sess_user in list(ACTIVE_SESSIONS.items()):
            if sess_user.get("id") == uid:
                del ACTIVE_SESSIONS[sess_token]

    conn.commit()
    conn.close()

    if deleted_count > 0:
        log_audit_event(
            admin_username,
            "ADMIN",
            "BULK_USERS_DELETED",
            f"{deleted_count} users",
            "SUCCESS",
            {"count": deleted_count, "skipped_admin": skipped_admin}
        )

    return jsonify({
        "success": True,
        "deleted_count": deleted_count,
        "skipped_admin": skipped_admin,
        "message": f"Successfully deleted {deleted_count} users." + (" Protected ADMIN was skipped." if skipped_admin else "")
    }), 200

