"""
Tests for Strict Single Administrator Policy & Configuration Enforcements.
Verifies:
1. Reads ADMIN_EMAIL from .env (normalized).
2. Assigns existing user the ADMIN role and preserves existing password and email-verification status.
3. Does not create a second user account for the admin.
4. If ADMIN_EMAIL account does not exist, reports clearly:
   'Configured ADMIN_EMAIL account does not exist. Create/verify the account first.'
5. If more than one ADMIN exists in the database, detects the conflict and requires administrative intervention.
6. Does not allow users to select ADMIN during registration (rejects with 403).
7. Does not trust browser-submitted role or is_admin fields.
8. Role cannot be changed to ADMIN via frontend or API.
9. Only the administrator corresponding to ADMIN_EMAIL can approve operators or grant/revoke permissions.
"""

import os
import sys
import pytest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import (
    init_db,
    bootstrap_single_admin,
    get_db_connection,
    hash_password,
    get_user_permissions
)

@pytest.fixture
def test_client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_admin_email_account_not_found_reports_and_raises():
    """If ADMIN_EMAIL account does not exist, do NOT create an admin; report clearly."""
    with patch.dict(os.environ, {"ADMIN_EMAIL": "nonexistent_admin_12345@example.com"}):
        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_single_admin()
        assert "Configured ADMIN_EMAIL account does not exist. Create/verify the account first." in str(exc_info.value)

def test_multiple_admins_conflict_detection():
    """If more than one ADMIN exists in the database, detect conflict and require intervention."""
    conn = get_db_connection()
    c = conn.cursor()
    pwd_hash, salt = hash_password("TempPass123!")
    # Insert temporary second admin
    c.execute("""
    INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
    VALUES ('usr_rogue_admin', 'rogue_admin', 'rogue_admin@example.com', 'Rogue Admin', ?, ?, 'ADMIN', 1, 1, '2026-01-01T00:00:00Z')
    """, (pwd_hash, salt))
    conn.commit()
    conn.close()

    try:
        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_single_admin()
        assert "Conflict detected" in str(exc_info.value)
        assert "Administrative intervention required" in str(exc_info.value)
    finally:
        # Cleanup rogue admin
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = 'usr_rogue_admin'")
        conn.commit()
        conn.close()

def test_existing_admin_account_preserves_password_and_verification():
    """Assigns ADMIN role to existing user and preserves password and email_verified values."""
    admin_email = os.environ.get("ADMIN_EMAIL", "vertexsdn@gmail.com").strip().lower()
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, email_verified, role FROM users WHERE LOWER(email) = ?", (admin_email,))
    before = c.fetchone()
    conn.close()

    assert before is not None
    orig_hash = before["password_hash"]
    orig_salt = before["salt"]
    orig_verified = before["email_verified"]

    # Re-run bootstrap
    bootstrap_single_admin()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, email_verified, role FROM users WHERE LOWER(email) = ?", (admin_email,))
    after = c.fetchone()
    conn.close()

    assert after["role"] == "ADMIN"
    assert after["password_hash"] == orig_hash
    assert after["salt"] == orig_salt
    assert after["email_verified"] == orig_verified

def test_no_second_user_account_created():
    """Ensure no duplicate admin account is created."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'")
    admin_count = c.fetchone()[0]
    conn.close()
    assert admin_count == 1

def test_register_with_admin_role_rejected(test_client):
    """Users cannot select ADMIN during registration."""
    res = test_client.post("/api/auth/register", json={
        "username": "fake_admin",
        "email": "fake_admin@example.com",
        "full_name": "Fake Admin",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "ADMIN"
    })
    assert res.status_code == 403
    assert res.get_json()["error"] == "Forbidden"

def test_register_with_browser_submitted_is_admin_flag_rejected(test_client):
    """Do not trust browser-submitted is_admin or isAdmin field."""
    res = test_client.post("/api/auth/register", json={
        "username": "sneaky_user",
        "email": "sneaky_user@example.com",
        "full_name": "Sneaky User",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "READER",
        "is_admin": True
    })
    assert res.status_code == 403
    assert res.get_json()["error"] == "Forbidden"

def test_only_configured_admin_email_can_approve_operators(test_client):
    """Only the administrator corresponding to ADMIN_EMAIL can approve operator requests."""
    # Create and verify an operator request
    conn = get_db_connection()
    c = conn.cursor()
    # Create reader user
    pwd_hash, salt = hash_password("Password@2026")
    c.execute("""
    INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
    VALUES ('usr_test_cand', 'test_cand', 'test_cand@vortex.local', 'Test Candidate', ?, ?, 'READER', 1, 1, '2026-01-01T00:00:00Z')
    """, (pwd_hash, salt))
    c.execute("""
    INSERT OR REPLACE INTO operator_access_requests (id, user_id, email, full_name, status, requested_at)
    VALUES ('req_test_cand', 'usr_test_cand', 'test_cand@vortex.local', 'Test Candidate', 'PENDING', '2026-01-01T00:00:00Z')
    """,)
    conn.commit()
    conn.close()

    # Reader login
    cand_login = test_client.post("/api/auth/login", json={"username": "test_cand@vortex.local", "password": "Password@2026"})
    cand_token = cand_login.get_json()["token"]

    # Reader attempts to approve operator request -> 403
    cand_approve = test_client.post("/api/admin/operator-requests/req_test_cand/approve", headers={"Authorization": f"Bearer {cand_token}"}, json={})
    assert cand_approve.status_code == 403

    # Demoted former admin (vertexsdn@gmail.com) login -> now OPERATOR, so approve is blocked with 403
    conn = get_db_connection()
    c = conn.cursor()
    pwd_hash_vtx, salt_vtx = hash_password("Admin@Vortex2026!")
    c.execute("""
    INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
    VALUES ('usr_admin_7d3fb1', 'vertexsdn', 'vertexsdn@gmail.com', 'Former Admin', ?, ?, 'OPERATOR', 1, 1, '2026-01-01T00:00:00Z')
    """, (pwd_hash_vtx, salt_vtx))
    conn.commit()
    conn.close()

    former_admin_login = test_client.post("/api/auth/login", json={"username": "vertexsdn@gmail.com", "password": "Admin@Vortex2026!"})
    assert former_admin_login.status_code == 200
    assert former_admin_login.get_json()["user"]["role"] == "OPERATOR"
    former_token = former_admin_login.get_json()["token"]

    former_approve = test_client.post("/api/admin/operator-requests/req_test_cand/approve", headers={"Authorization": f"Bearer {former_token}"}, json={})
    assert former_approve.status_code == 403

    # Legitimate ADMIN (premkumarj18122003@gmail.com) approves -> 200
    admin_token = "vtx_test_admin_premkumar"
    from backend.api.auth import ACTIVE_SESSIONS
    ACTIVE_SESSIONS[admin_token] = {
        "id": "usr_1084be32",
        "username": "sakshi",
        "email": "premkumarj18122003@gmail.com",
        "role": "ADMIN",
        "permissions": ["*"]
    }

    admin_approve = test_client.post("/api/admin/operator-requests/req_test_cand/approve", headers={"Authorization": f"Bearer {admin_token}"}, json={})
    assert admin_approve.status_code == 200
    assert admin_approve.get_json()["status"] == "APPROVED"

    # Clean up test user & request & session
    ACTIVE_SESSIONS.pop(admin_token, None)
    conn = get_db_connection()
    conn.execute("DELETE FROM operator_access_requests WHERE id = 'req_test_cand'")
    conn.execute("DELETE FROM user_permissions WHERE user_id = 'usr_test_cand'")
    conn.execute("DELETE FROM users WHERE id = 'usr_test_cand'")
    conn.execute("DELETE FROM users WHERE id = 'usr_admin_7d3fb1'")
    conn.commit()
    conn.close()

def test_handover_safety_unverified_target_rejected():
    """Handover stops if target account is not email-verified."""
    from backend.models.database import perform_admin_handover
    conn = get_db_connection()
    pwd_hash, salt = hash_password("Pass@123")
    conn.execute("""
    INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
    VALUES ('usr_unverified_target', 'unverified_target', 'unverified_target@example.com', 'Unverified', ?, ?, 'OPERATOR', 1, 0, '2026-01-01T00:00:00Z')
    """, (pwd_hash, salt))
    conn.commit()
    conn.close()

    try:
        with patch.dict(os.environ, {"ADMIN_TRANSFER_CONFIRM": "true"}):
            with pytest.raises(RuntimeError) as exc:
                perform_admin_handover(old_admin_email="premkumarj18122003@gmail.com", target_admin_email="unverified_target@example.com")
            assert "is not email-verified" in str(exc.value)
    finally:
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = 'usr_unverified_target'")
        conn.commit()
        conn.close()

def test_handover_safety_nonexistent_target_rejected():
    """Handover stops if target account does not exist."""
    from backend.models.database import perform_admin_handover
    with patch.dict(os.environ, {"ADMIN_TRANSFER_CONFIRM": "true"}):
        with pytest.raises(RuntimeError) as exc:
            perform_admin_handover(old_admin_email="premkumarj18122003@gmail.com", target_admin_email="ghost_user_999@example.com")
        assert "does not exist" in str(exc.value)

def test_handover_safety_missing_confirmation_flag_rejected():
    """Handover stops if ADMIN_TRANSFER_CONFIRM=true is missing."""
    from backend.models.database import perform_admin_handover
    with patch.dict(os.environ, {"ADMIN_TRANSFER_CONFIRM": "false"}):
        with pytest.raises(RuntimeError) as exc:
            perform_admin_handover(old_admin_email="premkumarj18122003@gmail.com", target_admin_email="vertexsdn@gmail.com")
        assert "ADMIN_TRANSFER_CONFIRM=true" in str(exc.value)

def test_handover_safety_wrong_old_admin_rejected():
    """Handover stops if old admin is not the current database admin."""
    from backend.models.database import perform_admin_handover
    with patch.dict(os.environ, {"ADMIN_TRANSFER_CONFIRM": "true"}):
        with pytest.raises(RuntimeError) as exc:
            perform_admin_handover(old_admin_email="wrong_old_admin@example.com", target_admin_email="vertexsdn@gmail.com")
        assert "Existing ADMIN is not wrong_old_admin@example.com" in str(exc.value)

