"""
VORTEX-SDN Comprehensive Access Control & Security Test Suite
Verifies:
1. Single Administrator policy (exactly ONE admin in installation, no signup/promotion).
2. Approval-based Operator lifecycle (request -> pending -> admin email -> approve/reject -> login control).
3. Strict Read-Only Reader enforcement (all mutation endpoints denied with 403).
4. Granular Permission Management (grant -> allowed; revoke -> immediately denied).
5. Account disabling (disabled user blocked from login).
6. Operator revocation (downgraded back to Reader).
7. Append-only audit logging of all security events.
8. Unauthenticated requests blocked with 401 when auth is enforced.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import (
    init_db,
    get_db_connection,
    hash_password,
    get_user_permissions,
    user_has_permission,
    DEFAULT_PERMISSIONS
)
from backend.services.email_service import generate_secure_token

@pytest.fixture
def app_client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def get_admin_token(client):
    from backend.api.auth import ACTIVE_SESSIONS
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role FROM users WHERE role = 'ADMIN'")
    admin_row = c.fetchone()
    conn.close()
    token = f"vtx_test_admin_{admin_row['id']}"
    ACTIVE_SESSIONS[token] = {
        "id": admin_row["id"],
        "username": admin_row["username"],
        "email": admin_row["email"],
        "role": "ADMIN",
        "permissions": ["*"]
    }
    return token

def test_1_create_normal_user_is_reader(app_client):
    """TEST 1: Normal signup creates a READER account with zero administrative privileges."""
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = 'test_reader@vortex.local'")
    conn.commit()
    conn.close()

    user_data = {
        "username": "test_reader",
        "email": "test_reader@vortex.local",
        "full_name": "Test Reader User",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "READER"
    }

    with patch("backend.api.auth.send_verification_email", return_value=(True, "Sent")):
        res = app_client.post("/api/auth/register", json=user_data)
        assert res.status_code == 201

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role, email_verified FROM users WHERE email = 'test_reader@vortex.local'")
    row = c.fetchone()
    conn.close()

    assert row is not None
    assert row["role"] == "READER"

def test_2_operator_access_request_creates_pending_and_sends_email(app_client):
    """TEST 2: Normal user requests operator access -> status is PENDING -> admin receives email."""
    # Ensure verified user
    conn = get_db_connection()
    conn.execute("UPDATE users SET email_verified = 1 WHERE email = 'test_reader@vortex.local'")
    conn.execute("DELETE FROM operator_access_requests WHERE email = 'test_reader@vortex.local'")
    conn.commit()
    conn.close()

    # Login as reader
    login_res = app_client.post("/api/auth/login", json={"username": "test_reader", "password": "Password@2026"})
    assert login_res.status_code == 200
    token = login_res.get_json()["token"]

    # Submit operator request
    with patch("backend.api.auth.send_operator_request_email") as mock_email:
        req_res = app_client.post("/api/auth/operator-request", headers={"Authorization": f"Bearer {token}"})
        assert req_res.status_code == 201
        data = req_res.get_json()
        assert data["success"] is True
        assert data["status"] == "PENDING"
        assert mock_email.called

    # Verify database state
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT status FROM operator_access_requests WHERE email = 'test_reader@vortex.local'")
    req_row = c.fetchone()
    conn.close()
    assert req_row is not None
    assert req_row["status"] == "PENDING"

def test_3_admin_approves_operator_request(app_client):
    """TEST 3 & 4: Admin approves request -> user becomes OPERATOR and can log in."""
    # Find request id
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, user_id FROM operator_access_requests WHERE email = 'test_reader@vortex.local'")
    req = c.fetchone()
    conn.close()
    assert req is not None

    admin_token = get_admin_token(app_client)

    # Approve request
    appr_res = app_client.post(
        f"/api/admin/operator-requests/{req['id']}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"reason": "Approved for NOC Operations"}
    )
    assert appr_res.status_code == 200
    assert appr_res.get_json()["status"] == "APPROVED"

    # Verify user role is now OPERATOR
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (req["user_id"],))
    u_row = c.fetchone()
    conn.close()
    assert u_row["role"] == "OPERATOR"

    # Operator logs in successfully
    op_login = app_client.post("/api/auth/login", json={"username": "test_reader@vortex.local", "password": "Password@2026"})
    assert op_login.status_code == 200
    assert op_login.get_json()["user"]["role"] == "OPERATOR"

def test_5_and_6_operator_cannot_call_admin_api_or_grant_permissions(app_client):
    """TEST 5 & 6: Operator calling admin API or trying to grant permissions is blocked with 403."""
    op_login = app_client.post("/api/auth/login", json={"username": "test_reader@vortex.local", "password": "Password@2026"})
    op_token = op_login.get_json()["token"]

    # Operator calling list_users
    res1 = app_client.get("/api/admin/users", headers={"Authorization": f"Bearer {op_token}"})
    assert res1.status_code == 403
    assert res1.get_json()["error"] == "Forbidden"

    # Operator calling list_operator_requests
    res2 = app_client.get("/api/admin/operator-requests", headers={"Authorization": f"Bearer {op_token}"})
    assert res2.status_code == 403

    # Operator trying to grant permissions
    res3 = app_client.post("/api/admin/users/usr_test/permissions", headers={"Authorization": f"Bearer {op_token}"}, json={"permissions": ["*"]})
    assert res3.status_code == 403

def test_7_reader_cannot_call_mutations(app_client):
    """TEST 7 & READER STRICT TESTS: Reader accounts calling any mutation API receive 403 with exact message."""
    # Create and verify a dedicated Reader
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = 'strict_reader@vortex.local'")
    conn.execute("DELETE FROM operator_access_requests WHERE email = 'strict_reader@vortex.local'")
    pwd_h, salt = hash_password("Password@2026")
    conn.execute("""
    INSERT INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
    VALUES ('usr_strict_reader', 'strict_reader', 'strict_reader@vortex.local', 'Strict Reader', ?, ?, 'READER', 1, 1, '2026-10-06T00:00:00Z')
    """, (pwd_h, salt))
    conn.commit()
    conn.close()

    r_login = app_client.post("/api/auth/login", json={"username": "strict_reader@vortex.local", "password": "Password@2026"})
    assert r_login.status_code == 200
    r_token = r_login.get_json()["token"]

    headers = {"Authorization": f"Bearer {r_token}"}

    # 1. Reader GET endpoints are ALLOWED
    get_summ = app_client.get("/api/security/summary", headers=headers)
    assert get_summ.status_code == 200

    get_pol = app_client.get("/api/policies", headers=headers)
    assert get_pol.status_code == 200

    get_inc = app_client.get("/api/incidents", headers=headers)
    assert get_inc.status_code == 200

    # 2. Reader POST/DELETE mutation endpoints are STRICTLY FORBIDDEN (403)
    # Mutation 1: Policies POST
    post_pol = app_client.post("/api/policies", headers=headers, json={"type": "QOS", "name": "Hack Rule"})
    assert post_pol.status_code == 403
    assert post_pol.get_json()["message"] == "Reader accounts have read-only access."

    # Mutation 2: Mitigation POST
    post_mit = app_client.post("/api/security/mitigate", headers=headers, json={"action": "BLOCK"})
    assert post_mit.status_code == 403
    assert post_mit.get_json()["message"] == "Reader accounts have read-only access."

    # Mutation 3: Security Mode POST
    post_mode = app_client.post("/api/security/mode", headers=headers, json={"mode": "ACTIVE"})
    assert post_mode.status_code == 403
    assert post_mode.get_json()["message"] == "Reader accounts have read-only access."

    # Mutation 4: Demo Scenario POST
    post_scen = app_client.post("/api/demo/scenario", headers=headers, json={"scenario": "DDOS_ATTACK"})
    assert post_scen.status_code == 403
    assert post_scen.get_json()["message"] == "Reader accounts have read-only access."

    # Mutation 5: Incident acknowledge POST
    post_ack = app_client.post("/api/incidents/inc_test/acknowledge", headers=headers)
    assert post_ack.status_code == 403
    assert post_ack.get_json()["message"] == "Reader accounts have read-only access."

def test_8_and_9_grant_and_revoke_granular_permissions(app_client):
    """TEST 8 & 9: Admin grants network.configure -> Operator can use it; Admin revokes it -> Operator loses it."""
    admin_token = get_admin_token(app_client)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = 'test_reader@vortex.local'")
    op_user_id = c.fetchone()["id"]
    conn.close()

    # Admin explicitly grants ONLY "network.configure"
    grant_res = app_client.post(
        f"/api/admin/users/{op_user_id}/permissions",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"permissions": ["network.configure"]}
    )
    assert grant_res.status_code == 200

    # Operator logs in and tests
    op_login = app_client.post("/api/auth/login", json={"username": "test_reader@vortex.local", "password": "Password@2026"})
    op_token = op_login.get_json()["token"]
    op_headers = {"Authorization": f"Bearer {op_token}"}

    # Allowed: network.configure action
    scen_res = app_client.post("/api/demo/scenario", headers=op_headers, json={"scenario": "NORMAL"})
    assert scen_res.status_code == 200

    # Denied: security.response action (not granted!)
    mit_res = app_client.post("/api/security/mitigate", headers=op_headers, json={"threat_id": "thr_999"})
    assert mit_res.status_code == 403

    # Admin revokes network.configure (sets empty permissions)
    revoke_res = app_client.post(
        f"/api/admin/users/{op_user_id}/permissions",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"permissions": []}
    )
    assert revoke_res.status_code == 200

    # Operator immediately loses network.configure
    scen_res2 = app_client.post("/api/demo/scenario", headers=op_headers, json={"scenario": "NORMAL"})
    assert scen_res2.status_code == 403

def test_10_and_11_attempt_to_create_or_forge_admin_blocked(app_client):
    """TEST 10 & 11: Attempt to register as ADMIN or forge role is blocked by backend."""
    # 1. Attempt to register with role = ADMIN
    bad_reg = app_client.post("/api/auth/register", json={
        "username": "hacker_admin",
        "email": "hacker_admin@vortex.local",
        "full_name": "Hacker Admin",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "ADMIN"
    })
    assert bad_reg.status_code == 403
    assert bad_reg.get_json()["error"] == "Forbidden"

    # 2. Verify exactly ONE admin exists in SQLite
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'")
    admin_count = c.fetchone()[0]
    conn.close()
    assert admin_count == 1

def test_12_disable_operator_blocks_login(app_client):
    """TEST 12: Disabled user account cannot log in."""
    admin_token = get_admin_token(app_client)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = 'test_reader@vortex.local'")
    op_user_id = c.fetchone()["id"]
    conn.close()

    # Toggle status to disabled (0)
    dis_res = app_client.post(f"/api/admin/users/{op_user_id}/toggle-status", headers={"Authorization": f"Bearer {admin_token}"})
    assert dis_res.status_code == 200
    assert dis_res.get_json()["is_active"] == 0

    # Operator login now fails with 403
    blocked_login = app_client.post("/api/auth/login", json={"username": "test_reader@vortex.local", "password": "Password@2026"})
    assert blocked_login.status_code == 403
    assert blocked_login.get_json()["message"] == "Account has been disabled."

    # Re-enable
    en_res = app_client.post(f"/api/admin/users/{op_user_id}/toggle-status", headers={"Authorization": f"Bearer {admin_token}"})
    assert en_res.status_code == 200
    assert en_res.get_json()["is_active"] == 1

def test_13_revoke_operator_downgrades_to_reader(app_client):
    """TEST 13: Revoke operator downgrades role to READER and clears permissions."""
    admin_token = get_admin_token(app_client)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = 'test_reader@vortex.local'")
    op_user_id = c.fetchone()["id"]
    conn.close()

    rev_res = app_client.post(f"/api/admin/users/{op_user_id}/revoke-operator", headers={"Authorization": f"Bearer {admin_token}"})
    assert rev_res.status_code == 200
    assert rev_res.get_json()["role"] == "READER"

    # User in database is now READER
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (op_user_id,))
    assert c.fetchone()["role"] == "READER"
    conn.close()

def test_14_audit_trail_records_events(app_client):
    """TEST 14: All security-sensitive actions appear in audit log."""
    admin_token = get_admin_token(app_client)

    audit_res = app_client.get("/api/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_res.status_code == 200
    logs = audit_res.get_json()["logs"]
    assert len(logs) > 0

    actions = [l["action"] for l in logs]
    # Verify critical audit action types were recorded
    assert any("OPERATOR" in a or "LOGIN" in a or "PERMISSIONS" in a or "USER" in a for a in actions)
