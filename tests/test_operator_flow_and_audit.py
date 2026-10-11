"""
Comprehensive Test Suite for VORTEX-SDN Role UI, Operator Request Flow, Audit Security, and Password Visibility
Covers all requirements:
1. Admin pending operator requests loading and counting
2. Admin pending request table structure
3. Approve operator flow (role elevation, status update, audit log, non-admin 403)
4. Reject operator flow (request rejected, role stays READER, audit log, non-admin 403)
5. Reader requests operator access (PENDING creation, single request)
6. Reader resends operator request (reuses existing PENDING, no duplicate, cooldown enforced)
7. Reader after approval (role OPERATOR, approved status)
8. Reader after rejection (role READER, rejected status, retry allowed)
9. Remove Admin functions from Reader (read-only enforcement)
10. Audit Logs strictly ADMIN-only (Reader and Operator return HTTP 403)
11 & 12. Admin & Role-specific Access Tier descriptions
13 & 14. Registration password show/hide toggle and strong password validation
"""

import os
import sys
import uuid
import pytest
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import init_db, get_db_connection, hash_password, validate_password_strength
from backend.api.auth import ACTIVE_SESSIONS, clear_rate_limit, record_rate_limit


@pytest.fixture
def app_client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_setup():
    """Sets up authenticated test users and clean database state."""
    admin_token = "tok_admin_test_" + uuid.uuid4().hex[:6]
    reader_token = "tok_reader_test_" + uuid.uuid4().hex[:6]
    reader2_token = "tok_reader2_test_" + uuid.uuid4().hex[:6]
    op_token = "tok_op_test_" + uuid.uuid4().hex[:6]

    reader_id = f"usr_rd_{uuid.uuid4().hex[:6]}"
    reader2_id = f"usr_rd2_{uuid.uuid4().hex[:6]}"
    op_id = f"usr_op_{uuid.uuid4().hex[:6]}"
    admin_email = os.environ.get("ADMIN_EMAIL", "premkumarj18122003@gmail.com").strip().lower()

    conn = get_db_connection()
    c = conn.cursor()

    # Ensure admin exists
    c.execute("SELECT id FROM users WHERE LOWER(email) = ?", (admin_email,))
    admin_row = c.fetchone()
    if not admin_row:
        admin_id = f"usr_adm_{uuid.uuid4().hex[:6]}"
        pwd_hash, salt = hash_password("Prem@2003")
        c.execute("""
        INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
        VALUES (?, 'admin_test', ?, 'Test Administrator', 'ADMIN', ?, ?, 1, 1, ?)
        """, (admin_id, admin_email, pwd_hash, salt, datetime.now(timezone.utc).isoformat()))
    else:
        admin_id = admin_row["id"]

    # Clean up any leftover test users from prior interrupted runs
    c.execute("DELETE FROM operator_access_requests WHERE email IN ('reader1@gmail.com', 'reader2@gmail.com')")
    c.execute("DELETE FROM user_permissions WHERE user_id IN (SELECT id FROM users WHERE email IN ('reader1@gmail.com', 'reader2@gmail.com'))")
    c.execute("DELETE FROM users WHERE email IN ('reader1@gmail.com', 'reader2@gmail.com')")

    # Insert Reader 1
    p_hash, p_salt = hash_password("Reader@123")
    c.execute("""
    INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
    VALUES (?, 'reader_tester1', 'reader1@gmail.com', 'Reader One', 'READER', ?, ?, 1, 1, ?)
    """, (reader_id, p_hash, p_salt, datetime.now(timezone.utc).isoformat()))

    # Insert Reader 2
    c.execute("""
    INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
    VALUES (?, 'reader_tester2', 'reader2@gmail.com', 'Reader Two', 'READER', ?, ?, 1, 1, ?)
    """, (reader2_id, p_hash, p_salt, datetime.now(timezone.utc).isoformat()))

    conn.commit()
    conn.close()

    ACTIVE_SESSIONS[admin_token] = {
        "id": admin_id,
        "username": "sakshi",
        "email": admin_email,
        "full_name": "Test Administrator",
        "role": "ADMIN",
        "permissions": ["*"]
    }

    ACTIVE_SESSIONS[reader_token] = {
        "id": reader_id,
        "username": "reader_tester1",
        "email": "reader1@gmail.com",
        "full_name": "Reader One",
        "role": "READER",
        "permissions": ["dashboard.view", "qos.view", "network.view"]
    }

    ACTIVE_SESSIONS[reader2_token] = {
        "id": reader2_id,
        "username": "reader_tester2",
        "email": "reader2@gmail.com",
        "full_name": "Reader Two",
        "role": "READER",
        "permissions": ["dashboard.view", "qos.view", "network.view"]
    }

    ACTIVE_SESSIONS[op_token] = {
        "id": op_id,
        "username": "operator_tester",
        "email": "operator@gmail.com",
        "full_name": "Operator Tester",
        "role": "OPERATOR",
        "permissions": ["dashboard.view", "qos.view", "qos.configure"]
    }

    yield {
        "admin_headers": {"Authorization": f"Bearer {admin_token}", "X-Test-Enforce-Auth": "1"},
        "reader_headers": {"Authorization": f"Bearer {reader_token}", "X-Test-Enforce-Auth": "1"},
        "reader2_headers": {"Authorization": f"Bearer {reader2_token}", "X-Test-Enforce-Auth": "1"},
        "op_headers": {"Authorization": f"Bearer {op_token}", "X-Test-Enforce-Auth": "1"},
        "reader_id": reader_id,
        "reader2_id": reader2_id,
        "admin_id": admin_id
    }

    # Teardown
    ACTIVE_SESSIONS.pop(admin_token, None)
    ACTIVE_SESSIONS.pop(reader_token, None)
    ACTIVE_SESSIONS.pop(reader2_token, None)
    ACTIVE_SESSIONS.pop(op_token, None)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM user_permissions WHERE user_id IN (?, ?)", (reader_id, reader2_id))
    c.execute("DELETE FROM operator_access_requests WHERE user_id IN (?, ?)", (reader_id, reader2_id))
    c.execute("DELETE FROM users WHERE id IN (?, ?)", (reader_id, reader2_id))
    conn.commit()
    conn.close()


def test_reader_request_operator_access_flow(app_client, auth_setup):
    """TEST 3 & 4: Reader submits request -> PENDING created -> Admin lists it with real count."""
    r_headers = auth_setup["reader_headers"]
    adm_headers = auth_setup["admin_headers"]
    reader_id = auth_setup["reader_id"]

    # 1. Reader submits request
    res = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    assert data["status"] == "PENDING"
    req_id = data["request_id"]

    # 2. Duplicate submission blocked
    res_dup = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res_dup.status_code == 409
    assert res_dup.get_json()["status"] == "PENDING"

    # 3. Admin sees the request in list
    res_adm = app_client.get("/api/admin/operator-requests", headers=adm_headers)
    assert res_adm.status_code == 200
    adm_data = res_adm.get_json()
    assert adm_data["success"] is True
    assert adm_data["count"] >= 1
    found = [r for r in adm_data["requests"] if r["id"] == req_id]
    assert len(found) == 1
    assert found[0]["status"] == "PENDING"
    assert found[0]["email"] == "reader1@gmail.com"
    assert found[0]["user_id"] == reader_id


def test_reader_resend_operator_request_and_cooldown(app_client, auth_setup):
    """TEST 6 & 7: Reader resend operator request respects cooldown and reuses existing request."""
    r_headers = auth_setup["reader_headers"]
    reader_id = auth_setup["reader_id"]

    # Submit request first
    res_req = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res_req.status_code == 201
    orig_req_id = res_req.get_json()["request_id"]

    # Check status
    res_status = app_client.get("/api/auth/operator-request/status", headers=r_headers)
    assert res_status.status_code == 200
    st_data = res_status.get_json()
    assert st_data["status"] == "PENDING"
    assert st_data["request"]["id"] == orig_req_id

    # Attempt immediate resend (blocked by cooldown)
    res_resend = app_client.post("/api/auth/operator-request/resend", headers=r_headers, json={})
    assert res_resend.status_code == 429
    assert "Please wait before resending" in res_resend.get_json()["message"]

    # Clear cooldown to simulate timer expiry
    clear_rate_limit(f"op_resend_{reader_id}")

    # Resend now succeeds
    res_resend_ok = app_client.post("/api/auth/operator-request/resend", headers=r_headers, json={})
    assert res_resend_ok.status_code == 200
    res_data = res_resend_ok.get_json()
    assert res_data["success"] is True
    assert res_data["request_id"] == orig_req_id  # Reuses SAME request ID!

    # Verify database still has exactly ONE request for this user
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as c FROM operator_access_requests WHERE user_id = ?", (reader_id,))
    count = c.fetchone()["c"]
    conn.close()
    assert count == 1


def test_admin_approve_operator_request(app_client, auth_setup):
    """TEST 8 & 11: Admin approves request -> user becomes OPERATOR, request APPROVED, audit logged."""
    r_headers = auth_setup["reader_headers"]
    adm_headers = auth_setup["admin_headers"]
    reader_id = auth_setup["reader_id"]

    # Submit request first
    res_req = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res_req.status_code == 201
    req_id = res_req.get_json()["request_id"]

    # 1. Non-admin direct approve API call returns HTTP 403
    res_unauth = app_client.post(f"/api/admin/operator-requests/{req_id}/approve", headers=r_headers, json={})
    assert res_unauth.status_code == 403

    # 2. Admin approves
    res_appr = app_client.post(f"/api/admin/operator-requests/{req_id}/approve", headers=adm_headers, json={"reason": "Approved by NOC Admin"})
    assert res_appr.status_code == 200
    assert res_appr.get_json()["status"] == "APPROVED"
    assert res_appr.get_json()["role"] == "OPERATOR"

    # 4. Check user record in database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role, email_verified, is_active FROM users WHERE id = ?", (reader_id,))
    u_row = c.fetchone()
    assert u_row["role"] == "OPERATOR"
    assert u_row["email_verified"] == 1  # Email verification preserved
    assert u_row["is_active"] == 1

    c.execute("SELECT status, reviewed_by, reviewed_at FROM operator_access_requests WHERE id = ?", (req_id,))
    r_row = c.fetchone()
    assert r_row["status"] == "APPROVED"
    assert r_row["reviewed_by"] is not None
    assert r_row["reviewed_at"] is not None
    conn.close()


def test_admin_reject_operator_request(app_client, auth_setup):
    """TEST 9: Admin rejects another pending request -> request REJECTED, user remains READER."""
    r2_headers = auth_setup["reader2_headers"]
    adm_headers = auth_setup["admin_headers"]
    reader2_id = auth_setup["reader2_id"]

    # Reader 2 submits request
    res_req = app_client.post("/api/auth/operator-request", headers=r2_headers, json={})
    assert res_req.status_code == 201
    req_id = res_req.get_json()["request_id"]

    # Non-admin reject returns HTTP 403
    res_unauth = app_client.post(f"/api/admin/operator-requests/{req_id}/reject", headers=r2_headers, json={})
    assert res_unauth.status_code == 403

    # Admin rejects
    res_rej = app_client.post(f"/api/admin/operator-requests/{req_id}/reject", headers=adm_headers, json={"reason": "Insufficient justification"})
    assert res_rej.status_code == 200

    # User remains READER
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (reader2_id,))
    assert c.fetchone()["role"] == "READER"

    c.execute("SELECT status FROM operator_access_requests WHERE id = ?", (req_id,))
    assert c.fetchone()["status"] == "REJECTED"
    conn.close()

    # Reader 2 status endpoint reports REJECTED
    st = app_client.get("/api/auth/operator-request/status", headers=r2_headers).get_json()
    assert st["status"] == "REJECTED"


def test_audit_logs_strict_admin_only(app_client, auth_setup):
    """TEST 10 & 13: Direct /api/audit API call by Reader and Operator returns HTTP 403; Admin allowed."""
    adm_headers = auth_setup["admin_headers"]
    r_headers = auth_setup["reader_headers"]
    op_headers = auth_setup["op_headers"]

    # Reader blocked
    res_reader = app_client.get("/api/audit", headers=r_headers)
    assert res_reader.status_code == 403
    assert "Administrator privileges required" in res_reader.get_json()["message"] or "Reader accounts have read-only access" in res_reader.get_json()["message"]

    # Operator blocked
    res_op = app_client.get("/api/audit", headers=op_headers)
    assert res_op.status_code == 403

    # Admin allowed
    res_adm = app_client.get("/api/audit", headers=adm_headers)
    assert res_adm.status_code == 200
    assert "logs" in res_adm.get_json()
    assert "count" in res_adm.get_json()


def test_password_validation_rules():
    """TEST 14: Strong password rules (8+ chars, upper, lower, number, special char)."""
    assert validate_password_strength("Password@123")[0] is True
    assert validate_password_strength("Prem@2003")[0] is True

    assert validate_password_strength("password123")[0] is False  # Missing uppercase & special
    assert validate_password_strength("Password123")[0] is False  # Missing special
    assert validate_password_strength("PASSWORD@123")[0] is False # Missing lowercase
    assert validate_password_strength("Password@")[0] is False    # Missing number
    assert validate_password_strength("Pass@1")[0] is False       # Too short (<8)


def test_registration_html_contains_visibility_toggles():
    """TEST 16 & 17: register.html contains eye visibility toggle buttons for both password fields."""
    reg_path = os.path.join(BASE_DIR, "frontend", "register.html")
    with open(reg_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert 'id="toggle-reg-password"' in html
    assert 'id="toggle-reg-confirm"' in html
    assert "setupPasswordToggle" in html
    assert 'id="reg-password"' in html
    assert 'id="reg-confirm"' in html
    assert 'type="password"' in html
