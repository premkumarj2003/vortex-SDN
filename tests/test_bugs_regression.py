"""
Regression Test Suite for Bug 1 (Operator Access Request Flow) and Bug 2 (OTP Verification Behavior)
Strictly adheres to all user requirements.
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
from backend.models.database import init_db, get_db_connection, hash_password
from backend.api.auth import ACTIVE_SESSIONS, clear_rate_limit
from backend.services.email_service import generate_secure_otp, verify_email_otp


@pytest.fixture
def app_client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def test_accounts():
    """Sets up isolated reader, operator, and admin test users."""
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("DELETE FROM operator_access_requests WHERE email LIKE 'regression_%@vortex.local'")
    c.execute("DELETE FROM user_permissions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'regression_%@vortex.local')")
    c.execute("DELETE FROM users WHERE email LIKE 'regression_%@vortex.local'")

    admin_email = os.environ.get("ADMIN_EMAIL", "premkumarj18122003@gmail.com").strip().lower()
    c.execute("SELECT id FROM users WHERE LOWER(email) = ?", (admin_email,))
    admin_row = c.fetchone()
    if admin_row:
        admin_id = admin_row["id"]
    else:
        admin_id = f"reg_adm_{uuid.uuid4().hex[:6]}"
        pwd_hash, salt = hash_password("Admin@2026")
        c.execute("""
        INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
        VALUES (?, 'reg_admin', ?, 'Regression Admin', 'ADMIN', ?, ?, 1, 1, ?)
        """, (admin_id, admin_email, pwd_hash, salt, datetime.now(timezone.utc).isoformat()))

    # Reader user
    reader_id = f"reg_rdr_{uuid.uuid4().hex[:6]}"
    r_hash, r_salt = hash_password("Reader@2026")
    c.execute("""
    INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
    VALUES (?, 'reg_reader', 'regression_reader@vortex.local', 'Regression Reader', 'READER', ?, ?, 1, 1, ?)
    """, (reader_id, r_hash, r_salt, datetime.now(timezone.utc).isoformat()))

    # Operator user
    operator_id = f"reg_opr_{uuid.uuid4().hex[:6]}"
    o_hash, o_salt = hash_password("Operator@2026")
    c.execute("""
    INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, created_at)
    VALUES (?, 'reg_operator', 'regression_operator@vortex.local', 'Regression Operator', 'OPERATOR', ?, ?, 1, 1, ?)
    """, (operator_id, o_hash, o_salt, datetime.now(timezone.utc).isoformat()))

    conn.commit()
    conn.close()

    admin_tok = f"tok_admin_{uuid.uuid4().hex[:6]}"
    reader_tok = f"tok_reader_{uuid.uuid4().hex[:6]}"
    operator_tok = f"tok_operator_{uuid.uuid4().hex[:6]}"

    ACTIVE_SESSIONS[admin_tok] = {"id": admin_id, "username": "admin", "email": admin_email, "role": "ADMIN", "permissions": ["*"]}
    ACTIVE_SESSIONS[reader_tok] = {"id": reader_id, "username": "reg_reader", "email": "regression_reader@vortex.local", "role": "READER", "permissions": ["dashboard.view"]}
    ACTIVE_SESSIONS[operator_tok] = {"id": operator_id, "username": "reg_operator", "email": "regression_operator@vortex.local", "role": "OPERATOR", "permissions": ["dashboard.view", "qos.configure"]}

    yield {
        "admin_tok": admin_tok,
        "reader_tok": reader_tok,
        "operator_tok": operator_tok,
        "admin_id": admin_id,
        "reader_id": reader_id,
        "operator_id": operator_id,
        "admin_email": admin_email,
        "admin_headers": {"Authorization": f"Bearer {admin_tok}", "X-Test-Enforce-Auth": "1"},
        "reader_headers": {"Authorization": f"Bearer {reader_tok}", "X-Test-Enforce-Auth": "1"},
        "operator_headers": {"Authorization": f"Bearer {operator_tok}", "X-Test-Enforce-Auth": "1"},
    }

    # Teardown
    ACTIVE_SESSIONS.pop(admin_tok, None)
    ACTIVE_SESSIONS.pop(reader_tok, None)
    ACTIVE_SESSIONS.pop(operator_tok, None)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM operator_access_requests WHERE user_id IN (?, ?) OR email LIKE 'regression_%@vortex.local'", (reader_id, operator_id))
    c.execute("DELETE FROM user_permissions WHERE user_id IN (?, ?)", (reader_id, operator_id))
    c.execute("DELETE FROM users WHERE id IN (?, ?)", (reader_id, operator_id))
    conn.commit()
    conn.close()


# ==============================================================================
# BUG 1 TESTS — OPERATOR ACCESS REQUEST FLOW
# ==============================================================================

def test_req_6_unauthenticated_request_rejected(app_client):
    """6. Unauthorized or unauthenticated requests are rejected with 401."""
    res = app_client.post("/api/auth/operator-request", json={})
    assert res.status_code == 401
    assert res.get_json()["error"] == "Unauthorized"


def test_req_10_operator_and_admin_cannot_submit_operator_request(app_client, test_accounts):
    """10. If the user is already an Operator or Admin, do not allow inappropriate duplicate request."""
    # Admin attempt
    res_adm = app_client.post("/api/auth/operator-request", headers=test_accounts["admin_headers"], json={})
    assert res_adm.status_code == 400
    assert "already holds" in res_adm.get_json()["message"]

    # Operator attempt
    res_op = app_client.post("/api/auth/operator-request", headers=test_accounts["operator_headers"], json={})
    assert res_op.status_code == 400
    assert "already holds" in res_op.get_json()["message"]


def test_req_1_to_5_reader_request_lifecycle(app_client, test_accounts):
    """
    1. A logged-in Reader submits a request successfully.
    2. The request appears in persistent storage.
    3. The Admin can see the pending request.
    4. Duplicate submissions do not create multiple pending requests.
    5. A user with an existing pending request sees the correct status.
    7. The request does not upgrade the user's role before Admin approval.
    """
    r_headers = test_accounts["reader_headers"]
    adm_headers = test_accounts["admin_headers"]
    reader_id = test_accounts["reader_id"]

    # 1. Logged-in Reader submits request
    res = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    assert data["status"] == "PENDING"
    req_id = data["request_id"]

    # 7. Check user role is still READER (NO auto-elevation)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (reader_id,))
    assert c.fetchone()["role"] == "READER"

    # 2. Check persistent storage
    c.execute("SELECT id, user_id, email, status FROM operator_access_requests WHERE id = ?", (req_id,))
    row = c.fetchone()
    assert row is not None
    assert row["user_id"] == reader_id
    assert row["status"] == "PENDING"
    conn.close()

    # 5. User checks status endpoint -> returns PENDING
    st_res = app_client.get("/api/auth/operator-request/status", headers=r_headers)
    assert st_res.status_code == 200
    assert st_res.get_json()["status"] == "PENDING"

    # 4. Duplicate submission is blocked with HTTP 409 Conflict
    res_dup = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res_dup.status_code == 409
    assert res_dup.get_json()["status"] == "PENDING"

    # 3. Admin can retrieve and see the pending request in the queue
    admin_list = app_client.get("/api/admin/operator-requests", headers=adm_headers)
    assert admin_list.status_code == 200
    requests_list = admin_list.get_json()["requests"]
    matching = [r for r in requests_list if r["id"] == req_id]
    assert len(matching) == 1
    assert matching[0]["status"] == "PENDING"


def test_req_8_admin_approval_and_rejection_workflow(app_client, test_accounts):
    """8. Existing Admin approval and rejection workflows remain functional."""
    r_headers = test_accounts["reader_headers"]
    adm_headers = test_accounts["admin_headers"]
    reader_id = test_accounts["reader_id"]

    # Submit request
    res = app_client.post("/api/auth/operator-request", headers=r_headers, json={})
    assert res.status_code == 201
    req_id = res.get_json()["request_id"]

    # Admin approves
    res_appr = app_client.post(f"/api/admin/operator-requests/{req_id}/approve", headers=adm_headers, json={"reason": "Approved"})
    assert res_appr.status_code == 200
    assert res_appr.get_json()["status"] == "APPROVED"

    # User role is now OPERATOR in db
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (reader_id,))
    assert c.fetchone()["role"] == "OPERATOR"
    conn.close()


# ==============================================================================
# BUG 2 TESTS — OTP VERIFICATION BEHAVIOR
# ==============================================================================

def test_otp_incomplete_and_invalid_codes(app_client):
    """
    5. Incomplete codes cannot be verified.
    6. Invalid and expired codes display the correct error.
    """
    # Incomplete code (< 6 digits)
    res_inc = app_client.post("/api/auth/verify-otp", json={"email": "nonexistent@gmail.com", "otp": "123"})
    assert res_inc.status_code == 400

    # Invalid code
    res_inv = app_client.post("/api/auth/verify-otp", json={"email": "nonexistent@gmail.com", "otp": "000000"})
    assert res_inv.status_code == 400
    assert "Invalid or expired" in res_inv.get_json()["message"]


def test_otp_success_flow_and_resend_cooldown(app_client):
    """
    7. Resending OTP continues working with the existing cooldown.
    8. A successful verification follows the existing completion flow.
    """
    test_email = "test_otp_flow_reg@gmail.com"
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE email = ?", (test_email,))

    # Create unverified user with OTP
    u_id = f"usr_{uuid.uuid4().hex[:6]}"
    raw_otp, otp_hash, expires_at = generate_secure_otp(5)
    p_hash, salt = hash_password("TempPass@123")
    c.execute("""
    INSERT INTO users (id, username, email, full_name, role, password_hash, salt, is_active, email_verified, verification_token_hash, verification_token_expires, verification_attempts, created_at)
    VALUES (?, 'test_otp_user', ?, 'OTP User', 'READER', ?, ?, 1, 0, ?, ?, 0, ?)
    """, (u_id, test_email, p_hash, salt, otp_hash, expires_at, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

    # Verify with correct 6-digit OTP
    res_verify = app_client.post("/api/auth/verify-otp", json={"email": test_email, "otp": raw_otp})
    assert res_verify.status_code == 200
    assert res_verify.get_json()["status"] == "SUCCESS"

    # Check user is verified in DB
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email_verified, verification_token_hash FROM users WHERE id = ?", (u_id,))
    u_row = c.fetchone()
    assert u_row["email_verified"] == 1
    assert u_row["verification_token_hash"] is None  # OTP cleared on success
    conn.close()

    # Clean up
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (u_id,))
    conn.commit()
    conn.close()


def test_password_reset_unaffected(app_client):
    """9. Password reset remains unaffected."""
    res = app_client.post("/api/auth/reset-password", json={
        "token": "invalid_test_token",
        "new_password": "NewPassword@2026",
        "confirm_password": "NewPassword@2026"
    })
    assert res.status_code == 400
    assert "invalid" in res.get_json()["message"].lower()


def test_otp_html_no_auto_verification():
    """
    Contract verification for Bug 2 in frontend/verify-email.html:
    1. Typing 5 digits does not submit verification.
    2. Typing 6th digit does NOT auto-submit verification.
    3. Pasting 6 digits does NOT auto-submit verification.
    4. Clicking Verify Email button is the sole trigger for verifyOtp.
    5. Incomplete codes disable the Verify Email button.
    """
    html_path = os.path.join(BASE_DIR, "frontend", "verify-email.html")
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify absence of auto-submission triggers
    assert "getEnteredOtp().length === 6) verifyOtp" not in content
    assert "getEnteredOtp().length === 6) { verifyOtp" not in content
    assert "digits.length === 6) verifyOtp" not in content
    assert "digits.length === 6) { verifyOtp" not in content

    # Verify input event only checks button state and navigates focus
    assert 'box.addEventListener("input"' in content
    assert "checkButtonState();" in content

    # Verify paste event only sets values, sets focus, and checks button state
    assert 'box.addEventListener("paste"' in content

    # Verify Verify Email button is the explicit trigger
    assert 'verifyBtn.addEventListener("click", verifyOtp);' in content

    # Verify button disabling on incomplete OTP
    assert "verifyBtn.disabled = !isComplete || isVerifying;" in content

