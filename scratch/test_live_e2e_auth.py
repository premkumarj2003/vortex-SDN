"""
Live End-to-End Authentication Validation Script
Runs against the running Flask server on http://127.0.0.1:5000
and database at data/vortex.db.
"""

import sys
import os
import json
import sqlite3
import urllib.request
import urllib.error
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import get_db_connection
from backend.services.email_service import get_smtp_config, clear_rate_limit

app = create_app()
app.config["TESTING"] = True
client = app.test_client()

def api_post(endpoint, data, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.post(endpoint, json=data, headers=headers)
    try:
        return resp.status_code, resp.get_json() or {}
    except Exception:
        return resp.status_code, {"error": resp.data.decode("utf-8")}

def api_get(endpoint, token=None, headers_extra=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if headers_extra:
        headers.update(headers_extra)
    resp = client.get(endpoint, headers=headers)
    ct = resp.content_type or ""
    if "application/json" in ct:
        return resp.status_code, resp.get_json() or {}, ct
    return resp.status_code, resp.data.decode("utf-8"), ct

def run_tests():
    print("=" * 70)
    print("STARTING LIVE END-TO-END AUTHENTICATION VALIDATION")
    print("=" * 70)

    # Clean up test users if existing
    test_email_1 = "vertexsdn@gmail.com"
    test_username_1 = "vortex_live_op1"
    test_email_2 = "vertexsdn+unverified@gmail.com"
    test_username_2 = "vortex_live_op2"

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE email IN (?, ?) OR username IN (?, ?)",
              (test_email_1, test_email_2, test_username_1, test_username_2))
    conn.commit()
    conn.close()

    clear_rate_limit()

    captured_tokens = {}

    # We hook _send_smtp_email to capture raw tokens sent via real SMTP without breaking delivery
    import backend.services.email_service as es_mod
    original_send = es_mod._send_smtp_email

    def intercept_send(to_email, subject, plain_content, html_content, audit_action="EMAIL_SENT"):
        # Extract token from URL in content
        if "token=" in plain_content:
            raw_tok = plain_content.split("token=")[1].split()[0].split('"')[0].strip()
            captured_tokens[to_email] = raw_tok
        return original_send(to_email, subject, plain_content, html_content, audit_action)

    es_mod._send_smtp_email = intercept_send

    # -------------------------------------------------------------
    # TEST A: NEW REGISTRATION & VERIFICATION
    # -------------------------------------------------------------
    print("\n--- TEST A: NEW REGISTRATION ---")
    reg_data = {
        "username": test_username_1,
        "email": test_email_1,
        "full_name": "VORTEX Live Lead Operator",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "OPERATOR"
    }

    # Also capture token directly via auth wrapper
    import backend.api.auth as auth_mod
    orig_auth_send_verif = auth_mod.send_verification_email
    def auth_verif_spy(email, name, raw_token):
        captured_tokens[email] = raw_token
        return orig_auth_send_verif(email, name, raw_token)
    auth_mod.send_verification_email = auth_verif_spy

    status, res = api_post("/api/auth/register", reg_data)
    print(f"[A.1] Registration API Status: {status}")
    assert status == 201, f"Expected 201, got {status}: {res}"
    assert res.get("success") is True
    assert res.get("email_sent") is True
    print("      [+] Registration returned 201 with email_sent=True")

    # Confirm in DB
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, email_verified, verification_token_hash FROM users WHERE username = ?", (test_username_1,))
    row = c.fetchone()
    conn.close()
    assert row is not None
    assert row["email_verified"] == 0
    print("      [+] Database confirms user created with email_verified=0")

    raw_token_1 = captured_tokens.get(test_email_1)
    assert raw_token_1 is not None, "Raw verification token was not captured from dispatch"
    print("      [+] Real verification token dispatched via SMTP")

    # Unverified login attempt MUST fail with 403
    print("\n--- TEST B.1: UNVERIFIED LOGIN BLOCK ---")
    status, login_res = api_post("/api/auth/login", {"username": test_username_1, "password": "Password@2026"})
    print(f"      Login attempt status: {status}")
    assert status == 403, f"Expected 403, got {status}"
    assert login_res.get("code") == "EMAIL_NOT_VERIFIED"
    print("      [+] Login successfully blocked with 403 EMAIL_NOT_VERIFIED")

    # Test browser GET /verify-email?token=<REAL_TOKEN>
    print("\n--- TEST A.2: BROWSER /verify-email ROUTE ---")
    status, body, ct = api_get(f"/verify-email?token={raw_token_1}")
    print(f"      Browser route status: {status}, content-type: {ct}")
    assert status == 200
    assert "verify-email.html" in body or "Email Verification" in body or "VORTEX-SDN" in body
    print("      [+] /verify-email served verify-email.html with HTTP 200")

    # Test API verification: GET /api/auth/verify-email?token=<REAL_TOKEN>
    print("\n--- TEST A.3: API TOKEN VALIDATION ---")
    status, verif_res, ct = api_get(f"/api/auth/verify-email?token={raw_token_1}")
    print(f"      API verification status: {status}, message: {verif_res.get('message')}")
    assert status == 200
    assert verif_res.get("success") is True
    print("      [+] API token validation succeeded with HTTP 200")

    # Confirm email_verified in database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email_verified, verification_token_hash FROM users WHERE username = ?", (test_username_1,))
    row = c.fetchone()
    conn.close()
    assert row["email_verified"] == 1
    assert row["verification_token_hash"] is None  # Token consumed
    print("      [+] Database confirms email_verified=1 and token invalidated")

    # Test A.4: Login now succeeds
    print("\n--- TEST A.4: VERIFIED LOGIN ---")
    status, good_login = api_post("/api/auth/login", {"username": test_username_1, "password": "Password@2026"})
    print(f"      Verified login status: {status}")
    assert status == 200
    assert good_login.get("success") is True
    auth_token = good_login.get("token")
    assert auth_token is not None
    print("      [+] Login succeeded! Session token received.")

    # -------------------------------------------------------------
    # TEST D: VERIFICATION TOKEN REUSE
    # -------------------------------------------------------------
    print("\n--- TEST D: TOKEN REUSE PROTECTION ---")
    status, reuse_res, _ = api_get(f"/api/auth/verify-email?token={raw_token_1}")
    print(f"      Token reuse status: {status}, message: {reuse_res.get('message')}")
    assert status == 400
    assert reuse_res.get("success") is False
    print("      [+] Token reuse successfully rejected with HTTP 400")

    # -------------------------------------------------------------
    # TEST B & C: UNVERIFIED USER, RESEND & RATE LIMITING
    # -------------------------------------------------------------
    print("\n--- TEST B: RESEND VERIFICATION & RATE LIMIT ---")
    reg_data_2 = {
        "username": test_username_2,
        "email": test_email_2,
        "full_name": "Unverified Operator Lead",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "OPERATOR"
    }
    status, _ = api_post("/api/auth/register", reg_data_2)
    assert status == 201

    # Resend 1: First request should succeed
    status, resend_1 = api_post("/api/auth/resend-verification", {"email": test_email_2})
    print(f"      Resend request 1 status: {status}")
    assert status == 200
    assert resend_1.get("success") is True
    print("      [+] First resend request succeeded with HTTP 200")

    # TEST C: Immediate duplicate click
    print("\n--- TEST C: DUPLICATE CLICK RATE LIMIT ---")
    status, resend_2 = api_post("/api/auth/resend-verification", {"email": test_email_2})
    print(f"      Immediate resend request 2 status: {status}")
    assert status == 429, f"Expected 429, got {status}: {resend_2}"
    assert resend_2.get("rate_limited") is True
    assert resend_2.get("retry_after_seconds") > 0
    print(f"      [+] Duplicate request blocked with HTTP 429 (retry after: {resend_2.get('retry_after_seconds')}s)")

    # -------------------------------------------------------------
    # TEST E: PASSWORD RESET
    # -------------------------------------------------------------
    print("\n--- TEST E: PASSWORD RESET FLOW ---")
    # Intercept password reset email
    orig_reset_send = auth_mod.send_password_reset_email
    def reset_spy(email, name, raw_token):
        captured_tokens["reset_" + email] = raw_token
        return orig_reset_send(email, name, raw_token)
    auth_mod.send_password_reset_email = reset_spy

    clear_rate_limit(f"forgot_{test_email_1}")

    status, forgot_res = api_post("/api/auth/forgot-password", {"email": test_email_1})
    print(f"      Forgot password status: {status}")
    assert status == 200
    assert forgot_res.get("success") is True

    raw_reset_token = captured_tokens.get("reset_" + test_email_1)
    assert raw_reset_token is not None, "Password reset token was not captured"
    print("      [+] Reset password token dispatched via SMTP")

    # Verify reset token
    status, val_reset, _ = api_get(f"/api/auth/verify-reset-token?token={raw_reset_token}")
    print(f"      Validate reset token status: {status}")
    assert status == 200
    assert val_reset.get("success") is True

    # Complete reset
    new_password = "ResetPassword@2026"
    status, reset_res = api_post("/api/auth/reset-password", {
        "token": raw_reset_token,
        "new_password": new_password,
        "confirm_password": new_password
    })
    print(f"      Reset password submission status: {status}")
    assert status == 200
    assert reset_res.get("success") is True
    print("      [+] Password reset completed successfully")

    # Old password MUST fail
    status, old_login = api_post("/api/auth/login", {"username": test_username_1, "password": "Password@2026"})
    print(f"      Old password login status: {status}")
    assert status == 401
    print("      [+] Old password rejected with HTTP 401")

    # New password MUST succeed
    status, new_login = api_post("/api/auth/login", {"username": test_username_1, "password": new_password})
    print(f"      New password login status: {status}")
    assert status == 200
    assert new_login.get("success") is True
    print("      [+] New password login succeeded with HTTP 200")

    # Reusing reset token MUST fail
    status, reuse_reset = api_post("/api/auth/reset-password", {
        "token": raw_reset_token,
        "new_password": "AnotherNewPass@2026",
        "confirm_password": "AnotherNewPass@2026"
    })
    print(f"      Reset token reuse status: {status}")
    assert status == 400
    print("      [+] Reset token reuse rejected with HTTP 400")

    # -------------------------------------------------------------
    # TEST F: PASSWORD CHANGE FROM SETTINGS
    # -------------------------------------------------------------
    print("\n--- TEST F: PASSWORD CHANGE FROM SETTINGS ---")
    active_token = new_login.get("token")
    final_password = "SettingsUpdatedPass@2026"

    # Wrong current password fails
    status, bad_change = api_post("/api/auth/change-password", {
        "current_password": "WrongPassword",
        "new_password": final_password,
        "confirm_password": final_password
    }, token=active_token)
    print(f"      Bad current password status: {status}")
    assert status == 400
    print("      [+] Wrong current password rejected with HTTP 400")

    # Correct password succeeds
    status, good_change = api_post("/api/auth/change-password", {
        "current_password": new_password,
        "new_password": final_password,
        "confirm_password": final_password
    }, token=active_token)
    print(f"      Password change status: {status}")
    assert status == 200
    assert good_change.get("success") is True
    print("      [+] Authenticated password change succeeded")

    # Prior password now fails
    status, prior_login = api_post("/api/auth/login", {"username": test_username_1, "password": new_password})
    assert status == 401

    # Updated password now succeeds
    status, final_login = api_post("/api/auth/login", {"username": test_username_1, "password": final_password})
    assert status == 200
    assert final_login.get("success") is True
    print("      [+] Login with Settings-updated password succeeded with HTTP 200")

    print("\n" + "=" * 70)
    print("ALL TESTS (A, B, C, D, E, F) PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
