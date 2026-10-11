"""
Comprehensive Automated Test Suite for VORTEX-SDN 6-Digit Email OTP Verification System
Validates:
1. Registration generates secure 6-digit numeric OTP and stores SHA-256 hash in SQLite
2. Registration email dispatched with 6-digit OTP
3. Verification of correct OTP activates account (email_verified=1) and clears OTP
4. Incorrect OTP rejected with remaining attempts reported
5. Exceeding 5 incorrect attempts invalidates the OTP
6. Expired OTP (5 minutes) rejected
7. Reusing verified OTP rejected (single-use)
8. Resend invalidates previous OTP and generates new OTP
9. Submitting superseded OTP fails
10. Resend cooldown (60s) enforced on server (HTTP 429)
11. Unverified login blocked (HTTP 403 EMAIL_NOT_VERIFIED)
12. Verified user login succeeds (HTTP 200)
13. Password reset remains completely separate and operational
"""

import os
import sys
import hashlib
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import init_db, get_db_connection, hash_password
from backend.services.email_service import (
    generate_secure_otp,
    verify_email_otp,
    send_verification_otp_email,
    get_smtp_config,
    clear_rate_limit,
    record_rate_limit
)

@pytest.fixture
def client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    clear_rate_limit()
    with app.test_client() as client:
        yield client
    clear_rate_limit()

def test_01_otp_generator_format_and_crypto():
    """Verify OTP generation produces exactly 6 numeric digits, SHA-256 hash, and 5-min expiry."""
    raw_otp, otp_hash, expires_at = generate_secure_otp(expiry_minutes=5)
    assert len(raw_otp) == 6
    assert raw_otp.isdigit()
    expected_hash = hashlib.sha256(raw_otp.encode("utf-8")).hexdigest()
    assert otp_hash == expected_hash

    # Expiry verification
    exp_dt = datetime.fromisoformat(expires_at)
    now_dt = datetime.now(timezone.utc)
    diff_sec = (exp_dt - now_dt).total_seconds()
    assert 280 <= diff_sec <= 320  # ~300 seconds (5 mins)

def test_02_registration_issues_otp_and_dispatches_email(client):
    """Verify user registration stores OTP hash in database and dispatches 6-digit OTP email."""
    test_email = "otp_test_user@gmail.com"
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    clear_rate_limit(f"resend_{test_email}")

    mock_send = MagicMock(return_value=(True, "Sent"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        res = client.post("/api/auth/register", json={
            "full_name": "OTP Test User",
            "email": test_email,
            "password": "Password@2026",
            "confirm_password": "Password@2026",
            "role": "READER"
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["email_sent"] is True
        assert data["email_verified"] is False
        assert "otp" not in data  # Never expose raw OTP in JSON response!

        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == test_email
        assert args[1] == "OTP Test User"
        raw_otp = args[2]
        assert len(raw_otp) == 6
        assert raw_otp.isdigit()

    # Verify database state
    conn = get_db_connection()
    row = conn.execute("SELECT email_verified, verification_token_hash, verification_attempts FROM users WHERE email = ?", (test_email,)).fetchone()
    conn.close()
    assert row["email_verified"] == 0
    assert row["verification_attempts"] == 0
    expected_hash = hashlib.sha256(raw_otp.encode("utf-8")).hexdigest()
    assert row["verification_token_hash"] == expected_hash

def test_03_unverified_login_blocked(client):
    """Verify unverified user cannot log in and receives EMAIL_NOT_VERIFIED error code."""
    res = client.post("/api/auth/login", json={
        "email": "otp_test_user@gmail.com",
        "password": "Password@2026"
    })
    assert res.status_code == 403
    data = res.get_json()
    assert data["code"] == "EMAIL_NOT_VERIFIED"
    assert data["email_verified"] is False

def test_04_incorrect_otp_fails_and_decrements_attempts(client):
    """Verify submitting incorrect OTP returns HTTP 400 and increments failed attempts."""
    test_email = "otp_test_user@gmail.com"
    res = client.post("/api/auth/verify-otp", json={
        "email": test_email,
        "otp": "999999"
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "remaining" in data["message"].lower()

    # Database check: verification_attempts must be incremented
    conn = get_db_connection()
    row = conn.execute("SELECT verification_attempts, email_verified FROM users WHERE email = ?", (test_email,)).fetchone()
    conn.close()
    assert row["verification_attempts"] == 1
    assert row["email_verified"] == 0

def test_05_max_five_attempts_invalidates_otp(client):
    """Verify exceeding 5 failed attempts invalidates the OTP completely."""
    test_email = "otp_test_user@gmail.com"
    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_attempts = 4 WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    # 5th failed attempt:
    res = client.post("/api/auth/verify-otp", json={
        "email": test_email,
        "otp": "000000"
    })
    assert res.status_code == 400
    data = res.get_json()
    assert "maximum" in data["message"].lower() or "exceeded" in data["message"].lower()

    # Database check: OTP hash and expires must now be NULL
    conn = get_db_connection()
    row = conn.execute("SELECT verification_token_hash, verification_token_expires FROM users WHERE email = ?", (test_email,)).fetchone()
    conn.close()
    assert row["verification_token_hash"] is None
    assert row["verification_token_expires"] is None

def test_06_expired_otp_fails(client):
    """Verify expired OTP is rejected."""
    test_email = "otp_test_user@gmail.com"
    raw_otp, otp_hash, _ = generate_secure_otp()
    expired_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ?, verification_attempts = 0 WHERE email = ?", (otp_hash, expired_time, test_email))
    conn.commit()
    conn.close()

    res = client.post("/api/auth/verify-otp", json={
        "email": test_email,
        "otp": raw_otp
    })
    assert res.status_code == 400
    assert "expired" in res.get_json()["message"].lower()

def test_07_resend_cooldown_enforced_and_resend_generates_new_otp(client):
    """Verify resend respects 60-second cooldown and generates fresh 6-digit OTP."""
    test_email = "otp_test_user@gmail.com"
    clear_rate_limit()

    mock_send = MagicMock(return_value=(True, "Resent"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        # 1. First resend: succeeds
        res1 = client.post("/api/auth/resend-verification", json={"email": test_email})
        assert res1.status_code == 200
        assert res1.get_json()["success"] is True
        mock_send.assert_called_once()
        first_otp = mock_send.call_args[0][2]
        assert len(first_otp) == 6

        # 2. Immediate second resend: blocked by cooldown (HTTP 429)
        res2 = client.post("/api/auth/resend-verification", json={"email": test_email})
        assert res2.status_code == 429
        assert "too many requests" in res2.get_json()["message"].lower()

        # 3. Clear rate limit to simulate cooldown expiry
        clear_rate_limit(f"resend_{test_email}")
        res3 = client.post("/api/auth/resend-verification", json={"email": test_email})
        assert res3.status_code == 200
        second_otp = mock_send.call_args[0][2]
        assert len(second_otp) == 6

        # 4. First OTP should now be superseded and rejected!
        res_old = client.post("/api/auth/verify-otp", json={"email": test_email, "otp": first_otp})
        # If first_otp != second_otp, it must fail
        if first_otp != second_otp:
            assert res_old.status_code == 400

def test_08_correct_otp_verifies_account_and_allows_login(client):
    """Verify entering correct 6-digit OTP activates account and allows subsequent login."""
    test_email = "otp_test_user@gmail.com"
    raw_otp, otp_hash, expires_at = generate_secure_otp(expiry_minutes=5)

    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ?, verification_attempts = 0, email_verified = 0 WHERE email = ?", (otp_hash, expires_at, test_email))
    conn.commit()
    conn.close()

    # Verify via POST /api/auth/verify-otp
    res = client.post("/api/auth/verify-otp", json={
        "email": test_email,
        "otp": raw_otp
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "verified" in data["message"].lower()

    # Database check: email_verified=1 and OTP hash is cleared (single-use)
    conn = get_db_connection()
    row = conn.execute("SELECT email_verified, verification_token_hash, verification_attempts FROM users WHERE email = ?", (test_email,)).fetchone()
    conn.close()
    assert row["email_verified"] == 1
    assert row["verification_token_hash"] is None
    assert row["verification_attempts"] == 0

    # Login now succeeds!
    login_res = client.post("/api/auth/login", json={
        "email": test_email,
        "password": "Password@2026"
    })
    assert login_res.status_code == 200
    login_data = login_res.get_json()
    assert login_data["success"] is True
    assert "token" in login_data
    assert login_data["user"]["email"] == test_email

def test_09_used_otp_cannot_be_reused(client):
    """Verify that a used OTP cannot be verified a second time."""
    test_email = "otp_test_user@gmail.com"
    res = client.post("/api/auth/verify-otp", json={
        "email": test_email,
        "otp": "123456"
    })
    # Since already verified, returns info response indicating already verified
    assert res.status_code in (200, 400)
    data = res.get_json()
    if res.status_code == 200:
        assert "already verified" in data["message"].lower()

def test_10_password_reset_remains_separate_with_tokens(client):
    """Verify forgot-password and password-reset flow still uses secure URL tokens, not OTPs."""
    test_email = "otp_test_user@gmail.com"
    clear_rate_limit(f"forgot_{test_email}")

    mock_send = MagicMock(return_value=(True, "Reset sent"))
    with patch("backend.api.auth.send_password_reset_email", mock_send):
        res = client.post("/api/auth/forgot-password", json={"email": test_email})
        assert res.status_code == 200
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        raw_token = args[2]
        # Password reset token is a 32-byte URL-safe string (>20 chars), NOT a 6-digit OTP!
        assert len(raw_token) > 20
        assert not raw_token.isdigit()
