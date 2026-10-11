"""
VORTEX-SDN Comprehensive Email Authentication Verification Test Suite
Explicitly verifies:
1. SMTP configuration and validation
2. Registration creates account with email_verified=0
3. Verification email dispatch
4. Verification link activates account (email_verified=1)
5. Verification token expires
6. Verification token cannot be reused (single-use)
7. Unverified login is blocked (403 EMAIL_NOT_VERIFIED)
8. Verified login works
9. Resend verification email
10. Forgot-password privacy response & email dispatch
11. Reset token validation
12. Reset token expiration
13. Reset token cannot be reused (single-use)
14. Authenticated password change from Settings
15. Password-change security notification email dispatched
16. Old password no longer works after change
17. New password works after change
"""

import pytest
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from backend.api.server import create_app
from backend.models.database import init_db, get_db_connection, hash_password
from backend.services.email_service import (
    generate_secure_token,
    verify_email_token,
    verify_password_reset_token,
    reset_password_with_token,
    send_verification_email,
    send_password_reset_email,
    send_password_changed_email,
    get_smtp_config,
    clear_rate_limit,
    is_email_verification_required
)

@pytest.fixture
def client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_01_smtp_config_and_enforcement():
    """Verify SMTP configuration helper and that verification is permanently enforced."""
    cfg = get_smtp_config()
    assert "host" in cfg
    assert "port" in cfg
    assert "use_tls" in cfg
    assert "verif_expiry" in cfg
    assert "reset_expiry" in cfg
    assert is_email_verification_required() is True

def test_02_registration_unverified_and_email_dispatched(client):
    """Verify registration creates unverified account (email_verified=0) and sends email."""
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = ?", ("sec_test_user@vortex.net",))
    conn.commit()
    conn.close()

    mock_send = MagicMock(return_value=(True, "Sent"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        res = client.post("/api/auth/register", json={
            "full_name": "Security Test User",
            "email": "sec_test_user@vortex.net",
            "password": "InitialPassword@2026",
            "confirm_password": "InitialPassword@2026",
            "role": "OPERATOR"
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["email_verified"] is False
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "sec_test_user@vortex.net"
        assert args[1] == "Security Test User"
        raw_token = args[2]
        assert len(raw_token) == 6 and raw_token.isdigit()

    # Verify database state
    conn = get_db_connection()
    row = conn.execute("SELECT email_verified, verification_token_hash FROM users WHERE email = ?", ("sec_test_user@vortex.net",)).fetchone()
    conn.close()
    assert row["email_verified"] == 0
    # Raw token must NOT be stored in database!
    assert row["verification_token_hash"] != raw_token
    # Only hash of raw token is stored
    expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert row["verification_token_hash"] == expected_hash

def test_03_unverified_login_blocked(client):
    """Verify unverified login is blocked with HTTP 403 and EMAIL_NOT_VERIFIED code."""
    res = client.post("/api/auth/login", json={
        "email": "sec_test_user@vortex.net",
        "password": "InitialPassword@2026"
    })
    assert res.status_code == 403
    data = res.get_json()
    assert data["code"] == "EMAIL_NOT_VERIFIED"
    assert ("verify your gmail" in data["message"].lower() or "verify your email" in data["message"].lower())

def test_04_resend_verification_email(client):
    """Verify resend verification endpoint generates fresh token and sends email."""
    clear_rate_limit()
    mock_send = MagicMock(return_value=(True, "Resent"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        res = client.post("/api/auth/resend-verification", json={
            "email": "sec_test_user@vortex.net"
        })
        assert res.status_code == 200
        assert res.get_json()["success"] is True
        mock_send.assert_called_once()

    # Privacy preservation for unknown email
    res_unknown = client.post("/api/auth/resend-verification", json={"email": "nonexistent_999@vortex.net"})
    assert res_unknown.status_code == 200
    assert "verification link has been sent" in res_unknown.get_json()["message"]

def test_05_verification_link_activates_account(client):
    """Verify clicking the verification link marks email_verified=1 and clears token."""
    raw_token, token_hash, expires_at = generate_secure_token()
    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ? WHERE email = ?", (token_hash, expires_at, "sec_test_user@vortex.net"))
    conn.commit()
    conn.close()

    res = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Database check: email_verified=1 and token hash is NULL
    conn = get_db_connection()
    row = conn.execute("SELECT email_verified, verification_token_hash FROM users WHERE email = ?", ("sec_test_user@vortex.net",)).fetchone()
    conn.close()
    assert row["email_verified"] == 1
    assert row["verification_token_hash"] is None

def test_06_verification_token_single_use_enforced(client):
    """Verify that a used verification token cannot be used a second time."""
    raw_token, token_hash, expires_at = generate_secure_token()
    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ? WHERE email = ?", (token_hash, expires_at, "sec_test_user@vortex.net"))
    conn.commit()
    conn.close()

    # First attempt: succeeds
    res1 = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert res1.status_code == 200

    # Second attempt: fails
    res2 = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert res2.status_code == 400
    assert "invalid or has already been used" in res2.get_json()["message"]

def test_07_verification_token_expiration(client):
    """Verify that an expired verification token is rejected."""
    raw_token, token_hash, _ = generate_secure_token()
    expired_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    conn = get_db_connection()
    conn.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ? WHERE email = ?", (token_hash, expired_at, "sec_test_user@vortex.net"))
    conn.commit()
    conn.close()

    res = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert res.status_code == 400
    assert "expired" in res.get_json()["message"]

def test_08_verified_login_success(client):
    """Verify that after verification, login succeeds and returns valid session token."""
    res = client.post("/api/auth/login", json={
        "email": "sec_test_user@vortex.net",
        "password": "InitialPassword@2026"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["email"] == "sec_test_user@vortex.net"

def test_09_forgot_password_and_reset_token_dispatch(client):
    """Verify forgot-password flow: privacy safe response and reset email dispatch."""
    mock_send = MagicMock(return_value=(True, "Reset sent"))
    with patch("backend.api.auth.send_password_reset_email", mock_send):
        res = client.post("/api/auth/forgot-password", json={
            "email": "sec_test_user@vortex.net"
        })
        assert res.status_code == 200
        assert "password-reset link has been sent" in res.get_json()["message"]
        mock_send.assert_called_once()
        raw_token = mock_send.call_args[0][2]

    # Verify reset token is valid via GET /api/auth/verify-reset-token
    val_res = client.get(f"/api/auth/verify-reset-token?token={raw_token}")
    assert val_res.status_code == 200
    assert val_res.get_json()["success"] is True

    # Unknown email returns identical privacy-safe message
    unk_res = client.post("/api/auth/forgot-password", json={"email": "nobody_here_999@vortex.net"})
    assert unk_res.status_code == 200
    assert "password-reset link has been sent" in unk_res.get_json()["message"]

def test_10_reset_token_expiration(client):
    """Verify expired reset token is rejected."""
    raw_token, token_hash, _ = generate_secure_token()
    expired_at = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    conn = get_db_connection()
    conn.execute("UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE email = ?", (token_hash, expired_at, "sec_test_user@vortex.net"))
    conn.commit()
    conn.close()

    res = client.get(f"/api/auth/verify-reset-token?token={raw_token}")
    assert res.status_code == 400
    assert "expired" in res.get_json()["message"]

def test_11_reset_password_single_use_and_security_email(client):
    """Verify password reset via token: password changes, security email sent, token invalidated."""
    raw_token, token_hash, expires_at = generate_secure_token()
    conn = get_db_connection()
    conn.execute("UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE email = ?", (token_hash, expires_at, "sec_test_user@vortex.net"))
    conn.commit()
    conn.close()

    mock_security_email = MagicMock(return_value=(True, "Security notice sent"))
    with patch("backend.services.email_service.send_password_changed_email", mock_security_email):
        res = client.post("/api/auth/reset-password", json={
            "token": raw_token,
            "new_password": "NewSecretPassword@2026",
            "confirm_password": "NewSecretPassword@2026"
        })
        assert res.status_code == 200
        assert res.get_json()["success"] is True
        mock_security_email.assert_called_once()
        assert mock_security_email.call_args[0][0] == "sec_test_user@vortex.net"

    # Reset token cannot be reused
    reuse_res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "ThirdPassword@2026",
        "confirm_password": "ThirdPassword@2026"
    })
    assert reuse_res.status_code == 400
    assert "invalid or has already been used" in reuse_res.get_json()["message"]

    # Old password fails
    assert client.post("/api/auth/login", json={"email": "sec_test_user@vortex.net", "password": "InitialPassword@2026"}).status_code == 401

    # New password works
    login_new = client.post("/api/auth/login", json={"email": "sec_test_user@vortex.net", "password": "NewSecretPassword@2026"})
    assert login_new.status_code == 200

def test_12_change_password_from_settings(client):
    """Verify authenticated password change from Settings with security notification."""
    # 1. Unauthenticated attempt fails (401)
    unauth_res = client.post("/api/auth/change-password", json={
        "current_password": "NewSecretPassword@2026",
        "new_password": "SettingsChangedPass@2026",
        "confirm_password": "SettingsChangedPass@2026"
    })
    assert unauth_res.status_code == 401

    # 2. Login to get token
    login_res = client.post("/api/auth/login", json={"email": "sec_test_user@vortex.net", "password": "NewSecretPassword@2026"})
    assert login_res.status_code == 200
    session_token = login_res.get_json()["token"]
    headers = {"Authorization": f"Bearer {session_token}"}

    # 3. Wrong current password fails (400)
    bad_current = client.post("/api/auth/change-password", headers=headers, json={
        "current_password": "IncorrectPassword123",
        "new_password": "SettingsChangedPass@2026",
        "confirm_password": "SettingsChangedPass@2026"
    })
    assert bad_current.status_code == 400
    assert "incorrect current password" in bad_current.get_json()["message"].lower()

    # 4. Correct current password succeeds and sends security notification email
    mock_sec_email = MagicMock(return_value=(True, "Notice sent"))
    with patch("backend.api.auth.send_password_changed_email", mock_sec_email):
        good_change = client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "NewSecretPassword@2026",
            "new_password": "SettingsChangedPass@2026",
            "confirm_password": "SettingsChangedPass@2026"
        })
        assert good_change.status_code == 200
        assert good_change.get_json()["success"] is True
        mock_sec_email.assert_called_once()
        assert mock_sec_email.call_args[0][0] == "sec_test_user@vortex.net"

    # 5. Old password no longer works
    assert client.post("/api/auth/login", json={"email": "sec_test_user@vortex.net", "password": "NewSecretPassword@2026"}).status_code == 401

    # 6. New password works
    assert client.post("/api/auth/login", json={"email": "sec_test_user@vortex.net", "password": "SettingsChangedPass@2026"}).status_code == 200

def test_13_resend_verification_rate_limiting(client):
    """Verify resend endpoint enforces rate limits and returns retry_after_seconds."""
    clear_rate_limit()
    mock_send = MagicMock(return_value=(True, "Resent"))

    # Make user unverified again for resend testing
    conn = get_db_connection()
    conn.execute("UPDATE users SET email_verified = 0 WHERE email = ?", ("sec_test_user@vortex.net",))
    conn.commit()
    conn.close()

    with patch("backend.api.auth.send_verification_email", mock_send):
        # 1st request: succeeds
        res1 = client.post("/api/auth/resend-verification", json={"email": "sec_test_user@vortex.net"})
        assert res1.status_code == 200
        assert res1.get_json()["success"] is True

        # 2nd immediate request: rate limited (HTTP 429)
        res2 = client.post("/api/auth/resend-verification", json={"email": "sec_test_user@vortex.net"})
        assert res2.status_code == 429
        data2 = res2.get_json()
        assert data2["success"] is False
        assert data2["rate_limited"] is True
        assert "retry_after_seconds" in data2
        assert data2["retry_after_seconds"] > 0
        assert "Too many requests. Please try again in" in data2["message"]
        # Ensure mock_send was NOT called a second time
        assert mock_send.call_count == 1

    # Dev reset allows resend again
    res_clear = client.post("/api/auth/reset-rate-limit", json={"email": "sec_test_user@vortex.net"})
    assert res_clear.status_code == 200

    with patch("backend.api.auth.send_verification_email", mock_send):
        res3 = client.post("/api/auth/resend-verification", json={"email": "sec_test_user@vortex.net"})
        assert res3.status_code == 200
        assert mock_send.call_count == 2

def test_14_forgot_password_rate_limiting(client):
    """Verify forgot-password endpoint enforces rate limits and returns retry_after_seconds."""
    clear_rate_limit()
    mock_send = MagicMock(return_value=(True, "Reset email sent"))

    with patch("backend.api.auth.send_password_reset_email", mock_send):
        # 1st request: succeeds
        res1 = client.post("/api/auth/forgot-password", json={"email": "sec_test_user@vortex.net"})
        assert res1.status_code == 200

        # 2nd request: rate limited
        res2 = client.post("/api/auth/forgot-password", json={"email": "sec_test_user@vortex.net"})
        assert res2.status_code == 429
        data2 = res2.get_json()
        assert data2["success"] is False
        assert data2["rate_limited"] is True
        assert "retry_after_seconds" in data2
        assert data2["retry_after_seconds"] > 0
        assert mock_send.call_count == 1

def test_15_smtp_failure_does_not_rate_limit_retry(client):
    """Verify that a failed SMTP delivery attempt does NOT lock the user out with rate limits."""
    clear_rate_limit()
    mock_fail = MagicMock(return_value=(False, "Connection timeout to mail server"))

    conn = get_db_connection()
    conn.execute("UPDATE users SET email_verified = 0 WHERE email = ?", ("sec_test_user@vortex.net",))
    conn.commit()
    conn.close()

    with patch("backend.api.auth.send_verification_email", mock_fail):
        # 1st attempt fails due to SMTP error
        res1 = client.post("/api/auth/resend-verification", json={"email": "sec_test_user@vortex.net"})
        assert res1.status_code == 502
        assert "Unable to send verification email" in res1.get_json()["message"]

        # 2nd attempt immediately after MUST NOT be rate-limited!
        res2 = client.post("/api/auth/resend-verification", json={"email": "sec_test_user@vortex.net"})
        assert res2.status_code == 502
        assert res2.status_code != 429
        assert mock_fail.call_count == 2


