"""
Unit and integration tests for VORTEX-SDN registration validation,
Gmail email validation, and strong password security policy enforcement.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from backend.api.server import create_app
from backend.models.database import (
    get_db_connection,
    validate_password_strength,
    init_db
)
from backend.api.auth import validate_gmail_address, ACTIVE_SESSIONS


@pytest.fixture
def app():
    init_db()
    test_app = create_app()
    test_app.config["TESTING"] = True
    return test_app


@pytest.fixture
def client(app):
    return app.test_client()


# ==============================================================================
# 1. GMAIL ADDRESS VALIDATION UNIT TESTS
# ==============================================================================

def test_validate_gmail_valid_addresses():
    valid_examples = [
        ("test@gmail.com", "test@gmail.com"),
        ("premkumarj@gmail.com", "premkumarj@gmail.com"),
        ("  PremkumarJ@Gmail.Com  ", "premkumarj@gmail.com"),
        ("vortex.sdn.operator@gmail.com", "vortex.sdn.operator@gmail.com"),
        ("operator+vortex@gmail.com", "operator+vortex@gmail.com"),
    ]
    for raw, expected_norm in valid_examples:
        ok, msg, norm = validate_gmail_address(raw)
        assert ok is True, f"Failed for {raw}: {msg}"
        assert norm == expected_norm


def test_validate_gmail_invalid_addresses():
    invalid_examples = [
        "test",
        "test@",
        "test@gmail",
        "test@yahoo.com",
        "test@outlook.com",
        "test@gmail.co",
        "test @gmail.com",
        "",
        "   ",
        None,
        "@gmail.com",
        "invalid..dots@gmail.com"
    ]
    for raw in invalid_examples:
        ok, msg, _ = validate_gmail_address(raw)
        assert ok is False, f"Expected failure for {raw}"
        assert "valid gmail address" in msg.lower()


# ==============================================================================
# 2. PASSWORD STRENGTH VALIDATION UNIT TESTS
# ==============================================================================

def test_validate_password_strength_valid():
    valid_passwords = [
        "Prem@2003",
        "Vortex#123",
        "Secure@Pass9",
        "Vortex#2026",
    ]
    for pwd in valid_passwords:
        ok, msg = validate_password_strength(pwd)
        assert ok is True, f"Expected valid for {pwd}, got {msg}"


def test_validate_password_strength_invalid():
    invalid_passwords = [
        "premkumar",     # missing uppercase, number, special
        "premkumar123",  # missing uppercase, special
        "Premkumar",     # missing number, special
        "12345678",      # missing uppercase, lowercase, special
        "password",      # missing uppercase, number, special
        "PASSWORD123",   # missing lowercase, special
        "Password123",   # missing special character
        "password@",     # missing uppercase, number
        "Password@",     # missing number
        "PASSWORD@123",  # missing lowercase letter
        "",              # empty
        "Ab1!",          # too short (< 8 chars)
    ]
    for pwd in invalid_passwords:
        ok, msg = validate_password_strength(pwd)
        assert ok is False, f"Expected invalid for {pwd}"
        assert len(msg) > 0


# ==============================================================================
# 3. REGISTRATION API ENDPOINT INTEGRATION TESTS
# ==============================================================================

def test_registration_rejects_non_gmail(client):
    """Registration endpoint must return HTTP 400 when email is not @gmail.com."""
    bad_emails = [
        "test",
        "test@",
        "test@gmail",
        "test@yahoo.com",
        "test@outlook.com",
        "test@gmail.co",
        "test @gmail.com"
    ]
    for email in bad_emails:
        res = client.post("/api/auth/register", json={
            "full_name": "Test User",
            "email": email,
            "password": "Prem@2003",
            "confirm_password": "Prem@2003",
            "role": "READER"
        })
        assert res.status_code == 400, f"Expected 400 for {email}, got {res.status_code}"
        data = res.get_json()
        assert data["success"] is False
        assert data["error"] == "Invalid Email"
        assert "Please enter a valid Gmail address." in data["message"]


def test_registration_rejects_weak_passwords(client):
    """Registration endpoint must independently reject weak passwords with HTTP 400."""
    weak_passwords = [
        "premkumar",
        "premkumar123",
        "Premkumar",
        "12345678",
        "password",
        "PASSWORD123",
        "Password123",
        "password@",
        "Password@",
        "PASSWORD@123"
    ]
    for pwd in weak_passwords:
        res = client.post("/api/auth/register", json={
            "full_name": "Test User",
            "email": "testvalidreg@gmail.com",
            "password": pwd,
            "confirm_password": pwd,
            "role": "READER"
        })
        assert res.status_code == 400, f"Expected 400 for {pwd}, got {res.status_code}"
        data = res.get_json()
        assert data["success"] is False
        assert data["error"] == "Weak Password"


def test_registration_normalizes_gmail_and_creates_unverified_account(client):
    """Valid Gmail registration stores normalized email and creates pending unverified account."""
    test_email = "  Test.Registrant2026@Gmail.Com  "
    expected_email = "test.registrant2026@gmail.com"

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = ?", (expected_email,))
    conn.commit()
    conn.close()

    mock_send = MagicMock(return_value=(True, "Sent"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        res = client.post("/api/auth/register", json={
            "full_name": "Test Registrant",
            "email": test_email,
            "password": "Vortex#2026",
            "confirm_password": "Vortex#2026",
            "role": "READER"
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["email"] == expected_email
        assert data["email_verified"] is False
        assert "verification email sent" in data["message"].lower()

    # Verify database state
    conn = get_db_connection()
    row = conn.execute("SELECT email, email_verified FROM users WHERE email = ?", (expected_email,)).fetchone()
    conn.close()
    assert row is not None
    assert row["email"] == expected_email
    assert row["email_verified"] == 0

    # Attempting unverified login must return HTTP 403 with specific message
    login_res = client.post("/api/auth/login", json={
        "email": expected_email,
        "password": "Vortex#2026"
    })
    assert login_res.status_code == 403
    login_data = login_res.get_json()
    assert login_data["code"] == "EMAIL_NOT_VERIFIED"
    assert "Please verify your Gmail address using the verification email sent to you." in login_data["message"]


def test_registration_hard_delivery_failure_message(client):
    """Hard bounce / delivery failure shows definitive message without exposing credentials."""
    test_email = "bounce_test@gmail.com"

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    mock_send = MagicMock(return_value=(False, "550 5.1.1 SMTP recipient rejected: user unknown"))
    with patch("backend.api.auth.send_verification_email", mock_send):
        res = client.post("/api/auth/register", json={
            "full_name": "Bounce User",
            "email": test_email,
            "password": "Secure@Pass9",
            "confirm_password": "Secure@Pass9",
            "role": "READER"
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data["status"] == "WARNING"
        assert data["message"] == "We could not deliver a verification email to this Gmail address. Please check the address and try again."


# ==============================================================================
# 4. USER SETTINGS CHANGE PASSWORD TESTS
# ==============================================================================

def test_settings_change_password_enforces_strong_password(client):
    """Changing password from Settings must enforce the same strong password rule."""
    test_email = "settings_test_user@gmail.com"
    old_pwd = "OldValidPassword#2026"

    # Create active verified user
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    reg_mock = MagicMock(return_value=(True, "Sent"))
    with patch("backend.api.auth.send_verification_email", reg_mock):
        client.post("/api/auth/register", json={
            "full_name": "Settings Tester",
            "email": test_email,
            "password": old_pwd,
            "confirm_password": old_pwd,
            "role": "READER"
        })

    # Activate user directly in DB
    conn = get_db_connection()
    conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    # Login to acquire session token
    login_res = client.post("/api/auth/login", json={"email": test_email, "password": old_pwd})
    assert login_res.status_code == 200
    token = login_res.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Weak new passwords must be rejected with HTTP 400
    weak_new_passwords = [
        "password123",
        "Password123",
        "Password@",
        "PASSWORD@123",
        "premkumar",
        "12345678"
    ]
    for weak_pwd in weak_new_passwords:
        res = client.post("/api/auth/change-password", headers=headers, json={
            "current_password": old_pwd,
            "new_password": weak_pwd,
            "confirm_password": weak_pwd
        })
        assert res.status_code == 400, f"Expected 400 for {weak_pwd}, got {res.status_code}"
        data = res.get_json()
        assert data["error"] == "Weak Password"

    # Valid strong new passwords must be accepted
    strong_new_passwords = ["Prem@2003", "Vortex#2026"]
    for strong_pwd in strong_new_passwords:
        with patch("backend.api.auth.send_password_changed_email", MagicMock()):
            res = client.post("/api/auth/change-password", headers=headers, json={
                "current_password": old_pwd,
                "new_password": strong_pwd,
                "confirm_password": strong_pwd
            })
            assert res.status_code == 200
            assert res.get_json()["success"] is True
            # Update old_pwd for next iteration
            old_pwd = strong_pwd


# ==============================================================================
# 5. PASSWORD RESET ENDPOINT TESTS
# ==============================================================================

def test_reset_password_enforces_strong_password(client):
    """Reset password via token must enforce the same strong password rule."""
    res = client.post("/api/auth/reset-password", json={
        "token": "valid_mock_token_1234567890",
        "new_password": "PASSWORD@123",
        "confirm_password": "PASSWORD@123"
    })
    assert res.status_code == 400
    assert res.get_json()["error"] == "Weak Password"
