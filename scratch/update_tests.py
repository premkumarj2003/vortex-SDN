import re

with open("tests/test_vortex.py", "r", encoding="utf-8") as f:
    content = f.read()

# Normalize line endings
content = content.replace("\r\n", "\n")

old_bypass_test = '''def test_auth_registration_and_login_bypass_mode(client):
    """Verifies direct registration and instant login when email verification is disabled."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ? OR username = ?", ("test_direct@vortex-sdn.local", "test_direct_op"))
    conn.commit()
    conn.close()

    test_user = {
        "username": "test_direct_op",
        "email": "test_direct@vortex-sdn.local",
        "full_name": "Direct Operator Lead",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "OPERATOR"
    }

    # 1. Register in default bypass mode (EMAIL_VERIFICATION_REQUIRED=false)
    with patch("backend.api.auth.is_email_verification_required", return_value=False):
        res = client.post("/api/auth/register", json=test_user)
        assert res.status_code == 201
        reg_data = res.get_json()
        assert reg_data["success"] is True
        assert reg_data["email_verified"] is True

        # 2. Login immediately succeeds
        good_login = client.post("/api/auth/login", json={"username": "test_direct_op", "password": "Password@2026"})
        assert good_login.status_code == 200
        login_data = good_login.get_json()
        assert login_data["success"] is True
        assert "token" in login_data
        token = login_data["token"]
        assert login_data["user"]["full_name"] == "Direct Operator Lead"
        assert login_data["user"]["role"] == "OPERATOR"

        # 3. /api/auth/me returns authenticated identity
        me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.get_json()["authenticated"] is True
        assert me_res.get_json()["user"]["full_name"] == "Direct Operator Lead"

        # 4. Logout invalidates session
        logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout_res.status_code == 200

        after_logout = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert after_logout.status_code == 200
        assert after_logout.get_json()["authenticated"] is False'''

new_real_test = '''def test_auth_registration_and_login_real_verification(client):
    """Verifies complete real email verification lifecycle: register -> unverified blocked -> verify token -> login -> change password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ? OR username = ?", ("test_direct@vortex-sdn.local", "test_direct_op"))
    conn.commit()
    conn.close()

    test_user = {
        "username": "test_direct_op",
        "email": "test_direct@vortex-sdn.local",
        "full_name": "Direct Operator Lead",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "OPERATOR"
    }

    # 1. Register with real verification (send_verification_email mocked as successful)
    with patch("backend.api.auth.send_verification_email", return_value=(True, "Verification email sent successfully.")):
        res = client.post("/api/auth/register", json=test_user)
        assert res.status_code == 201
        reg_data = res.get_json()
        assert reg_data["success"] is True
        assert reg_data["email_verified"] is False

    # 2. Login before email verification MUST fail with 403 EMAIL_NOT_VERIFIED
    blocked = client.post("/api/auth/login", json={"username": "test_direct_op", "password": "Password@2026"})
    assert blocked.status_code == 403
    assert blocked.get_json()["code"] == "EMAIL_NOT_VERIFIED"

    # 3. Resend verification email
    with patch("backend.api.auth.send_verification_email", return_value=(True, "Verification email sent successfully.")):
        resend_res = client.post("/api/auth/resend-verification", json={"email": "test_direct@vortex-sdn.local"})
        assert resend_res.status_code == 200
        assert resend_res.get_json()["success"] is True

    # 4. Generate and verify token
    raw_token, tok_hash, exp_iso = generate_secure_token()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ? WHERE username = ?", (tok_hash, exp_iso, "test_direct_op"))
    conn.commit()
    conn.close()

    verif_res = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert verif_res.status_code == 200
    assert verif_res.get_json()["success"] is True

    # Token cannot be reused (single-use)
    reuse_verif = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert reuse_verif.status_code == 400

    # 5. Login now succeeds
    good_login = client.post("/api/auth/login", json={"username": "test_direct_op", "password": "Password@2026"})
    assert good_login.status_code == 200
    login_data = good_login.get_json()
    assert login_data["success"] is True
    assert "token" in login_data
    token = login_data["token"]
    assert login_data["user"]["full_name"] == "Direct Operator Lead"
    assert login_data["user"]["role"] == "OPERATOR"

    # 6. /api/auth/me returns authenticated identity
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.get_json()["authenticated"] is True
    assert me_res.get_json()["user"]["full_name"] == "Direct Operator Lead"

    # 7. Change password from settings
    with patch("backend.api.auth.send_password_changed_email", return_value=(True, "Security email sent")):
        # Wrong current password fails
        bad_change = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {token}"}, json={
            "current_password": "WrongPassword",
            "new_password": "NewOperatorPass@2026",
            "confirm_password": "NewOperatorPass@2026"
        })
        assert bad_change.status_code == 400

        # Correct current password succeeds
        good_change = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {token}"}, json={
            "current_password": "Password@2026",
            "new_password": "NewOperatorPass@2026",
            "confirm_password": "NewOperatorPass@2026"
        })
        assert good_change.status_code == 200

    # Old password no longer works
    assert client.post("/api/auth/login", json={"username": "test_direct_op", "password": "Password@2026"}).status_code == 401

    # New password works
    assert client.post("/api/auth/login", json={"username": "test_direct_op", "password": "NewOperatorPass@2026"}).status_code == 200

    # 8. Logout invalidates session
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    after_logout = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert after_logout.status_code == 200
    assert after_logout.get_json()["authenticated"] is False'''

if old_bypass_test in content:
    content = content.replace(old_bypass_test, new_real_test)
    print("Replaced bypass test successfully!")
else:
    print("Warning: old_bypass_test not found in content")

# In test_user_settings_persistence, verify email so login works
old_settings_reg = '''        "full_name": "Settings Operator"
    })
    assert reg.status_code == 201

    login = client.post("/api/auth/login", json={"username": uname, "password": "Password@2026"})'''

new_settings_reg = '''        "full_name": "Settings Operator"
    })
    assert reg.status_code == 201

    # Verify user email in database so login succeeds
    _c = get_db_connection()
    _c.execute("UPDATE users SET email_verified = 1 WHERE username = ?", (uname,))
    _c.commit()
    _c.close()

    login = client.post("/api/auth/login", json={"username": uname, "password": "Password@2026"})'''

if old_settings_reg in content:
    content = content.replace(old_settings_reg, new_settings_reg)
    print("Replaced settings reg successfully!")
else:
    print("Warning: old_settings_reg not found in content")

with open("tests/test_vortex.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Finished writing tests/test_vortex.py")
