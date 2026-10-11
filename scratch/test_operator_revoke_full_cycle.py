"""
Comprehensive Test Script for VORTEX-SDN Operator Revoke/Downgrade Flow:
OPERATOR -> ADMIN REVOKE -> DATABASE = READER -> PERMISSIONS = READER ->
SESSION/AUTH STATE = READER -> USER SETTINGS = READER ->
REQUEST OPERATOR ACCESS AVAILABLE -> NEW REQUEST = PENDING ->
ADMIN APPROVES -> DATABASE = OPERATOR -> USER = OPERATOR
"""

import os
import sys
import sqlite3
import requests

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.abspath("data/vortex.db")

def run_test():
    print("=================================================================")
    print(" STARTING COMPLETE OPERATOR REVOKE / DOWNGRADE / RESTORE TEST")
    print("=================================================================")

    # 1. Clean up test user
    test_email = "testop.revoke2026@gmail.com"
    test_username = "testop_revoke"
    test_pwd = "Password@123"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM operator_access_requests WHERE email = ?", (test_email,))
    cur.execute("DELETE FROM user_permissions WHERE user_id IN (SELECT id FROM users WHERE email = ?)", (test_email,))
    cur.execute("DELETE FROM users WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    # 2. Register test user
    reg_res = requests.post(f"{BASE_URL}/api/auth/register", json={
        "username": test_username,
        "email": test_email,
        "full_name": "Test Revoke Operator",
        "password": test_pwd,
        "confirm_password": test_pwd
    })
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"

    # Activate email directly in DB and get user_id
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET email_verified = 1, is_active = 1 WHERE email = ?", (test_email,))
    conn.commit()
    cur.execute("SELECT id FROM users WHERE email = ?", (test_email,))
    user_id = cur.fetchone()[0]
    conn.close()
    print(f"[STEP 1] Registered test user: id={user_id}")

    # 3. Promote user to OPERATOR with initial approved request and permissions
    # Login as user and submit request
    user_sess = requests.Session()
    u_login = user_sess.post(f"{BASE_URL}/api/auth/login", json={
        "username": test_username,
        "password": test_pwd
    })
    assert u_login.status_code == 200, f"User login failed: {u_login.text}"
    user_token = u_login.json()["token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    req_sub = user_sess.post(f"{BASE_URL}/api/auth/operator-request", headers=user_headers, json={})
    assert req_sub.status_code == 201, f"Operator request failed: {req_sub.text}"
    req_id = req_sub.json()["request_id"]
    print(f"[STEP 2] Submitted initial operator request: {req_id}")

    # Admin login
    admin_email = os.environ.get("ADMIN_EMAIL", "premkumarj18122003@gmail.com")
    admin_sess = requests.Session()
    adm_login = admin_sess.post(f"{BASE_URL}/api/auth/login", json={
        "username": admin_email,
        "password": "Prem@2003"
    })
    assert adm_login.status_code == 200, f"Admin login failed: {adm_login.text}"
    admin_token = adm_login.json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("[STEP 3] Admin logged in successfully")

    # Admin approves request -> User becomes OPERATOR
    app_res = admin_sess.post(f"{BASE_URL}/api/admin/operator-requests/{req_id}/approve", headers=admin_headers, json={
        "reason": "Initial test approval"
    })
    assert app_res.status_code == 200, f"Approval failed: {app_res.text}"
    print("[STEP 4] Admin approved request. User is now OPERATOR")

    # Verify initial OPERATOR state
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    assert cur.fetchone()[0] == "OPERATOR", "Database role is not OPERATOR"
    cur.execute("SELECT status FROM operator_access_requests WHERE id = ?", (req_id,))
    assert cur.fetchone()[0] == "APPROVED", "Request status is not APPROVED"
    cur.execute("SELECT COUNT(*) FROM user_permissions WHERE user_id = ?", (user_id,))
    perm_count = cur.fetchone()[0]
    assert perm_count > 0, "No permissions granted"
    conn.close()

    # User re-authenticates to verify OPERATOR session
    u_login_op = user_sess.post(f"{BASE_URL}/api/auth/login", json={
        "username": test_username,
        "password": test_pwd
    })
    assert u_login_op.status_code == 200
    assert u_login_op.json()["user"]["role"] == "OPERATOR"
    user_token = u_login_op.json()["token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}
    print(f"[STEP 5] Verified OPERATOR credentials: role={u_login_op.json()['user']['role']}, perms={len(u_login_op.json()['user']['permissions'])}")

    # 4. ADMIN REVOKES OPERATOR PRIVILEGES
    print("\n>>> ADMIN CLICKING REVOKE OPERATOR <<<")
    revoke_res = admin_sess.post(f"{BASE_URL}/api/admin/users/{user_id}/revoke-operator", headers=admin_headers, json={})
    assert revoke_res.status_code == 200, f"Revoke endpoint failed: {revoke_res.text}"
    revoke_json = revoke_res.json()
    assert revoke_json["success"] is True
    assert revoke_json["role"] == "READER"
    print(f"[STEP 6] Revoke API returned: success=True, role={revoke_json['role']}")

    # 5. VERIFY DATABASE STATE AFTER REVOKE
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT role, is_active, email_verified FROM users WHERE id = ?", (user_id,))
    u_row = cur.fetchone()
    assert u_row[0] == "READER", f"Expected DB role READER, got {u_row[0]}"
    assert u_row[1] == 1, "Expected account_status ACTIVE (is_active=1)"
    assert u_row[2] == 1, "Expected email_verified unchanged (1)"

    cur.execute("SELECT status, review_reason FROM operator_access_requests WHERE id = ?", (req_id,))
    req_row = cur.fetchone()
    assert req_row[0] == "REVOKED", f"Expected operator request status REVOKED, got {req_row[0]}"

    cur.execute("SELECT COUNT(*) FROM user_permissions WHERE user_id = ?", (user_id,))
    assert cur.fetchone()[0] == 0, "Expected custom user_permissions cleared (0)"
    conn.close()
    print("[STEP 7] Verified Database State: role=READER, is_active=1, email_verified=1, request=REVOKED, user_permissions=0")

    # 6. VERIFY AUDIT TRAIL
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT action, role, resource, result FROM audit_logs WHERE action = 'OPERATOR_REVOKED' ORDER BY timestamp DESC LIMIT 1")
    audit_row = cur.fetchone()
    assert audit_row is not None, "Audit log missing OPERATOR_REVOKED entry"
    assert audit_row[0] == "OPERATOR_REVOKED"
    assert audit_row[3] == "SUCCESS"
    conn.close()
    print(f"[STEP 8] Verified Audit Log: action={audit_row[0]}, status={audit_row[3]}")

    # 7. VERIFY ADMIN DIRECTORY IMMEDIATELY REFLECTS READER
    dir_res = admin_sess.get(f"{BASE_URL}/api/admin/users", headers=admin_headers)
    assert dir_res.status_code == 200
    all_users = dir_res.json()["users"]
    target_in_dir = next((u for u in all_users if u["id"] == user_id), None)
    assert target_in_dir is not None, "Target user not found in admin directory"
    assert target_in_dir["role"] == "READER", f"Admin directory displays {target_in_dir['role']} instead of READER"
    mod_perms = [p for p in target_in_dir["permissions"] if not p.endswith(".view") and p != "*"]
    assert len(mod_perms) == 0, f"Reader has unexpected modification permissions: {mod_perms}"
    print(f"[STEP 9] Verified Admin Directory: user displayed as {target_in_dir['role']} with {len(target_in_dir['permissions'])} view perms and 0 control perms")

    # 8. VERIFY READER LOGIN & SERVER-AUTHORITATIVE ROLE AFTER REVOKE
    u_login_reader = user_sess.post(f"{BASE_URL}/api/auth/login", json={
        "username": test_username,
        "password": test_pwd
    })
    assert u_login_reader.status_code == 200
    reader_user = u_login_reader.json()["user"]
    assert reader_user["role"] == "READER", f"Login payload returned role {reader_user['role']} instead of READER"
    reader_token = u_login_reader.json()["token"]
    reader_headers = {"Authorization": f"Bearer {reader_token}"}
    print(f"[STEP 10] Downgraded User Login: role={reader_user['role']}")

    # 9. VERIFY /api/auth/me SERVER-AUTHORITY
    me_res = user_sess.get(f"{BASE_URL}/api/auth/me", headers=reader_headers)
    assert me_res.status_code == 200
    assert me_res.json()["user"]["role"] == "READER", f"GET /api/auth/me returned {me_res.json()['user']['role']}"
    print(f"[STEP 11] GET /api/auth/me returned server-authoritative role: {me_res.json()['user']['role']}")

    # 10. VERIFY /api/auth/operator-request/status RETURNS REVOKED (READY FOR NEW REQUEST)
    status_res = user_sess.get(f"{BASE_URL}/api/auth/operator-request/status", headers=reader_headers)
    assert status_res.status_code == 200
    status_json = status_res.json()
    assert status_json["status"] == "REVOKED", f"Expected request status REVOKED, got {status_json['status']}"
    print(f"[STEP 12] GET /api/auth/operator-request/status returned: {status_json['status']}")

    # 11. READER SUBMITS A NEW OPERATOR REQUEST
    print("\n>>> READER SUBMITTING NEW OPERATOR ACCESS REQUEST <<<")
    new_req_res = user_sess.post(f"{BASE_URL}/api/auth/operator-request", headers=reader_headers, json={})
    assert new_req_res.status_code == 201, f"Failed to submit new operator request: {new_req_res.text}"
    new_req_id = new_req_res.json()["request_id"]
    assert new_req_res.json()["status"] == "PENDING"
    print(f"[STEP 13] New operator request submitted successfully: id={new_req_id}, status=PENDING")

    # 12. ADMIN VIEWS PENDING REQUEST
    pending_res = admin_sess.get(f"{BASE_URL}/api/admin/operator-requests", headers=admin_headers)
    assert pending_res.status_code == 200
    pending_list = pending_res.json()["requests"]
    new_pending = next((r for r in pending_list if r["id"] == new_req_id), None)
    assert new_pending is not None, "New operator request not found in Admin pending list"
    assert new_pending["status"] == "PENDING"
    print(f"[STEP 14] Verified Admin sees new pending request: {new_pending['id']} (status={new_pending['status']})")

    # 13. ADMIN APPROVES NEW REQUEST -> USER BECOMES OPERATOR AGAIN
    approve2_res = admin_sess.post(f"{BASE_URL}/api/admin/operator-requests/{new_req_id}/approve", headers=admin_headers, json={
        "reason": "Re-approved by administrator"
    })
    assert approve2_res.status_code == 200
    assert approve2_res.json()["role"] == "OPERATOR"
    print("[STEP 15] Admin approved new request. User role restored to OPERATOR")

    # 14. VERIFY USER IS OPERATOR AGAIN ACROSS ALL LAYERS
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    assert cur.fetchone()[0] == "OPERATOR", "Database role is not OPERATOR"
    conn.close()

    final_me = user_sess.get(f"{BASE_URL}/api/auth/me", headers=reader_headers)
    assert final_me.status_code == 200
    assert final_me.json()["user"]["role"] == "OPERATOR", "GET /api/auth/me did not return OPERATOR"

    # Clean up test user
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM operator_access_requests WHERE email = ?", (test_email,))
    cur.execute("DELETE FROM user_permissions WHERE user_id IN (SELECT id FROM users WHERE email = ?)", (test_email,))
    cur.execute("DELETE FROM users WHERE email = ?", (test_email,))
    conn.commit()
    conn.close()

    print("\n=================================================================")
    print(" ALL 15 VERIFICATION STEPS PASSED 100% PERFECTLY!")
    print(" NO STALE OPERATOR STATE FOUND AT ANY POINT.")
    print("=================================================================")

if __name__ == "__main__":
    run_test()
