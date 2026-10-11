"""
Complete End-to-End Test for VORTEX-SDN Operator Request and Admin Approval Flow
Tests all 20 requirements:
1. Reader login
2. Reader requests Operator Access
3. Database verification of PENDING record
4. Resend while PENDING reuses existing request (no duplicate)
5. Admin login and GET /api/admin/operator-requests and GET /api/admin/users
6. Admin APPROVE flow -> Role becomes OPERATOR, request becomes APPROVED
7. Second Reader request -> Admin REJECT flow -> Request becomes REJECTED, role remains READER
8. Audit log verification
"""

import requests
import sqlite3
import os
import json

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.abspath("data/vortex.db")

def test_flow():
    print("=== STARTING COMPLETE OPERATOR REQUEST & ADMIN APPROVAL FLOW TEST ===")
    print(f"Database Path: {DB_PATH} (exists: {os.path.exists(DB_PATH)})")

    # 1. Clean up test users if existing
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM operator_access_requests WHERE email IN ('testreader1.flow2026@gmail.com', 'testreader2.flow2026@gmail.com')")
    cur.execute("DELETE FROM users WHERE email IN ('testreader1.flow2026@gmail.com', 'testreader2.flow2026@gmail.com')")
    conn.commit()
    conn.close()

    # 2. Register Reader 1
    session = requests.Session()
    reg1 = session.post(f"{BASE_URL}/api/auth/register", json={
        "username": "testreader1",
        "email": "testreader1.flow2026@gmail.com",
        "full_name": "Test Reader One",
        "password": "Password@123",
        "confirm_password": "Password@123"
    })
    print(f"Register Reader 1: {reg1.status_code}")
    assert reg1.status_code == 201, f"Reg failed: {reg1.text}"

    # Verify email directly in DB for Reader 1 so they are active verified Reader
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET email_verified = 1 WHERE email = 'testreader1.flow2026@gmail.com'")
    conn.commit()
    conn.close()

    # Login as Reader 1
    login1 = session.post(f"{BASE_URL}/api/auth/login", json={
        "email": "testreader1.flow2026@gmail.com",
        "password": "Password@123"
    })
    assert login1.status_code == 200, f"Login failed: {login1.text}"
    token1 = login1.json()["token"]
    user1_id = login1.json()["user"]["id"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    print(f"Logged in as Reader 1: {user1_id}, role: {login1.json()['user']['role']}")

    # 3. Reader 1 checks status before requesting
    st_before = session.get(f"{BASE_URL}/api/auth/operator-request/status", headers=headers1)
    assert st_before.status_code == 200
    assert st_before.json()["status"] == "NONE"
    print(f"Reader 1 initial status: {st_before.json()['status']}")

    # 4. Reader 1 submits Request Operator Access
    req1 = session.post(f"{BASE_URL}/api/auth/operator-request", headers=headers1, json={})
    print(f"Reader 1 submit request: {req1.status_code}, response: {req1.json()}")
    assert req1.status_code == 201
    assert req1.json()["success"] is True
    assert req1.json()["status"] == "PENDING"
    req1_id = req1.json()["request_id"]

    # 5. Check real database for PENDING request
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM operator_access_requests WHERE id = ?", (req1_id,))
    db_req1 = dict(cur.fetchone())
    conn.close()
    print(f"Database PENDING request verified: {db_req1}")
    assert db_req1["status"] == "PENDING"
    assert db_req1["user_id"] == user1_id
    assert db_req1["email"] == "testreader1.flow2026@gmail.com"

    # 6. Test duplicate submission prevention
    dup_res = session.post(f"{BASE_URL}/api/auth/operator-request", headers=headers1, json={})
    print(f"Duplicate request response: {dup_res.status_code}, {dup_res.json()}")
    assert dup_res.status_code in (200, 409)
    assert dup_res.json()["status"] == "PENDING"

    # Confirm still exactly ONE row in database for Reader 1
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM operator_access_requests WHERE user_id = ?", (user1_id,))
    count1 = cur.fetchone()[0]
    conn.close()
    assert count1 == 1, f"Expected 1 request row, found {count1}"
    print(f"Verified exactly 1 row exists in DB for Reader 1")

    # 7. Test Resend Request (reuses existing request, enforces cooldown)
    resend_res = session.post(f"{BASE_URL}/api/auth/operator-request/resend", headers=headers1, json={})
    print(f"Resend response: {resend_res.status_code}, {resend_res.json()}")
    assert resend_res.status_code in (200, 429)
    if resend_res.status_code == 429:
        assert resend_res.json()["error"] == "Rate Limited"
        print("Resend properly rate-limited with cooldown")
    else:
        assert resend_res.json()["request_id"] == req1_id

    # Confirm still exactly ONE row in database
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM operator_access_requests WHERE user_id = ?", (user1_id,))
    count_after_resend = cur.fetchone()[0]
    conn.close()
    assert count_after_resend == 1
    print(f"Verified resend did not create duplicate row: count={count_after_resend}")

    # 8. Login as Admin
    admin_session = requests.Session()
    admin_login = admin_session.post(f"{BASE_URL}/api/auth/login", json={
        "email": "premkumarj18122003@gmail.com",
        "password": "Prem@2003"
    })
    assert admin_login.status_code == 200, f"Admin login failed: {admin_login.text}"
    admin_token = admin_login.json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print(f"Logged in as ADMIN: {admin_login.json()['user']['email']}")

    # 9. Admin queries pending operator requests API
    adm_reqs = admin_session.get(f"{BASE_URL}/api/admin/operator-requests", headers=admin_headers)
    assert adm_reqs.status_code == 200
    adm_reqs_json = adm_reqs.json()
    assert adm_reqs_json["success"] is True
    print(f"Admin pending requests API: count={adm_reqs_json['count']}")
    found1 = [r for r in adm_reqs_json["requests"] if r["id"] == req1_id]
    assert len(found1) == 1
    assert found1[0]["status"] == "PENDING"
    assert found1[0]["email"] == "testreader1.flow2026@gmail.com"
    assert found1[0]["request_id"] == req1_id
    assert found1[0]["name"] == "Test Reader One"

    # 10. Admin queries users directory API
    adm_users = admin_session.get(f"{BASE_URL}/api/admin/users", headers=admin_headers)
    assert adm_users.status_code == 200
    adm_users_json = adm_users.json()
    assert adm_users_json["success"] is True
    print(f"Admin users directory API: count={adm_users_json['count']}")
    found_user1 = [u for u in adm_users_json["users"] if u["id"] == user1_id]
    assert len(found_user1) == 1
    assert found_user1[0]["role"] == "READER"

    # 11. Admin clicks APPROVE for Reader 1
    approve_res = admin_session.post(f"{BASE_URL}/api/admin/operator-requests/{req1_id}/approve", headers=admin_headers, json={
        "reason": "Approved in NOC security verification"
    })
    print(f"Approve response: {approve_res.status_code}, {approve_res.json()}")
    assert approve_res.status_code == 200
    assert approve_res.json()["success"] is True
    assert approve_res.json()["role"] == "OPERATOR"

    # Verify database after approval
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT status, reviewed_at, reviewed_by FROM operator_access_requests WHERE id = ?", (req1_id,))
    approved_req = dict(cur.fetchone())
    cur.execute("SELECT role, email_verified FROM users WHERE id = ?", (user1_id,))
    approved_user = dict(cur.fetchone())
    conn.close()

    print(f"DB request after approval: {approved_req}")
    print(f"DB user after approval: {approved_user}")
    assert approved_req["status"] == "APPROVED"
    assert approved_req["reviewed_at"] is not None
    assert approved_user["role"] == "OPERATOR"
    assert approved_user["email_verified"] == 1

    # Verify Reader 1 me/status reflects OPERATOR
    me1 = session.get(f"{BASE_URL}/api/auth/me", headers=headers1)
    assert me1.json()["user"]["role"] == "OPERATOR"

    # 12. Register Reader 2 to test REJECT flow
    reg2 = session.post(f"{BASE_URL}/api/auth/register", json={
        "username": "testreader2",
        "email": "testreader2.flow2026@gmail.com",
        "full_name": "Test Reader Two",
        "password": "Password@123",
        "confirm_password": "Password@123"
    })
    assert reg2.status_code == 201

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET email_verified = 1 WHERE email = 'testreader2.flow2026@gmail.com'")
    conn.commit()
    conn.close()

    login2 = session.post(f"{BASE_URL}/api/auth/login", json={
        "email": "testreader2.flow2026@gmail.com",
        "password": "Password@123"
    })
    token2 = login2.json()["token"]
    user2_id = login2.json()["user"]["id"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Reader 2 submits request
    req2 = session.post(f"{BASE_URL}/api/auth/operator-request", headers=headers2, json={})
    assert req2.status_code == 201
    req2_id = req2.json()["request_id"]

    # Admin REJECTS Reader 2 request
    reject_res = admin_session.post(f"{BASE_URL}/api/admin/operator-requests/{req2_id}/reject", headers=admin_headers, json={
        "reason": "Insufficient operational credentials"
    })
    print(f"Reject response: {reject_res.status_code}, {reject_res.json()}")
    assert reject_res.status_code == 200
    assert reject_res.json()["success"] is True

    # Verify DB after rejection
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT status, review_reason FROM operator_access_requests WHERE id = ?", (req2_id,))
    rejected_req = dict(cur.fetchone())
    cur.execute("SELECT role FROM users WHERE id = ?", (user2_id,))
    rejected_user = dict(cur.fetchone())
    conn.close()

    print(f"DB request after rejection: {rejected_req}")
    print(f"DB user after rejection: {rejected_user}")
    assert rejected_req["status"] == "REJECTED"
    assert rejected_user["role"] == "READER"

    # 13. Verify Audit Log contains all events
    audit_res = admin_session.get(f"{BASE_URL}/api/audit", headers=admin_headers)
    assert audit_res.status_code == 200
    audit_actions = [e["action"] for e in audit_res.json().get("logs", [])]
    print(f"Recent audit actions: {audit_actions[:10]}")
    assert "OPERATOR_ACCESS_REQUESTED" in audit_actions
    assert "OPERATOR_APPROVED" in audit_actions
    assert "OPERATOR_REJECTED" in audit_actions

    # Non-admin cannot access audit or admin endpoints
    reader_audit = session.get(f"{BASE_URL}/api/audit", headers=headers2)
    assert reader_audit.status_code == 403
    reader_adm_reqs = session.get(f"{BASE_URL}/api/admin/operator-requests", headers=headers2)
    assert reader_adm_reqs.status_code == 403

    # Clean up test users
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM operator_access_requests WHERE email IN ('testreader1.flow2026@gmail.com', 'testreader2.flow2026@gmail.com')")
    cur.execute("DELETE FROM users WHERE email IN ('testreader1.flow2026@gmail.com', 'testreader2.flow2026@gmail.com')")
    conn.commit()
    conn.close()

    print("\nALL 20 TEST CHECKS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_flow()
