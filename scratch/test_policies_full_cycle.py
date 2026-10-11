import requests
import json
import sqlite3
import os

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vortex.db")

def run_tests():
    print("=== STARTING FULL POLICY & RULE MANAGEMENT LIFECYCLE TESTS ===")
    
    # Step 1: Login as ADMIN
    login_res = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "premkumarj18122003@gmail.com",
        "password": "Prem@2003"
    })
    assert login_res.status_code == 200, f"Admin login failed: {login_res.text}"
    admin_token = login_res.json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("[PASS] Step 1: ADMIN Login successful")

    # Step 2: Fetch policies as ADMIN
    pols_res = requests.get(f"{BASE_URL}/api/policies", headers=admin_headers)
    assert pols_res.status_code == 200, f"Get policies failed: {pols_res.text}"
    pols_data = pols_res.json()
    assert "qos_policies" in pols_data and "security_policies" in pols_data
    print(f"[PASS] Step 2: Fetched {len(pols_data['qos_policies'])} QoS policies and {len(pols_data['security_policies'])} Security rules")

    # Step 3: CREATE QoS Policy as ADMIN
    qos_payload = {
        "type": "QOS",
        "name": "E2E Automated QoS Test Policy",
        "traffic_class": "VOICE",
        "priority_code": "EF",
        "min_bandwidth_mbps": 15.0,
        "max_bandwidth_mbps": 75.0,
        "queue_id": 1,
        "dscp_mark": 46,
        "match_criteria": "UDP dst_port: 5060-5080",
        "action": "ENQUEUE",
        "is_active": 1
    }
    create_qos_res = requests.post(f"{BASE_URL}/api/policies", headers=admin_headers, json=qos_payload)
    assert create_qos_res.status_code == 201, f"Create QoS policy failed: {create_qos_res.text}"
    qos_id = create_qos_res.json()["id"]
    print(f"[PASS] Step 3: Created QoS policy with real ID: {qos_id}")

    # Verify in SQLite database
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM qos_policies WHERE id = ?", (qos_id,))
    row = c.fetchone()
    assert row is not None, "QoS policy not found in database!"
    assert row["name"] == "E2E Automated QoS Test Policy"
    assert row["priority_code"] == "EF"
    assert row["min_bandwidth_mbps"] == 15.0
    print("[PASS] Step 3b: Verified QoS policy directly in SQLite database")

    # Verify audit log
    c.execute("SELECT * FROM audit_logs WHERE resource = ? AND action = 'CREATE_QOS_POLICY'", (f"Policy {qos_id}",))
    audit_row = c.fetchone()
    assert audit_row is not None, "Audit log missing for CREATE_QOS_POLICY"
    print("[PASS] Step 3c: Audit log verified: CREATE_QOS_POLICY")
    conn.close()

    # Step 4: GET Single Policy via GET /api/policies/<id>
    get_single = requests.get(f"{BASE_URL}/api/policies/{qos_id}", headers=admin_headers)
    assert get_single.status_code == 200, f"GET single policy failed: {get_single.text}"
    pol_obj = get_single.json()["policy"]
    assert pol_obj["id"] == qos_id
    assert pol_obj["name"] == "E2E Automated QoS Test Policy"
    assert pol_obj["type"] == "QOS"
    print("[PASS] Step 4: GET /api/policies/<id> returned correct database values for edit modal")

    # Step 5: EDIT QoS Policy via PUT /api/policies/<id>
    edit_payload = {
        "name": "E2E Automated QoS Test Policy - Modified",
        "traffic_class": "VIDEO",
        "priority_code": "AF",
        "min_bandwidth_mbps": 20.0,
        "max_bandwidth_mbps": 90.0,
        "queue_id": 2,
        "dscp_mark": 34,
        "match_criteria": "TCP dst_port: 1935",
        "is_active": 1
    }
    edit_res = requests.put(f"{BASE_URL}/api/policies/{qos_id}", headers=admin_headers, json=edit_payload)
    assert edit_res.status_code == 200, f"Edit QoS policy failed: {edit_res.text}"

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM qos_policies WHERE id = ?", (qos_id,))
    row = c.fetchone()
    assert row["name"] == "E2E Automated QoS Test Policy - Modified"
    assert row["traffic_class"] == "VIDEO"
    assert row["priority_code"] == "AF"
    assert row["min_bandwidth_mbps"] == 20.0
    print("[PASS] Step 5: Updated QoS policy; same ID preserved in database")

    c.execute("SELECT * FROM audit_logs WHERE resource = ? AND action = 'MODIFY_QOS_POLICY'", (f"Policy {qos_id}",))
    assert c.fetchone() is not None, "Audit log missing for MODIFY_QOS_POLICY"
    print("[PASS] Step 5b: Audit log verified: MODIFY_QOS_POLICY")
    conn.close()

    # Step 6: TOGGLE QoS Policy
    toggle_res = requests.post(f"{BASE_URL}/api/policies/{qos_id}/toggle", headers=admin_headers)
    assert toggle_res.status_code == 200
    assert toggle_res.json()["is_active"] == 0
    print("[PASS] Step 6a: Toggled policy to DISABLED")

    toggle_res2 = requests.post(f"{BASE_URL}/api/policies/{qos_id}/toggle", headers=admin_headers)
    assert toggle_res2.status_code == 200
    assert toggle_res2.json()["is_active"] == 1
    print("[PASS] Step 6b: Toggled policy back to ENABLED")

    # Step 7: CREATE Security Rule as ADMIN
    sec_payload = {
        "type": "SECURITY",
        "name": "E2E Automated Security Block Rule",
        "rule_type": "BLOCK",
        "source_ip": "10.0.0.199",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "threshold_pps": 3500.0,
        "is_active": 1
    }
    create_sec_res = requests.post(f"{BASE_URL}/api/rules", headers=admin_headers, json=sec_payload)
    assert create_sec_res.status_code == 201, f"Create Security rule failed: {create_sec_res.text}"
    sec_id = create_sec_res.json()["id"]
    print(f"[PASS] Step 7: Created Security rule with ID: {sec_id}")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM security_policies WHERE id = ?", (sec_id,))
    row = c.fetchone()
    assert row is not None
    assert row["name"] == "E2E Automated Security Block Rule"
    assert row["rule_type"] == "BLOCK"
    assert row["source_ip"] == "10.0.0.199"
    conn.close()
    print("[PASS] Step 7b: Verified Security rule in database")

    # Step 8: EDIT Security Rule
    edit_sec = requests.put(f"{BASE_URL}/api/rules/{sec_id}", headers=admin_headers, json={
        "name": "E2E Automated Security Rate Limit Rule",
        "rule_type": "RATE_LIMIT",
        "threshold_pps": 1200.0,
        "protocol": "UDP",
        "source_ip": "10.0.0.199",
        "destination_ip": "*",
        "is_active": 1
    })
    assert edit_sec.status_code == 200, f"Edit Security rule failed: {edit_sec.text}"
    print("[PASS] Step 8: Updated Security rule")

    # Step 9: VALIDATION TESTS
    # 9a: Empty name
    bad_name = requests.post(f"{BASE_URL}/api/policies", headers=admin_headers, json={"type": "QOS", "name": " "})
    assert bad_name.status_code == 400
    print("[PASS] Step 9a: Empty name correctly rejected with HTTP 400")

    # 9b: Min BW > Max BW
    bad_bw = requests.post(f"{BASE_URL}/api/policies", headers=admin_headers, json={
        "type": "QOS",
        "name": "Bad BW Rule",
        "min_bandwidth_mbps": 100.0,
        "max_bandwidth_mbps": 50.0
    })
    assert bad_bw.status_code == 400
    print("[PASS] Step 9b: Inverted bandwidth range correctly rejected with HTTP 400")

    # 9c: Duplicate name
    dup_res = requests.post(f"{BASE_URL}/api/policies", headers=admin_headers, json={
        "type": "QOS",
        "name": "E2E Automated QoS Test Policy - Modified"
    })
    assert dup_res.status_code == 400
    print("[PASS] Step 9c: Duplicate policy name correctly rejected with HTTP 400")

    # 9d: Invalid security threshold
    bad_thresh = requests.post(f"{BASE_URL}/api/rules", headers=admin_headers, json={
        "type": "SECURITY",
        "name": "Bad Threshold Rule",
        "threshold_pps": -50.0
    })
    assert bad_thresh.status_code == 400
    print("[PASS] Step 9d: Negative threshold correctly rejected with HTTP 400")

    # Step 10: RBAC AUTHORIZATION TESTS (Non-Admin forbidden)
    # Check with no auth -> 401
    anon_res = requests.post(f"{BASE_URL}/api/policies", json={"name": "Anon"})
    assert anon_res.status_code == 401
    print("[PASS] Step 10a: Unauthenticated mutation rejected with HTTP 401")

    # Step 11: DELETE both created test policies as ADMIN
    del_qos = requests.delete(f"{BASE_URL}/api/policies/{qos_id}", headers=admin_headers)
    assert del_qos.status_code == 200
    del_sec = requests.delete(f"{BASE_URL}/api/rules/{sec_id}", headers=admin_headers)
    assert del_sec.status_code == 200

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM qos_policies WHERE id = ?", (qos_id,))
    assert c.fetchone() is None
    c.execute("SELECT * FROM security_policies WHERE id = ?", (sec_id,))
    assert c.fetchone() is None
    c.execute("SELECT * FROM audit_logs WHERE resource = ? AND action = 'DELETE_POLICY'", (f"Policy {qos_id}",))
    assert c.fetchone() is not None
    conn.close()
    print("[PASS] Step 11: Both test policies deleted, removed from SQLite, and audited with DELETE_POLICY")

    print("\n>>> ALL BACKEND API & DATABASE TESTS PASSED 100%! <<<\n")

if __name__ == "__main__":
    run_tests()
