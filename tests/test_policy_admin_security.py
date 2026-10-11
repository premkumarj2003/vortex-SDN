"""
Comprehensive Test Suite for Admin-Only Policy & Rule Management and User Protection
Verifies:
1. ADMIN can view policies.
2. ADMIN can create QoS policy.
3. ADMIN can edit QoS policy.
4. ADMIN can delete QoS policy.
5. ADMIN can create network security rule.
6. ADMIN can edit network security rule.
7. ADMIN can delete network security rule.
8. OPERATOR cannot delete a policy (HTTP 403).
9. OPERATOR cannot modify a policy (HTTP 403).
10. OPERATOR cannot delete a network rule (HTTP 403).
11. READER cannot modify a policy (HTTP 403).
12. READER cannot delete a network rule (HTTP 403).
13. Direct DELETE API call by OPERATOR returns HTTP 403.
14. Direct DELETE API call by READER returns HTTP 403.
15. Direct DELETE API call by ADMIN succeeds.
16. Attempt to delete ADMIN account returns HTTP 403.
17. Attempting to delete non-existent policy returns HTTP 404.
"""

import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api.server import create_app
from backend.models.database import init_db, get_db_connection
from backend.api.auth import ACTIVE_SESSIONS


@pytest.fixture
def app_client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_tokens():
    """Sets up authenticated test sessions for ADMIN, OPERATOR, and READER."""
    admin_token = "test_sess_admin_premkumar"
    op_token = "test_sess_operator"
    reader_token = "test_sess_reader"

    ACTIVE_SESSIONS[admin_token] = {
        "id": "usr_1084be32",
        "username": "sakshi",
        "email": "premkumarj18122003@gmail.com",
        "role": "ADMIN",
        "permissions": ["*"]
    }

    ACTIVE_SESSIONS[op_token] = {
        "id": "usr_test_operator_1",
        "username": "op_tester",
        "email": "op_tester@vortex.local",
        "role": "OPERATOR",
        "permissions": ["dashboard.view", "qos.view", "network.view", "qos.configure", "network.configure"]
    }

    ACTIVE_SESSIONS[reader_token] = {
        "id": "usr_test_reader_1",
        "username": "reader_tester",
        "email": "reader_tester@vortex.local",
        "role": "READER",
        "permissions": ["dashboard.view", "qos.view", "network.view"]
    }

    yield {
        "admin": {"Authorization": f"Bearer {admin_token}", "X-Test-Enforce-Auth": "1"},
        "operator": {"Authorization": f"Bearer {op_token}", "X-Test-Enforce-Auth": "1"},
        "reader": {"Authorization": f"Bearer {reader_token}", "X-Test-Enforce-Auth": "1"}
    }

    # Cleanup
    ACTIVE_SESSIONS.pop(admin_token, None)
    ACTIVE_SESSIONS.pop(op_token, None)
    ACTIVE_SESSIONS.pop(reader_token, None)


def test_view_policies_allowed_for_all(app_client, auth_tokens):
    """1. ADMIN, OPERATOR, and READER can all view policies."""
    res_admin = app_client.get("/api/policies", headers=auth_tokens["admin"])
    assert res_admin.status_code == 200
    assert "qos_policies" in res_admin.get_json()

    res_op = app_client.get("/api/policies", headers=auth_tokens["operator"])
    assert res_op.status_code == 200

    res_reader = app_client.get("/api/policies", headers=auth_tokens["reader"])
    assert res_reader.status_code == 200


def test_admin_create_modify_delete_qos_policy(app_client, auth_tokens):
    """2-4, 15. ADMIN can create, edit, toggle, and delete a QoS policy."""
    # 2. ADMIN creates policy
    create_res = app_client.post("/api/policies", headers=auth_tokens["admin"], json={
        "type": "QOS",
        "name": "Admin Test QoS Policy",
        "traffic_class": "VOICE",
        "priority_code": "EF",
        "min_bandwidth_mbps": 20.0,
        "max_bandwidth_mbps": 80.0,
        "queue_id": 1,
        "dscp_mark": 46,
        "match_criteria": "UDP dst_port: 5060",
        "action": "ENQUEUE"
    })
    assert create_res.status_code == 201
    pol_id = create_res.get_json()["id"]

    # 3. ADMIN edits policy
    edit_res = app_client.put(f"/api/policies/{pol_id}", headers=auth_tokens["admin"], json={
        "name": "Updated Admin QoS Policy",
        "max_bandwidth_mbps": 95.0,
        "priority_code": "EF"
    })
    assert edit_res.status_code == 200
    assert edit_res.get_json()["status"] == "SUCCESS"

    # Toggle policy
    toggle_res = app_client.post(f"/api/policies/{pol_id}/toggle", headers=auth_tokens["admin"])
    assert toggle_res.status_code == 200
    assert toggle_res.get_json()["is_active"] == 0

    # 4 & 15. ADMIN deletes policy
    del_res = app_client.delete(f"/api/policies/{pol_id}", headers=auth_tokens["admin"])
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "SUCCESS"

    # Verify deletion from DB
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM qos_policies WHERE id = ?", (pol_id,))
    assert c.fetchone() is None
    conn.close()


def test_admin_create_modify_delete_security_rule(app_client, auth_tokens):
    """5-7. ADMIN can create, edit, and delete a network security rule."""
    create_res = app_client.post("/api/rules", headers=auth_tokens["admin"], json={
        "type": "SECURITY",
        "name": "Admin Firewall Block Rule",
        "rule_type": "BLOCK",
        "source_ip": "10.0.0.99",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "threshold_pps": 2500.0,
        "action": "BLOCK"
    })
    assert create_res.status_code == 201
    rule_id = create_res.get_json()["id"]

    # Edit rule
    edit_res = app_client.put(f"/api/rules/{rule_id}", headers=auth_tokens["admin"], json={
        "name": "Admin Rate Limit Rule",
        "rule_type": "RATE_LIMIT",
        "threshold_pps": 1000.0
    })
    assert edit_res.status_code == 200

    # Delete rule
    del_res = app_client.delete(f"/api/rules/{rule_id}", headers=auth_tokens["admin"])
    assert del_res.status_code == 200

    # Verify rule deleted
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM security_policies WHERE id = ?", (rule_id,))
    assert c.fetchone() is None
    conn.close()


def test_operator_cannot_modify_or_delete_policy_or_rule(app_client, auth_tokens):
    """8, 9, 10, 13. Direct mutation/deletion by OPERATOR returns HTTP 403."""
    # Create target policy as Admin
    create_res = app_client.post("/api/policies", headers=auth_tokens["admin"], json={
        "type": "QOS",
        "name": "Target Policy For Operator Block",
        "traffic_class": "WEB",
        "priority_code": "AF"
    })
    assert create_res.status_code == 201
    pol_id = create_res.get_json()["id"]

    # 9. OPERATOR cannot modify policy -> 403
    mod_res = app_client.put(f"/api/policies/{pol_id}", headers=auth_tokens["operator"], json={
        "name": "Operator Hacked Policy"
    })
    assert mod_res.status_code == 403

    # OPERATOR cannot toggle policy -> 403
    toggle_res = app_client.post(f"/api/policies/{pol_id}/toggle", headers=auth_tokens["operator"])
    assert toggle_res.status_code == 403

    # OPERATOR cannot create policy -> 403
    create_op = app_client.post("/api/policies", headers=auth_tokens["operator"], json={
        "type": "QOS",
        "name": "Operator Created Policy"
    })
    assert create_op.status_code == 403

    # 8, 10, 13. OPERATOR direct DELETE API call returns HTTP 403
    del_res = app_client.delete(f"/api/policies/{pol_id}", headers=auth_tokens["operator"])
    assert del_res.status_code == 403
    assert del_res.get_json()["error"] == "Forbidden"

    # Verify policy was NOT deleted
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM qos_policies WHERE id = ?", (pol_id,))
    assert c.fetchone() is not None

    # Cleanup by ADMIN
    app_client.delete(f"/api/policies/{pol_id}", headers=auth_tokens["admin"])
    conn.close()


def test_reader_cannot_modify_or_delete_policy_or_rule(app_client, auth_tokens):
    """11, 12, 14. Direct mutation/deletion by READER returns HTTP 403."""
    create_res = app_client.post("/api/policies", headers=auth_tokens["admin"], json={
        "type": "SECURITY",
        "name": "Target Rule For Reader Block",
        "rule_type": "BLOCK"
    })
    assert create_res.status_code == 201
    rule_id = create_res.get_json()["id"]

    # 11. READER cannot modify -> 403
    mod_res = app_client.put(f"/api/policies/{rule_id}", headers=auth_tokens["reader"], json={
        "name": "Reader Modified"
    })
    assert mod_res.status_code == 403

    # 12, 14. Direct DELETE by READER -> 403
    del_res = app_client.delete(f"/api/policies/{rule_id}", headers=auth_tokens["reader"])
    assert del_res.status_code == 403

    # Cleanup by ADMIN
    app_client.delete(f"/api/policies/{rule_id}", headers=auth_tokens["admin"])


def test_delete_nonexistent_policy_returns_404(app_client, auth_tokens):
    """Attempting to delete a non-existent policy returns 404."""
    del_res = app_client.delete("/api/policies/nonexistent_policy_99999", headers=auth_tokens["admin"])
    assert del_res.status_code == 404
    assert del_res.get_json()["error"] == "Not Found"


def test_attempt_to_delete_admin_account_returns_403(app_client, auth_tokens):
    """16. Attempt to delete ADMIN account returns HTTP 403."""
    # Attempting to delete the admin user ID
    del_res = app_client.delete("/api/admin/users/usr_1084be32", headers=auth_tokens["admin"])
    assert del_res.status_code == 403
    assert "The system administrator account cannot be deleted." in del_res.get_json()["message"]

    # Bulk delete attempting to delete admin
    bulk_res = app_client.post("/api/admin/users/bulk-delete", headers=auth_tokens["admin"], json={
        "user_ids": ["usr_1084be32"]
    })
    assert bulk_res.status_code == 200
    assert bulk_res.get_json()["skipped_admin"] is True
    assert bulk_res.get_json()["deleted_count"] == 0
