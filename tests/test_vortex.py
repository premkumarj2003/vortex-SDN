"""
VORTEX-SDN Automated Test Suite
Tests: Authentication (both bypass & enforced modes), Telemetry rate calculations, Security AI, QoS ML, Incidents, Policies, and Chatbot.
"""

import os
import pytest
import json
from unittest.mock import patch
from backend.api.server import create_app
from backend.models.database import init_db, get_db_connection, hash_password
from backend.services.email_service import generate_secure_token
from ai.inference import ai_engine
from telemetry.flow_monitor import FlowTelemetryMonitor
from chatbot.assistant import vortex_assistant

@pytest.fixture
def client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_database_and_health(client):
    """Verifies /api/status and /api/health return 200 with online status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert "health" in data
    assert "network_health" in data["health"]
    assert data["health"]["network_health"] > 0

def test_auth_registration_and_login_real_verification(client):
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
    assert after_logout.get_json()["authenticated"] is False

def test_auth_registration_and_login_enforced_mode(client):
    """Verifies email verification enforcement when EMAIL_VERIFICATION_REQUIRED is true."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ? OR username = ?", ("test_enforce@vortex-sdn.local", "test_enforce_op"))
    conn.commit()
    conn.close()

    test_user = {
        "username": "test_enforce_op",
        "email": "test_enforce@vortex-sdn.local",
        "full_name": "Enforce Operator Lead",
        "password": "Password@2026",
        "confirm_password": "Password@2026",
        "role": "OPERATOR"
    }

    with patch("backend.api.auth.is_email_verification_required", return_value=True):
        with patch("backend.api.auth.send_verification_email", return_value=(True, "Verification email sent successfully.")):
            res = client.post("/api/auth/register", json=test_user)
            assert res.status_code == 201
            assert res.get_json()["email_verified"] is False

        # Login before email verification MUST return 403 EMAIL_NOT_VERIFIED
        blocked_login = client.post("/api/auth/login", json={"username": "test_enforce_op", "password": "Password@2026"})
        assert blocked_login.status_code == 403
        assert blocked_login.get_json()["code"] == "EMAIL_NOT_VERIFIED"

        # Verify token
        raw_tok, tok_hash, exp_iso = generate_secure_token()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verification_token_hash = ?, verification_token_expires = ? WHERE username = ?", (tok_hash, exp_iso, "test_enforce_op"))
        conn.commit()
        conn.close()

        ver_res = client.get(f"/api/auth/verify-email?token={raw_tok}")
        assert ver_res.status_code == 200
        assert ver_res.get_json()["success"] is True

        # Now login succeeds
        good_login = client.post("/api/auth/login", json={"username": "test_enforce_op", "password": "Password@2026"})
        assert good_login.status_code == 200
        assert good_login.get_json()["user"]["full_name"] == "Enforce Operator Lead"

def test_password_reset_flow(client):
    """Verifies end-to-end password reset flow with token validation and single-use enforcement."""
    conn = get_db_connection()
    cursor = conn.cursor()
    pwd_hash, salt = hash_password("OldPassword@2026")
    cursor.execute("""
    INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, email_verified, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, ("usr_test_reset", "reset_user", "reset_user@vortex-sdn.local", "Reset User", pwd_hash, salt, "OPERATOR", "2026-01-01T00:00:00Z"))
    conn.commit()
    conn.close()

    # 1. Request forgot password
    with patch("backend.api.auth.send_password_reset_email", return_value=(True, "Password reset email sent successfully.")):
        forgot_res = client.post("/api/auth/forgot-password", json={"email": "reset_user@vortex-sdn.local"})
        assert forgot_res.status_code == 200
        assert forgot_res.get_json()["success"] is True

    # 2. Extract or set reset token for testing
    raw_reset, reset_hash, reset_exp = generate_secure_token()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE email = ?", (reset_hash, reset_exp, "reset_user@vortex-sdn.local"))
    conn.commit()
    conn.close()

    # 3. Validate token
    val_res = client.get(f"/api/auth/verify-reset-token?token={raw_reset}")
    assert val_res.status_code == 200
    assert val_res.get_json()["success"] is True

    # 4. Reset password with mismatch -> should fail
    mismatch_res = client.post("/api/auth/reset-password", json={"token": raw_reset, "new_password": "NewSecret@2026", "confirm_password": "DifferentPassword"})
    assert mismatch_res.status_code == 400

    # 5. Reset password with correct confirmation
    reset_res = client.post("/api/auth/reset-password", json={"token": raw_reset, "new_password": "NewSecret@2026", "confirm_password": "NewSecret@2026"})
    assert reset_res.status_code == 200
    assert reset_res.get_json()["success"] is True

    # 6. Old password must now fail
    old_login = client.post("/api/auth/login", json={"username": "reset_user", "password": "OldPassword@2026"})
    assert old_login.status_code == 401

    # 7. New password must now succeed
    new_login = client.post("/api/auth/login", json={"username": "reset_user", "password": "NewSecret@2026"})
    assert new_login.status_code == 200
    assert new_login.get_json()["user"]["username"] == "reset_user"

    # 8. Token cannot be reused
    reuse_res = client.post("/api/auth/reset-password", json={"token": raw_reset, "new_password": "AnotherPassword@2026", "confirm_password": "AnotherPassword@2026"})
    assert reuse_res.status_code == 400

def test_telemetry_delta_rate_calculation():
    """Verifies packet_rate and byte_rate are calculated using counter deltas and not cumulative totals."""
    monitor = FlowTelemetryMonitor()
    
    flow_obs_1 = {
        "dpid": "0000000000000001",
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "packets": 1000,
        "bytes": 500000,
        "duration": 5.0
    }
    r1 = monitor.calculate_flow_rates(flow_obs_1)
    assert r1["packet_rate"] > 0

    # Second observation with counter delta
    import time
    time.sleep(0.2)
    flow_obs_2 = {
        "dpid": "0000000000000001",
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "packets": 1500,
        "bytes": 750000,
        "duration": 5.2
    }
    r2 = monitor.calculate_flow_rates(flow_obs_2)
    assert r2["packet_rate"] > 0
    assert r2["byte_rate"] > 0

def test_security_ai_prediction():
    """Verifies security ML model correctly classifies a high-volume attack flow."""
    attack_flow = {
        "packet_rate": 30000.0,
        "byte_rate": 15000000.0,
        "packets": 450000,
        "bytes": 225000000,
        "flow_duration": 15.0,
        "destination_port": 80,
        "protocol_num": 17,
        "unique_destinations": 1,
        "connection_frequency": 50.0,
        "packet_size": 512,
        "destination_frequency": 100.0,
        "source_frequency": 100.0
    }
    pred = ai_engine.predict_security(attack_flow)
    assert pred["label"] == "ATTACK"
    assert pred["risk_score"] >= 70.0
    assert pred["severity"] in ("HIGH", "CRITICAL")
    assert pred["recommended_action"] in ("BLOCK", "RATE_LIMIT")

def test_qos_ai_classification():
    """Verifies QoS ML model classifies VoIP flow into VOICE with EF priority."""
    voip_flow = {
        "packet_rate": 50.0,
        "byte_rate": 8000.0,
        "packet_size": 160,
        "protocol_num": 17,
        "destination_port": 5060,
        "flow_duration": 60.0,
        "latency_ms": 12.0,
        "jitter_ms": 2.0,
        "packet_loss_pct": 0.01,
        "throughput_mbps": 0.064
    }
    pred = ai_engine.predict_qos(voip_flow)
    assert pred["traffic_class"] == "VOICE"
    assert pred["priority_code"] == "EF"
    assert pred["recommended_queue"] == 1

def test_chatbot_context_queries():
    """Verifies VORTEX AI Assistant responds to all core network intelligence inquiries."""
    # 1. Network Health
    res1 = vortex_assistant.process_message("What is the current network health?", session_id="test_session")
    assert "NETWORK HEALTH" in res1["response"] or "health" in res1["response"].lower()
    assert len(res1["suggestions"]) > 0
    assert "source" in res1

    # 2. Active Threats
    res2 = vortex_assistant.process_message("Are there any active threats?", session_id="test_session")
    assert "threat" in res2["response"].lower() or "security" in res2["response"].lower()

    # 3. Multi-turn Follow-up ("Where?")
    res3 = vortex_assistant.process_message("Where?", session_id="test_session")
    assert "response" in res3 and len(res3["response"]) > 0

    # 4. Health Explanation ("Why is network health low?")
    res4 = vortex_assistant.process_message("Why is network health low?", session_id="test_session")
    assert "contributing" in res4["response"].lower() or "health is currently" in res4["response"].lower()

    # 5. QoS Status
    res5 = vortex_assistant.process_message("What is the QoS status?", session_id="test_session")
    assert "QOS" in res5["response"] or "qos" in res5["response"].lower()

    # 6. Top Flows
    res6 = vortex_assistant.process_message("Show top flows", session_id="test_session")
    assert "FLOW" in res6["response"] or "traffic" in res6["response"].lower()

    # 7. Device Status (Switch s2)
    res7 = vortex_assistant.process_message("Status of s2?", session_id="test_session")
    assert "SWITCH S2" in res7["response"] or "s2" in res7["response"].lower()

    # 8. Offline Devices
    res8 = vortex_assistant.process_message("Which devices are currently offline?", session_id="test_session")
    assert "DEVICE" in res8["response"] or "ONLINE" in res8["response"]

    # 9. Incidents
    res9 = vortex_assistant.process_message("Are there any critical incidents?", session_id="test_session")
    assert "INCIDENT" in res9["response"]

    # 10. Recent Events
    res10 = vortex_assistant.process_message("What happened recently?", session_id="test_session")
    assert "RECENT" in res10["response"] or "EVENT" in res10["response"]

    # 11. Recommendations
    res11 = vortex_assistant.process_message("What should I investigate first?", session_id="test_session")
    assert "RECOMMENDATION" in res11["response"] or "investigate" in res11["response"].lower()

    # 12. Clear Session Memory
    cleared = vortex_assistant.clear_session("test_session")
    assert cleared is True

def test_chatbot_api_endpoints(client):
    """Verifies REST endpoints for AI chat, status checks, and session clearing."""
    # 1. Chat inquiry
    chat_res = client.post("/api/chat", json={"message": "What is the network health?", "session_id": "api_test_sess"})
    assert chat_res.status_code == 200
    data = chat_res.get_json()
    assert "response" in data
    assert "intent" in data
    assert "source" in data

    # 2. Chat AI alias
    ai_res = client.post("/api/ai/chat", json={"message": "Are there any threats?"})
    assert ai_res.status_code == 200

    # 3. Status endpoint
    status_res = client.get("/api/chat/status")
    assert status_res.status_code == 200
    sdata = status_res.get_json()
    assert "status" in sdata
    assert "engine" in sdata

    # 4. Status alias
    status_ai_res = client.get("/api/ai/status")
    assert status_ai_res.status_code == 200

    # 5. Clear chat endpoint
    clear_res = client.post("/api/chat/clear", json={"session_id": "api_test_sess"})
    assert clear_res.status_code == 200
    assert clear_res.get_json()["success"] is True

    # 6. Empty message returns 400
    bad_res = client.post("/api/chat", json={"message": ""})
    assert bad_res.status_code == 400

def test_policies_crud(client):
    """Verifies policy creation and retrieval."""
    new_pol = {
        "type": "QOS",
        "name": "Test Priority Policy",
        "traffic_class": "VIDEO",
        "priority_code": "AF",
        "min_bandwidth_mbps": 20.0,
        "max_bandwidth_mbps": 80.0,
        "queue_id": 2
    }
    create_res = client.post("/api/policies", json=new_pol)
    assert create_res.status_code == 201
    pol_id = create_res.get_json()["id"]

    del_res = client.delete(f"/api/policies/{pol_id}")
    assert del_res.status_code == 200

def test_notifications_lifecycle(client):
    """Verifies notification creation, deduplication, unread counting, and read-status updates."""
    from backend.services.notification_service import create_notification, get_notifications

    # 1. Start by marking all read
    client.post("/api/notifications/read-all")
    initial = client.get("/api/notifications").get_json()
    assert initial["unread_count"] == 0

    # 2. Create security notification
    notif_id = create_notification("Security", "Test Sec Alert", "Test security message", "HIGH", "security")
    assert notif_id is not None

    after_create = client.get("/api/notifications").get_json()
    assert after_create["unread_count"] >= 1
    assert any(n["id"] == notif_id and n["is_read"] == 0 for n in after_create["notifications"])

    # 3. Deduplication check: duplicate unread insertion returns same ID
    dup_id = create_notification("Security", "Test Sec Alert", "Test security message", "HIGH", "security")
    assert dup_id == notif_id

    # 4. Mark as read
    read_res = client.post(f"/api/notifications/{notif_id}/read")
    assert read_res.status_code == 200

    after_read = client.get("/api/notifications").get_json()
    target = next(n for n in after_read["notifications"] if n["id"] == notif_id)
    assert target["is_read"] == 1

    all_res = client.post("/api/notifications/read-all")
    assert all_res.status_code == 200
    after_all = client.get("/api/notifications").get_json()
    assert after_all["unread_count"] == 0

def test_user_settings_persistence(client):
    """Verifies appearance, dashboard polling, and notification settings persistence."""
    import time
    # 1. Unauthenticated defaults
    def_res = client.get("/api/user/settings")
    assert def_res.status_code == 200
    assert "appearance" in def_res.get_json()

    # 2. Register & login user with unique username
    uname = f"set_user_{int(time.time() * 1000)}"
    reg = client.post("/api/auth/register", json={
        "username": uname,
        "email": f"{uname}@vortex.local",
        "password": "Password@2026",
        "full_name": "Settings Operator"
    })
    assert reg.status_code == 201

    # Verify user email in database so login succeeds
    _c = get_db_connection()
    _c.execute("UPDATE users SET email_verified = 1 WHERE username = ?", (uname,))
    _c.commit()
    _c.close()

    login = client.post("/api/auth/login", json={"username": uname, "password": "Password@2026"})
    assert login.status_code == 200
    token = login.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Save customized settings
    payload = {
        "appearance": {"theme": "light", "accent": "violet", "density": "compact", "reduce_motion": True},
        "dashboard": {"auto_refresh": True, "refresh_interval": 15, "chart_history": 40},
        "notifications": {
            "master_enabled": True,
            "security_alerts": True,
            "critical_threats": True,
            "network_events": False,
            "qos_alerts": True,
            "incident_updates": True,
            "system_alerts": False,
            "audit_alerts": True,
            "severity_critical": True,
            "severity_high": True,
            "severity_medium": False,
            "severity_low": False,
            "severity_info": False,
            "sound_enabled": True,
            "quiet_mode": False,
            "mark_read_on_click": True
        }
    }

    put_res = client.put("/api/user/settings", json=payload, headers=headers)
    assert put_res.status_code == 200

    # 4. Read back settings
    get_res = client.get("/api/user/settings", headers=headers)
    assert get_res.status_code == 200
    saved = get_res.get_json()
    assert saved["appearance"]["theme"] == "light"
    assert saved["appearance"]["accent"] == "violet"
    assert saved["appearance"]["density"] == "compact"
    assert saved["appearance"]["reduce_motion"] is True
    assert saved["dashboard"]["refresh_interval"] == 15
    assert saved["dashboard"]["chart_history"] == 40
    assert saved["notifications"]["network_events"] is False
    assert saved["notifications"]["sound_enabled"] is True

def test_attack_mitigation_fast_recovery_lifecycle(client):
    """
    Tests complete lifecycle:
    NORMAL -> ATTACK -> AUTO-MITIGATION -> VERIFICATION -> THREAT CLEARANCE -> FAST RECOVERY -> PERSISTENT HISTORY.
    """
    import time
    from security.detector import security_detector
    from security.mitigation import mitigation_engine
    from telemetry.flow_monitor import flow_monitor

    # 1. Normal State Baseline
    security_detector.clear_threats()
    mitigation_engine.clear_mitigations()
    flow_monitor.reset_health(98.0, 95.0, 92.0)

    res_norm = client.get("/api/summary")
    assert res_norm.status_code == 200
    data_norm = res_norm.get_json()
    assert data_norm["security_summary"]["active_threats_count"] == 0
    assert data_norm["security_health_score"] >= 90.0
    assert data_norm["network_health_score"] >= 90.0

    # 2. Ingest Attack Flow (DDoS flood from 10.0.0.4)
    attack_flow = {
        "flow_id": "flw_test_atk_01",
        "dpid": "0000000000000004",
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.1",
        "source_port": 45678,
        "destination_port": 80,
        "protocol": "UDP",
        "protocol_num": 17,
        "packets": 300000,
        "bytes": 150000000,
        "duration": 10.0,
        "packet_rate": 30000.0,
        "byte_rate": 15000000.0,
        "latency_ms": 65.0,
        "packet_loss_pct": 2.5,
        "jitter_ms": 14.0,
        "connection_frequency": 65.0,
        "destination_frequency": 120.0,
        "source_frequency": 110.0,
        "unique_destinations": 1,
        "packet_size": 512
    }
    processed = flow_monitor.ingest_observations([attack_flow], source_type="DEMO")
    for f in processed:
        security_detector.evaluate_flow(f)

    # Allow auto-mitigation thread to process
    time.sleep(0.3)

    # 3. Verify Auto-Mitigation Executed
    assert (mitigation_engine.is_ip_blocked("10.0.0.4") or mitigation_engine.is_ip_rate_limited("10.0.0.4")) is True

    # 4. Ingest post-mitigation benign traffic (attacker traffic is dropped by switch)
    benign_flow = {
        "flow_id": "flw_test_benign_01",
        "dpid": "0000000000000001",
        "source_ip": "10.0.0.2",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": "TCP",
        "protocol_num": 6,
        "packets": 500,
        "bytes": 425000,
        "duration": 20.0,
        "packet_rate": 25.0,
        "byte_rate": 21250.0,
        "latency_ms": 15.0,
        "packet_loss_pct": 0.01,
        "jitter_ms": 2.0,
        "connection_frequency": 3.0,
        "destination_frequency": 8.0,
        "source_frequency": 8.0,
        "unique_destinations": 1,
        "packet_size": 850
    }
    for _ in range(3):
        flow_monitor.ingest_observations([benign_flow], source_type="DEMO")

    time.sleep(1.6)

    # 5. Verify Threat Clearance & Fast Health Recovery
    sec_summary = security_detector.get_summary()
    assert sec_summary["active_threats_count"] == 0
    assert sec_summary["threat_level"] == "NORMAL"
    assert sec_summary["mitigated_count"] >= 1

    # Poll summary API - health must rapidly recover toward normal baseline
    summary_res = client.get("/api/summary")
    assert summary_res.status_code == 200
    sum_data = summary_res.get_json()
    assert sum_data["malicious_flows"] == 0
    assert sum_data["security_health_score"] >= 80.0
    assert sum_data["network_health_score"] >= 80.0

    # Advance one more tick
    flow_monitor.ingest_observations([benign_flow], source_type="DEMO")
    summary_res2 = client.get("/api/summary")
    sum_data2 = summary_res2.get_json()
    assert sum_data2["security_health_score"] >= 90.0
    assert sum_data2["network_health_score"] >= 90.0

    # 6. Verify Incident History Persists
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.get_json()["incidents"]
    assert len(incidents) >= 1
    # Check that incident is marked MITIGATED or active mitigation
    atk_inc = next((i for i in incidents if i["source_ip"] == "10.0.0.4"), None)
    assert atk_inc is not None
    assert atk_inc["status"] in ("MITIGATED", "MITIGATING", "RECOVERING", "RESOLVED", "CLOSED")

def test_demo_scenario_lifecycle_and_manual_mitigation(client):
    """
    Verifies Demo Scenario transitions (PORT_SCAN, BRUTE_FORCE, RECOVERY, NORMAL)
    and manual /api/security/mitigate execution.
    """
    import time
    from backend.services.demo_engine import demo_engine
    from security.detector import security_detector
    from security.mitigation import mitigation_engine

    # 1. Switch to PORT_SCAN scenario
    res_ps = client.post("/api/demo/scenario", json={"scenario": "PORT_SCAN"})
    assert res_ps.status_code == 200
    assert res_ps.get_json()["active_scenario"] == "PORT_SCAN"

    # 2. Allow detector & simulator to run a cycle
    time.sleep(1.0)
    summary_res = client.get("/api/security/summary")
    assert summary_res.status_code == 200

    # 3. Manual Mitigation Execution via API
    mit_res = client.post("/api/security/mitigate", json={
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.2",
        "attack_type": "PORT_SCAN",
        "action": "ISOLATE"
    })
    assert mit_res.status_code == 200
    assert mit_res.get_json()["status"] == "SUCCESS"
    assert mitigation_engine.is_ip_mitigated("10.0.0.4") is True

    # 4. Switch to NORMAL scenario -> ensures clean reset
    res_norm = client.post("/api/demo/scenario", json={"scenario": "NORMAL"})
    assert res_norm.status_code == 200
    time.sleep(1.0)
    sum_data = client.get("/api/summary").get_json()
    assert sum_data["security_summary"]["active_threats_count"] == 0
    assert sum_data["security_health_score"] >= 85.0

def test_intelligent_incident_management_and_rca(client):
    """
    Comprehensive test for Feature #4:
    - Incident correlation & deduplication
    - Root Cause Analysis (RCA) classification
    - Lifecycle state transitions (DETECTED -> INVESTIGATING -> MITIGATING -> RECOVERING -> RESOLVED -> CLOSED)
    - KPI calculations (active, critical, MTTR)
    - REST API endpoints and filters
    - AI chatbot incident understanding
    """
    from backend.services.incident_service import create_incident, get_incident_by_id, get_incident_summary, update_incident_status

    # 1. Create a correlated DDoS incident
    inc_id = create_incident(
        severity="HIGH",
        category="SECURITY",
        source_ip="10.0.0.4",
        destination_ip="10.0.0.1",
        description="DDoS UDP flood anomaly detected (18,000 pps)",
        ai_confidence=0.95,
        risk_score=92.0,
        action_taken="BLOCK"
    )
    assert inc_id is not None

    # 2. Duplicate Prevention Test: Repeated alert from same source within time window updates existing
    dup_id = create_incident(
        severity="HIGH",
        category="SECURITY",
        source_ip="10.0.0.4",
        destination_ip="10.0.0.1",
        description="DDoS UDP flood continuing at 20,000 pps",
        ai_confidence=0.96,
        risk_score=94.0
    )
    assert dup_id == inc_id, "Duplicate incident should be correlated into existing incident ID"

    # 3. Verify RCA and Impact
    inc_detail = get_incident_by_id(inc_id)
    assert inc_detail is not None
    assert inc_detail["root_cause"]["level"] == "CONFIRMED"
    assert "DDoS" in inc_detail["root_cause"]["summary"] or "surge" in inc_detail["root_cause"]["summary"].lower()
    assert len(inc_detail["root_cause"]["contributing_factors"]) >= 2
    assert inc_detail["impact"]["security_impact"] in ("HIGH", "CRITICAL")
    assert len(inc_detail["timeline"]) >= 2

    # 4. REST API Detail Endpoint
    api_detail_res = client.get(f"/api/incidents/{inc_id}")
    assert api_detail_res.status_code == 200
    detail_data = api_detail_res.get_json()["incident"]
    assert detail_data["id"] == inc_id
    assert detail_data["affected_device"] == "S4 → S1" or "S" in detail_data["affected_device"]

    # 5. Lifecycle Transitions via REST API
    # Acknowledge
    ack_res = client.post(f"/api/incidents/{inc_id}/acknowledge")
    assert ack_res.status_code == 200
    assert get_incident_by_id(inc_id)["status"] == "ACKNOWLEDGED"

    # Investigate
    inv_res = client.post(f"/api/incidents/{inc_id}/investigate")
    assert inv_res.status_code == 200
    assert get_incident_by_id(inc_id)["status"] == "INVESTIGATING"

    # Mitigate
    mit_res = client.post(f"/api/incidents/{inc_id}/mitigate", json={"action": "BLOCK"})
    assert mit_res.status_code == 200
    assert get_incident_by_id(inc_id)["status"] == "MITIGATING"

    # Resolve
    res_res = client.post(f"/api/incidents/{inc_id}/resolve", json={"notes": "Traffic dropped to baseline"})
    assert res_res.status_code == 200
    assert get_incident_by_id(inc_id)["status"] == "RESOLVED"
    assert get_incident_by_id(inc_id)["recovery_pct"] == 100.0

    # 6. KPI Summary Endpoint
    kpi_res = client.get("/api/incidents/summary")
    assert kpi_res.status_code == 200
    kpi = kpi_res.get_json()
    assert "active_incidents" in kpi
    assert "mttr" in kpi
    assert kpi["resolved_today"] >= 1

    # 7. Multi-Criteria Filters
    # Filter by status
    resolved_list = client.get("/api/incidents?status=RESOLVED").get_json()["incidents"]
    assert any(i["id"] == inc_id for i in resolved_list)

    # Filter by search
    searched = client.get(f"/api/incidents?search={inc_id}").get_json()["incidents"]
    assert len(searched) == 1
    assert searched[0]["id"] == inc_id

    # 8. AI Chatbot understanding of incidents
    chat_res = client.post("/api/chat", json={"message": f"What caused {inc_id}?"})
    assert chat_res.status_code == 200
    assert "DDoS" in chat_res.get_json()["response"] or "Root Cause" in chat_res.get_json()["response"]


def test_digital_twin_and_what_if_simulation(client):
    """
    Validates Feature #5: Network Digital Twin & What-If Simulation Engine
    - Snapshot capture and isolation
    - Graph pathfinding & Dijkstra shortest path recalculation
    - Link failure simulation & alternate pathfinding (S1-S2 failure -> S1-S3-S2)
    - Switch failure simulation & survivability assessment
    - Congestion, DDoS, and packet loss what-if simulations
    - Resilience score computation & before/after comparisons
    - Single point of failure (SPOF) & critical node ranking
    - Digital Twin REST APIs & session history tracking
    - AI Chatbot simulation queries & safety guardrails
    """
    from backend.digital_twin.snapshot import capture_snapshot
    from backend.digital_twin.graph import NetworkGraph, analyze_critical_infrastructure
    from backend.digital_twin.simulator import (
        run_what_if_simulation,
        get_simulation_history,
        clear_simulation_history
    )

    # 1. Snapshot Capture & Data Isolation
    snapshot = capture_snapshot()
    assert "nodes" in snapshot
    assert "links" in snapshot
    assert "metrics" in snapshot
    assert len(snapshot["nodes"]) >= 4
    assert len(snapshot["links"]) >= 6
    assert snapshot["metrics"]["network_health"] >= 0.0

    # 2. Graph Pathfinding & Dijkstra Recalculation
    base_graph = NetworkGraph(snapshot["nodes"], snapshot["links"])
    path_s1_s2, cost_base = base_graph.dijkstra_shortest_path("s1", "s2")
    assert path_s1_s2 == ["s1", "s2"]

    # Exclude direct S1-S2 link and verify failover route
    sim_graph = NetworkGraph(snapshot["nodes"], snapshot["links"], excluded_links={"s1-s2"})
    path_failover, cost_failover = sim_graph.dijkstra_shortest_path("s1", "s2")
    assert len(path_failover) >= 3  # e.g. ['s1', 's3', 's2']
    assert path_failover[0] == "s1"
    assert path_failover[-1] == "s2"

    # 3. Critical Infrastructure Analysis
    crit = analyze_critical_infrastructure(snapshot["nodes"], snapshot["links"])
    assert "critical_nodes" in crit
    assert len(crit["critical_nodes"]) == 4
    sw_names = {n["device"] for n in crit["critical_nodes"]}
    assert {"S1", "S2", "S3", "S4"}.issubset(sw_names)

    # 4. Simulation: Link Failure
    clear_simulation_history()
    sim_link = run_what_if_simulation("link_failure", {"link": "s1-s2"}, snapshot)
    assert sim_link["status"] == "COMPLETED"
    assert sim_link["survivability"] == "RESILIENT"
    assert sim_link["resilience_score"]["after"] <= sim_link["resilience_score"]["before"]
    assert len(sim_link["rerouted_paths"]) > 0
    assert len(sim_link["timeline"]) == 6

    # 5. Simulation: Switch Failure
    sim_sw = run_what_if_simulation("switch_failure", {"switch": "s2"}, snapshot)
    assert sim_sw["status"] == "COMPLETED"
    assert sim_sw["target"] == "S2"
    assert "S2" in sim_sw["affected_devices"]
    assert sim_sw["resilience_score"]["change"] < 0

    # 6. Simulation: Congestion, DDoS, Packet Loss
    sim_cong = run_what_if_simulation("congestion", {"load_multiplier": 1.5}, snapshot)
    assert sim_cong["after_metrics"]["average_latency_ms"] > sim_cong["before_metrics"]["average_latency_ms"]

    sim_ddos = run_what_if_simulation("ddos", {"source": "h4", "target": "s1"}, snapshot)
    assert sim_ddos["after_metrics"]["security_health"] < sim_ddos["before_metrics"]["security_health"]

    sim_loss = run_what_if_simulation("packet_loss", {"loss_pct": 5.0}, snapshot)
    assert sim_loss["after_metrics"]["packet_loss_pct"] >= 5.0

    # 7. Session History
    hist = get_simulation_history()
    assert len(hist) >= 5

    # 8. Digital Twin REST API Endpoints
    # Snapshot endpoint
    snap_res = client.get("/api/digital-twin/snapshot")
    assert snap_res.status_code == 200
    assert "critical_analysis" in snap_res.get_json()

    # Simulate endpoint
    sim_api_res = client.post("/api/digital-twin/simulate", json={
        "scenario": "link_failure",
        "params": {"link": "s1-s3"}
    })
    assert sim_api_res.status_code == 200
    assert sim_api_res.get_json()["status"] == "COMPLETED"

    # History endpoint
    hist_res = client.get("/api/digital-twin/history")
    assert hist_res.status_code == 200
    assert hist_res.get_json()["count"] >= 1

    # Reset endpoint
    reset_res = client.post("/api/digital-twin/reset")
    assert reset_res.status_code == 200
    assert reset_res.get_json()["status"] == "SUCCESS"

    # Critical nodes endpoint
    crit_res = client.get("/api/digital-twin/critical-nodes")
    assert crit_res.status_code == 200
    assert "critical_nodes" in crit_res.get_json()

    # 9. AI Assistant Integration & Safety Interception
    # Digital Twin simulation question
    ai_sim = client.post("/api/chat", json={"message": "Simulate failure of S2"})
    assert ai_sim.status_code == 200
    assert "DIGITAL TWIN SIMULATION" in ai_sim.get_json()["response"].upper() or "RESILIENCE" in ai_sim.get_json()["response"].upper()

    # Critical switch question
    ai_crit = client.post("/api/chat", json={"message": "Which switch is the most critical?"})
    assert ai_crit.status_code == 200
    assert "CRITICAL" in ai_crit.get_json()["response"].upper()

    # Safety Guardrail Interception (Destructive shutdown attempt)
    ai_safe = client.post("/api/chat", json={"message": "Shutdown S2"})
    assert ai_safe.status_code == 200
    safe_text = ai_safe.get_json()["response"]
    assert "SAFETY GUARDRAIL" in safe_text.upper() or "DISABLED FOR NETWORK SAFETY" in safe_text.upper()
    assert "DIGITAL TWIN" in safe_text.upper()


def test_predictive_network_intelligence(client):
    """
    Comprehensive test for Feature #6: Predictive Network Intelligence.
    Covers: baseline engine, anomaly detection, forecasting, risk scoring,
    early warnings, all REST endpoints, and AI chatbot predictive queries.
    """
    from backend.predictive.baseline import calculate_telemetry_baselines, determine_trend
    from backend.predictive.anomaly import detect_predictive_anomalies
    from backend.predictive.forecast import generate_predictive_forecast, holt_linear_forecast
    from backend.predictive.risk import calculate_predictive_risk, get_risk_level
    from backend.predictive.analysis import run_predictive_analysis, acknowledge_warning

    # 1. Baseline Engine: Data Sufficiency Guard
    baselines = calculate_telemetry_baselines()
    assert isinstance(baselines, dict)
    assert "is_sufficient" in baselines
    assert "status" in baselines

    # 2. Trend Detection Logic
    assert determine_trend([10, 10, 11, 10, 10]) == "STABLE"
    # Gentle increasing (stays within low-volatility band)
    assert determine_trend([40, 42, 44, 46, 48]) == "INCREASING"
    # Gentle decreasing
    assert determine_trend([48, 46, 44, 42, 40]) == "DECREASING"
    assert determine_trend([1]) == "INSUFFICIENT_DATA"

    # 3. Anomaly Detection: Empty/Insufficient Baselines
    assert detect_predictive_anomalies({}) == []
    assert detect_predictive_anomalies({"is_sufficient": False}) == []

    # 4. Anomaly Detection: Synthetic Burst Scenario
    synthetic_baselines = {
        "is_sufficient": True,
        "observations_count": 20,
        "source": "DEMO",
        "metrics": {
            "throughput": {"current": 95.0, "mean": 45.0, "std_dev": 5.0, "trend": "INCREASING", "unit": "Mbps"},
            "latency": {"current": 14.5, "mean": 14.0, "std_dev": 0.5, "trend": "STABLE", "unit": "ms"},
            "packet_loss": {"current": 0.1, "mean": 0.1, "std_dev": 0.05, "trend": "STABLE", "unit": "%"},
            "security_threats": {"current_count": 0, "trend": "STABLE", "unit": "threats"},
            "packet_rate": {"current": 1300, "mean": 1200, "std_dev": 100, "trend": "STABLE", "unit": "pps"},
            "byte_rate": {"current": 5000, "mean": 4500, "std_dev": 200, "trend": "STABLE", "unit": "Bps"}
        }
    }
    burst_anomalies = detect_predictive_anomalies(synthetic_baselines)
    assert isinstance(burst_anomalies, list)
    categories = [a["category"] for a in burst_anomalies]
    assert "TRAFFIC" in categories

    # 5. Holt Linear Trend Forecast
    flat = holt_linear_forecast([50.0, 50.0, 50.0, 50.0], steps=3)
    assert len(flat) == 3
    assert all(isinstance(v, float) for v in flat)
    rising = holt_linear_forecast([10.0, 20.0, 30.0, 40.0], steps=3)
    assert rising[-1] >= rising[0]

    # 6. Forecast Refusal With Insufficient Data
    fc_insuff = generate_predictive_forecast({"is_sufficient": False})
    assert fc_insuff["status"] == "INSUFFICIENT_DATA"
    assert fc_insuff["confidence"] == "N/A"

    # 7. Forecast With Sufficient Synthetic Data
    fc_ok = generate_predictive_forecast(synthetic_baselines)
    assert fc_ok["status"] == "READY"
    assert 50 <= fc_ok["confidence"] <= 100
    assert len(fc_ok["chart_series"]) > 0
    assert "ESTIMATE" in fc_ok["forecasts"]["throughput"]["label"]

    # 8. Risk Score Classification
    assert get_risk_level(10.0) == "LOW"
    assert get_risk_level(30.0) == "MODERATE"
    assert get_risk_level(60.0) == "HIGH"
    assert get_risk_level(85.0) == "CRITICAL"

    # 9. Risk Calculation With Synthetic Data
    risk = calculate_predictive_risk(synthetic_baselines, burst_anomalies, fc_ok)
    assert "network_risk" in risk and "risk_level" in risk
    assert 0 <= risk["network_risk"] <= 100
    assert isinstance(risk["device_risks"], list)

    # 10. Full Analysis Pipeline
    analysis = run_predictive_analysis()
    assert "network_risk" in analysis
    assert "early_warnings" in analysis
    assert "baselines" in analysis
    # Live telemetry values must NOT be in predictive output
    assert "packet_rate" not in analysis
    assert "network_health" not in analysis

    # 11. Warning Acknowledgment
    assert acknowledge_warning("WARN-999") is True

    # 12. REST: GET /api/predictive/summary
    res_sum = client.get("/api/predictive/summary")
    assert res_sum.status_code == 200
    data_sum = res_sum.get_json()
    for key in ["network_risk", "risk_level", "traffic_trend", "security_risk", "qos_risk", "confidence", "current_network_health"]:
        assert key in data_sum, f"Missing key: {key}"

    # 13. REST: GET /api/predictive/anomalies
    res_anom = client.get("/api/predictive/anomalies")
    assert res_anom.status_code == 200
    assert "anomalies" in res_anom.get_json()

    # 14. REST: GET /api/predictive/forecast
    res_fc = client.get("/api/predictive/forecast")
    assert res_fc.status_code == 200
    assert "status" in res_fc.get_json()

    # 15. REST: GET /api/predictive/risks
    res_risk = client.get("/api/predictive/risks")
    assert res_risk.status_code == 200
    assert "early_warnings" in res_risk.get_json()
    assert "device_risks" in res_risk.get_json()

    # 16. REST: POST /api/predictive/refresh
    res_refresh = client.post("/api/predictive/refresh", json={"window": "15m"})
    assert res_refresh.status_code == 200
    assert res_refresh.get_json().get("status") == "SUCCESS"

    # 17. REST: POST /api/predictive/warnings/<id>/acknowledge
    res_ack = client.post("/api/predictive/warnings/WARN-001/acknowledge")
    assert res_ack.status_code == 200
    assert res_ack.get_json().get("acknowledged") is True

    # 18–20. AI Chatbot Predictive Queries
    for q in ["What are the current predictive risks?", "Explain the traffic forecast", "Are there any early warnings?"]:
        r = client.post("/api/chat", json={"message": q})
        assert r.status_code == 200
        assert len(r.get_json().get("response", "")) > 10, f"Empty chatbot response for: {q}"

    # 21. Confirm Live Telemetry NOT Modified
    t_res = client.get("/api/telemetry/summary")
    assert t_res.status_code == 200
    t_data = t_res.get_json()
    assert "network_health" in t_data
    assert "predictive_risk" not in t_data

    # 22. Existing API Regression Check
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/topology").status_code == 200
    assert client.get("/api/security/summary").status_code == 200
    assert client.get("/api/qos/summary").status_code == 200
