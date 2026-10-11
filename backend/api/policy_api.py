"""
VORTEX-SDN Policy & Rule Management REST API (CRUD for QoS and Security Policies)
Strictly enforces ADMIN-ONLY authorization on all policy and rule mutation endpoints:
- Create policy / rule
- Modify / Edit policy / rule
- Delete policy / rule
- Enable / Disable policy / rule
- Change priority / action / rate thresholds
OPERATOR and READER accounts have strictly VIEW-ONLY access.
Any direct mutation/deletion attempt by OPERATOR or READER returns HTTP 403 Forbidden.
"""

import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
from backend.models.database import get_db_connection
from backend.services.audit_service import log_audit_event
from backend.api.auth import get_current_user, require_admin

policy_bp = Blueprint("policies", __name__)


@policy_bp.route("/api/policies", methods=["GET"])
@policy_bp.route("/api/rules", methods=["GET"])
def get_all_policies():
    """Returns all QoS and Security policies for dashboard view. Read-only access permitted."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM qos_policies ORDER BY created_at DESC")
    qos_pols = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM security_policies ORDER BY created_at DESC")
    sec_pols = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({
        "qos_policies": qos_pols,
        "security_policies": sec_pols,
        "total_qos": len(qos_pols),
        "total_security": len(sec_pols)
    }), 200


@policy_bp.route("/api/policies/<policy_id>", methods=["GET"])
@policy_bp.route("/api/rules/<policy_id>", methods=["GET"])
def get_single_policy(policy_id):
    """
    Returns the real database record for a single QoS policy or Security rule.
    Accessible to all authenticated users for viewing; used by Edit modal to load real values.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM qos_policies WHERE id = ?", (policy_id,))
    qos_row = cursor.fetchone()
    if qos_row:
        conn.close()
        item = dict(qos_row)
        item["type"] = "QOS"
        return jsonify({"status": "SUCCESS", "policy": item}), 200

    cursor.execute("SELECT * FROM security_policies WHERE id = ?", (policy_id,))
    sec_row = cursor.fetchone()
    conn.close()
    if sec_row:
        item = dict(sec_row)
        item["type"] = "SECURITY"
        return jsonify({"status": "SUCCESS", "policy": item}), 200

    return jsonify({"error": "Not Found", "message": f"Policy or rule {policy_id} not found."}), 404


@policy_bp.route("/api/policies", methods=["POST"])
@policy_bp.route("/api/rules", methods=["POST"])
@require_admin
def create_policy():
    """
    Creates a new QoS policy or Security firewall/rate-limit rule with strict validation.
    ADMIN ONLY: Any attempt by OPERATOR or READER returns HTTP 403.
    """
    user = get_current_user()
    username = user.get("username", "ADMIN") if user else "ADMIN"
    now = datetime.now(timezone.utc).isoformat()

    data = request.get_json() or {}
    pol_type = str(data.get("type", "QOS")).strip().upper()
    if pol_type not in ("QOS", "SECURITY"):
        return jsonify({"error": "Validation Error", "message": "Policy type must be either QOS or SECURITY."}), 400

    name = str(data.get("name", "")).strip()
    if not name or len(name) < 2 or len(name) > 120:
        return jsonify({"error": "Validation Error", "message": "Policy name is required and must be between 2 and 120 characters."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Duplicate name check
    if pol_type == "QOS":
        cursor.execute("SELECT id FROM qos_policies WHERE LOWER(name) = LOWER(?)", (name,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Duplicate Policy", "message": f"A QoS policy named '{name}' already exists."}), 400
    else:
        cursor.execute("SELECT id FROM security_policies WHERE LOWER(name) = LOWER(?)", (name,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Duplicate Policy", "message": f"A security rule named '{name}' already exists."}), 400

    is_active_val = 1 if data.get("is_active", 1) in (1, "1", True, "true") else 0

    if pol_type == "QOS":
        pol_id = f"qos_pol_{uuid.uuid4().hex[:6]}"
        traffic_class = str(data.get("traffic_class", "WEB")).strip().upper()
        allowed_classes = ('VOICE', 'VIDEO', 'CRITICAL_APPLICATION', 'WEB', 'FILE_TRANSFER', 'EMAIL', 'P2P', 'BEST_EFFORT')
        if traffic_class not in allowed_classes:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Traffic class must be one of: {', '.join(allowed_classes)}."}), 400

        priority_code = str(data.get("priority_code", "AF")).strip().upper()
        if priority_code not in ('EF', 'AF', 'BE'):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Priority code must be EF, AF, or BE."}), 400

        try:
            min_bw = float(data.get("min_bandwidth_mbps", 10.0))
            max_bw = float(data.get("max_bandwidth_mbps", 50.0))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Bandwidth values must be valid numbers."}), 400

        if min_bw < 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Minimum bandwidth cannot be negative."}), 400
        if max_bw <= 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Maximum bandwidth must be greater than 0 Mbps."}), 400
        if min_bw > max_bw:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Minimum bandwidth cannot exceed maximum bandwidth."}), 400

        try:
            queue_id = int(data.get("queue_id", 2))
            dscp_mark = int(data.get("dscp_mark", 26))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Queue ID and DSCP mark must be integers."}), 400

        if queue_id < 0 or queue_id > 8:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Queue ID must be between 0 and 8."}), 400
        if dscp_mark < 0 or dscp_mark > 63:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "DSCP mark must be between 0 and 63."}), 400

        match_criteria = str(data.get("match_criteria", "Custom Criteria")).strip() or "Custom Criteria"
        action = str(data.get("action", "ENQUEUE")).strip() or "ENQUEUE"

        cursor.execute("""
        INSERT INTO qos_policies (id, name, traffic_class, priority_code, min_bandwidth_mbps, max_bandwidth_mbps, queue_id, dscp_mark, match_criteria, action, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pol_id,
            name,
            traffic_class,
            priority_code,
            min_bw,
            max_bw,
            queue_id,
            dscp_mark,
            match_criteria,
            action,
            is_active_val,
            username,
            now,
            now
        ))
    else:
        pol_id = f"sec_pol_{uuid.uuid4().hex[:6]}"
        rule_type = str(data.get("rule_type", "BLOCK")).strip().upper()
        allowed_rule_types = ('BLOCK', 'RATE_LIMIT', 'ISOLATE', 'MONITOR')
        if rule_type not in allowed_rule_types:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Rule type must be one of: {', '.join(allowed_rule_types)}."}), 400

        protocol = str(data.get("protocol", "TCP")).strip().upper()
        allowed_protocols = ('TCP', 'UDP', 'ICMP', 'ANY')
        if protocol not in allowed_protocols:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Protocol must be one of: {', '.join(allowed_protocols)}."}), 400

        try:
            threshold_pps = float(data.get("threshold_pps", 5000.0))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Threshold must be a valid number."}), 400

        if threshold_pps <= 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Threshold must be greater than 0 packets/sec."}), 400

        source_ip = str(data.get("source_ip", "*")).strip() or "*"
        destination_ip = str(data.get("destination_ip", "*")).strip() or "*"
        action = str(data.get("action", rule_type)).strip().upper()
        if action not in allowed_rule_types:
            action = rule_type

        cursor.execute("""
        INSERT INTO security_policies (id, name, rule_type, source_ip, destination_ip, protocol, threshold_pps, action, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pol_id,
            name,
            rule_type,
            source_ip,
            destination_ip,
            protocol,
            threshold_pps,
            action,
            is_active_val,
            username,
            now,
            now
        ))

        # Real system enforcement: connect to existing mitigation engine if active and source IP is specified
        if is_active_val and source_ip and source_ip != "*":
            try:
                from security.mitigation import mitigation_engine
                if action == "BLOCK":
                    mitigation_engine.blocked_ips.add(source_ip)
                elif action == "RATE_LIMIT":
                    mitigation_engine.rate_limited_ips[source_ip] = int(threshold_pps)
                elif action == "ISOLATE":
                    mitigation_engine.isolated_hosts.add(source_ip)
            except Exception as e:
                current_app.logger.warning(f"Could not sync policy with mitigation engine: {e}")

    conn.commit()
    conn.close()

    log_audit_event(
        username=username,
        role="ADMIN",
        action=f"CREATE_{pol_type}_POLICY",
        resource=f"Policy {pol_id}",
        result="SUCCESS",
        details={
            "actor": username,
            "actor_role": "ADMIN",
            "action": f"CREATE_{pol_type}_POLICY",
            "target": pol_id,
            "target_type": pol_type,
            "name": name,
            "timestamp": now,
            "result": "SUCCESS"
        }
    )

    from backend.services.notification_service import create_notification
    create_notification(
        category="QoS" if pol_type == "QOS" else "Security",
        title=f"{pol_type} Policy Created: {name}",
        message=f"New policy {pol_id} activated by {username}.",
        severity="INFO",
        link="policies"
    )
    return jsonify({
        "status": "SUCCESS",
        "id": pol_id,
        "message": f"{pol_type} policy created successfully."
    }), 201


@policy_bp.route("/api/policies/<policy_id>", methods=["PUT", "PATCH"])
@policy_bp.route("/api/rules/<policy_id>", methods=["PUT", "PATCH"])
@require_admin
def modify_policy(policy_id):
    """
    Modifies an existing policy or network rule with full validation and state sync.
    ADMIN ONLY: Any attempt by OPERATOR or READER returns HTTP 403.
    """
    user = get_current_user()
    username = user.get("username", "ADMIN") if user else "ADMIN"
    now = datetime.now(timezone.utc).isoformat()
    data = request.get_json() or {}

    conn = get_db_connection()
    cursor = conn.cursor()

    # Step 1: Verify target exists
    cursor.execute("SELECT * FROM qos_policies WHERE id = ?", (policy_id,))
    qos_row = cursor.fetchone()
    cursor.execute("SELECT * FROM security_policies WHERE id = ?", (policy_id,))
    sec_row = cursor.fetchone()

    if not qos_row and not sec_row:
        conn.close()
        return jsonify({"error": "Not Found", "message": f"Policy or rule {policy_id} not found."}), 404

    pol_type = "QOS" if qos_row else "SECURITY"
    table_name = "qos_policies" if qos_row else "security_policies"

    # Validate name
    name = str(data.get("name", qos_row["name"] if qos_row else sec_row["name"])).strip()
    if not name or len(name) < 2 or len(name) > 120:
        conn.close()
        return jsonify({"error": "Validation Error", "message": "Policy name is required and must be between 2 and 120 characters."}), 400

    # Duplicate name check for other records
    cursor.execute(f"SELECT id FROM {table_name} WHERE LOWER(name) = LOWER(?) AND id != ?", (name, policy_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Duplicate Policy", "message": f"Another policy named '{name}' already exists."}), 400

    if qos_row:
        traffic_class = str(data.get("traffic_class", qos_row["traffic_class"])).strip().upper()
        allowed_classes = ('VOICE', 'VIDEO', 'CRITICAL_APPLICATION', 'WEB', 'FILE_TRANSFER', 'EMAIL', 'P2P', 'BEST_EFFORT')
        if traffic_class not in allowed_classes:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Traffic class must be one of: {', '.join(allowed_classes)}."}), 400

        priority_code = str(data.get("priority_code", qos_row["priority_code"])).strip().upper()
        if priority_code not in ('EF', 'AF', 'BE'):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Priority code must be EF, AF, or BE."}), 400

        try:
            min_bw = float(data.get("min_bandwidth_mbps", qos_row["min_bandwidth_mbps"]))
            max_bw = float(data.get("max_bandwidth_mbps", qos_row["max_bandwidth_mbps"]))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Bandwidth values must be valid numbers."}), 400

        if min_bw < 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Minimum bandwidth cannot be negative."}), 400
        if max_bw <= 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Maximum bandwidth must be greater than 0 Mbps."}), 400
        if min_bw > max_bw:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Minimum bandwidth cannot exceed maximum bandwidth."}), 400

        try:
            queue_id = int(data.get("queue_id", qos_row["queue_id"]))
            dscp_mark = int(data.get("dscp_mark", qos_row["dscp_mark"]))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Queue ID and DSCP mark must be integers."}), 400

        if queue_id < 0 or queue_id > 8:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Queue ID must be between 0 and 8."}), 400
        if dscp_mark < 0 or dscp_mark > 63:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "DSCP mark must be between 0 and 63."}), 400

        match_criteria = str(data.get("match_criteria", qos_row["match_criteria"])).strip() or "Custom Criteria"
        action = str(data.get("action", qos_row["action"])).strip() or "ENQUEUE"
        is_active = 1 if data.get("is_active", qos_row["is_active"]) in (1, "1", True, "true") else 0

        cursor.execute("""
        UPDATE qos_policies
        SET name = ?, traffic_class = ?, priority_code = ?, min_bandwidth_mbps = ?,
            max_bandwidth_mbps = ?, queue_id = ?, dscp_mark = ?, match_criteria = ?,
            action = ?, is_active = ?, updated_at = ?
        WHERE id = ?
        """, (name, traffic_class, priority_code, min_bw, max_bw, queue_id, dscp_mark, match_criteria, action, is_active, now, policy_id))
    else:
        rule_type = str(data.get("rule_type", sec_row["rule_type"])).strip().upper()
        allowed_rule_types = ('BLOCK', 'RATE_LIMIT', 'ISOLATE', 'MONITOR')
        if rule_type not in allowed_rule_types:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Rule type must be one of: {', '.join(allowed_rule_types)}."}), 400

        protocol = str(data.get("protocol", sec_row["protocol"])).strip().upper()
        allowed_protocols = ('TCP', 'UDP', 'ICMP', 'ANY')
        if protocol not in allowed_protocols:
            conn.close()
            return jsonify({"error": "Validation Error", "message": f"Protocol must be one of: {', '.join(allowed_protocols)}."}), 400

        try:
            threshold = float(data.get("threshold_pps", sec_row["threshold_pps"]))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Threshold must be a valid number."}), 400

        if threshold <= 0:
            conn.close()
            return jsonify({"error": "Validation Error", "message": "Threshold must be greater than 0 packets/sec."}), 400

        source_ip = str(data.get("source_ip", sec_row["source_ip"])).strip() or "*"
        dest_ip = str(data.get("destination_ip", sec_row["destination_ip"])).strip() or "*"
        action = str(data.get("action", sec_row["action"])).strip().upper()
        if action not in allowed_rule_types:
            action = rule_type
        is_active = 1 if data.get("is_active", sec_row["is_active"]) in (1, "1", True, "true") else 0

        cursor.execute("""
        UPDATE security_policies
        SET name = ?, rule_type = ?, source_ip = ?, destination_ip = ?,
            protocol = ?, threshold_pps = ?, action = ?, is_active = ?, updated_at = ?
        WHERE id = ?
        """, (name, rule_type, source_ip, dest_ip, protocol, threshold, action, is_active, now, policy_id))

        # Real system enforcement: sync with mitigation engine
        try:
            from security.mitigation import mitigation_engine
            old_src = sec_row["source_ip"]
            if old_src and old_src != "*":
                mitigation_engine.blocked_ips.discard(old_src)
                mitigation_engine.rate_limited_ips.pop(old_src, None)
                mitigation_engine.isolated_hosts.discard(old_src)
            if is_active and source_ip and source_ip != "*":
                if action == "BLOCK":
                    mitigation_engine.blocked_ips.add(source_ip)
                elif action == "RATE_LIMIT":
                    mitigation_engine.rate_limited_ips[source_ip] = int(threshold)
                elif action == "ISOLATE":
                    mitigation_engine.isolated_hosts.add(source_ip)
        except Exception as e:
            current_app.logger.warning(f"Could not sync policy with mitigation engine: {e}")

    conn.commit()
    conn.close()

    log_audit_event(
        username=username,
        role="ADMIN",
        action=f"MODIFY_{pol_type}_POLICY",
        resource=f"Policy {policy_id}",
        result="SUCCESS",
        details={
            "actor": username,
            "actor_role": "ADMIN",
            "action": f"MODIFY_{pol_type}_POLICY",
            "target": policy_id,
            "target_type": pol_type,
            "name": name,
            "timestamp": now,
            "result": "SUCCESS"
        }
    )

    from backend.services.notification_service import create_notification
    create_notification(
        category="QoS" if pol_type == "QOS" else "Security",
        title=f"Policy Updated: {name}",
        message=f"Policy {policy_id} updated by {username}.",
        severity="INFO",
        link="policies"
    )

    return jsonify({
        "status": "SUCCESS",
        "id": policy_id,
        "message": f"Policy {policy_id} updated successfully."
    }), 200


@policy_bp.route("/api/policies/<policy_id>/toggle", methods=["POST"])
@policy_bp.route("/api/rules/<policy_id>/toggle", methods=["POST"])
@require_admin
def toggle_policy(policy_id):
    """
    Enables or disables a policy or rule.
    ADMIN ONLY: Any attempt by OPERATOR or READER returns HTTP 403.
    """
    user = get_current_user()
    username = user.get("username", "ADMIN") if user else "ADMIN"
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM qos_policies WHERE id = ?", (policy_id,))
    qos_row = cursor.fetchone()
    cursor.execute("SELECT * FROM security_policies WHERE id = ?", (policy_id,))
    sec_row = cursor.fetchone()

    if not qos_row and not sec_row:
        conn.close()
        return jsonify({"error": "Not Found", "message": f"Policy or rule {policy_id} not found."}), 404

    target = qos_row or sec_row
    new_status = 0 if target["is_active"] else 1
    table_name = "qos_policies" if qos_row else "security_policies"

    cursor.execute(f"UPDATE {table_name} SET is_active = ?, updated_at = ? WHERE id = ?", (new_status, now, policy_id))
    conn.commit()

    # Real system sync for security policies
    if sec_row:
        try:
            from security.mitigation import mitigation_engine
            src_ip = sec_row["source_ip"]
            action = sec_row["action"]
            if src_ip and src_ip != "*":
                if new_status == 1:
                    if action == "BLOCK":
                        mitigation_engine.blocked_ips.add(src_ip)
                    elif action == "RATE_LIMIT":
                        mitigation_engine.rate_limited_ips[src_ip] = int(sec_row["threshold_pps"])
                    elif action == "ISOLATE":
                        mitigation_engine.isolated_hosts.add(src_ip)
                else:
                    mitigation_engine.blocked_ips.discard(src_ip)
                    mitigation_engine.rate_limited_ips.pop(src_ip, None)
                    mitigation_engine.isolated_hosts.discard(src_ip)
        except Exception:
            pass

    conn.close()

    status_str = "ENABLED" if new_status else "DISABLED"
    log_audit_event(
        username=username,
        role="ADMIN",
        action=f"{status_str}_POLICY",
        resource=f"Policy {policy_id}",
        result="SUCCESS",
        details={
            "actor": username,
            "actor_role": "ADMIN",
            "action": f"{status_str}_POLICY",
            "target": policy_id,
            "new_status": new_status,
            "timestamp": now,
            "result": "SUCCESS"
        }
    )

    return jsonify({
        "status": "SUCCESS",
        "id": policy_id,
        "is_active": new_status,
        "message": f"Policy {policy_id} {status_str.lower()} successfully."
    }), 200


@policy_bp.route("/api/policies/<policy_id>", methods=["DELETE"])
@policy_bp.route("/api/rules/<policy_id>", methods=["DELETE"])
@require_admin
def delete_policy(policy_id):
    """
    Deletes an existing policy or rule.
    ADMIN ONLY: Any attempt by OPERATOR or READER returns HTTP 403.
    """
    user = get_current_user()
    username = user.get("username", "ADMIN") if user else "ADMIN"
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verify target exists in QoS or Security policies
    cursor.execute("SELECT * FROM qos_policies WHERE id = ?", (policy_id,))
    qos_row = cursor.fetchone()
    cursor.execute("SELECT * FROM security_policies WHERE id = ?", (policy_id,))
    sec_row = cursor.fetchone()

    if not qos_row and not sec_row:
        conn.close()
        return jsonify({"error": "Not Found", "message": f"Policy or rule {policy_id} not found."}), 404

    target = qos_row or sec_row
    pol_type = "QOS" if qos_row else "SECURITY"
    table_name = "qos_policies" if qos_row else "security_policies"

    cursor.execute(f"DELETE FROM {table_name} WHERE id = ?", (policy_id,))
    conn.commit()

    # Real system sync
    if sec_row:
        try:
            from security.mitigation import mitigation_engine
            src_ip = sec_row["source_ip"]
            if src_ip and src_ip != "*":
                mitigation_engine.blocked_ips.discard(src_ip)
                mitigation_engine.rate_limited_ips.pop(src_ip, None)
                mitigation_engine.isolated_hosts.discard(src_ip)
        except Exception:
            pass

    conn.close()

    # Create audit-log entry
    log_audit_event(
        username=username,
        role="ADMIN",
        action="DELETE_POLICY",
        resource=f"Policy {policy_id}",
        result="SUCCESS",
        details={
            "actor": username,
            "actor_role": "ADMIN",
            "action": "DELETE_POLICY",
            "target": policy_id,
            "target_name": target["name"],
            "target_type": pol_type,
            "timestamp": now,
            "result": "SUCCESS"
        }
    )

    # Dispatch notification
    from backend.services.notification_service import create_notification
    create_notification(
        category="QoS" if pol_type == "QOS" else "Security",
        title=f"Policy Deleted: {policy_id}",
        message=f"Policy '{target['name']}' ({policy_id}) was removed by {username}.",
        severity="LOW",
        link="policies"
    )

    return jsonify({
        "status": "SUCCESS",
        "message": f"Policy {policy_id} deleted successfully."
    }), 200
