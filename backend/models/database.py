"""
VORTEX-SDN Database Model & SQLite Persistence Layer
Handles user accounts, security incidents, QoS policies, audit logs,
operator access requests, and granular role-based permissions.
"""

import os
import sys
import sqlite3
import hashlib
import json
import uuid
import re
from datetime import datetime, timezone

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "vortex.db")

# Standard granular permissions
DEFAULT_PERMISSIONS = [
    # Observability
    ("perm_dash_view", "dashboard.view", "Observability", "View main NOC dashboard, telemetry cards, and KPIs"),
    ("perm_telem_view", "telemetry.view", "Observability", "View live OpenFlow port, packet, and byte telemetry"),
    ("perm_sec_view", "security.view", "Observability", "View active security threat feeds and anomaly detection"),
    ("perm_qos_view", "qos.view", "Observability", "View QoS queue latency, traffic classes, and bandwidth stats"),
    ("perm_net_view", "network.view", "Observability", "View network topology, SDN switch mesh, and host status"),
    ("perm_inc_view", "incident.view", "Observability", "View incident timeline, root-cause analysis, and alerts"),
    ("perm_rep_view", "reports.view", "Observability", "View compliance and operational reports"),
    ("perm_set_view", "settings.view", "Observability", "View user preferences and platform settings"),
    ("perm_aud_view", "audit.view", "Observability", "View system audit trail and compliance activity logs"),
    # Control & Modification
    ("perm_net_cfg", "network.configure", "Control", "Configure network topologies, demo scenarios, and flow modes"),
    ("perm_flow_mgt", "flow.manage", "Control", "Install, modify, and delete OpenFlow forwarding rules"),
    ("perm_sec_resp", "security.response", "Control", "Execute threat mitigations, IP quarantine, and mode switching"),
    ("perm_qos_cfg", "qos.configure", "Control", "Create, edit, and remove QoS queue policies"),
    ("perm_inc_mgt", "incident.manage", "Control", "Acknowledge, investigate, and resolve security incidents"),
    ("perm_rep_exp", "reports.export", "Control", "Export telemetry and compliance reports to CSV/JSON"),
    ("perm_dev_mgt", "device.manage", "Control", "Manage SDN switches, port states, and attached hosts"),
    ("perm_set_mod", "settings.modify", "Control", "Modify platform configurations and runtime parameters"),
    # Administration
    ("perm_adm_mgt", "admin.manage", "Administration", "Manage users, approve operator requests, and grant permissions")
]

# Default modification permissions granted to newly approved operators
DEFAULT_OPERATOR_PERMISSIONS = [
    "dashboard.view",
    "telemetry.view",
    "security.view",
    "qos.view",
    "network.view",
    "incident.view",
    "reports.view",
    "settings.view",
    "security.response",
    "incident.manage",
    "network.configure"
]

# Standard read-only permissions automatically available to READER / VIEWER
READER_VIEW_PERMISSIONS = [
    "dashboard.view",
    "telemetry.view",
    "security.view",
    "qos.view",
    "network.view",
    "incident.view",
    "reports.view",
    "settings.view"
]

def ensure_dirs():
    """Ensure all required data directories exist."""
    subdirs = ["telemetry", "security", "qos", "datasets", "users", "incidents", "audit", "models"]
    for d in subdirs:
        os.makedirs(os.path.join(DB_DIR, d), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ai", "models"), exist_ok=True)

def get_db_connection():
    """Returns a thread-safe connection to the SQLite database with Row factory."""
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Generates a secure salted SHA-256 password hash."""
    if salt is None:
        salt = uuid.uuid4().hex
    pwd_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return pwd_hash, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a password against the stored salted hash."""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == stored_hash

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validates password strength according to VORTEX-SDN security policy:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    Returns: (is_strong, error_or_success_message)
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    missing = []
    if not re.search(r"[A-Z]", password):
        missing.append("uppercase letter")
    if not re.search(r"[a-z]", password):
        missing.append("lowercase letter")
    if not re.search(r"[0-9]", password):
        missing.append("number")
    if not re.search(r"[^A-Za-z0-9]", password):
        missing.append("special character")

    if missing:
        return False, f"Password must include at least one {', '.join(missing)}."

    return True, "Password meets strength requirements."

def init_db():
    """Initializes the SQLite database schema and seeds initial accounts."""
    ensure_dirs()
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table (Support ADMIN, OPERATOR, VIEWER, READER)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OPERATOR', 'VIEWER', 'READER')),
        avatar TEXT,
        is_active INTEGER DEFAULT 1,
        email_verified INTEGER DEFAULT 0,
        verification_token_hash TEXT,
        verification_token_expires TEXT,
        reset_token_hash TEXT,
        reset_token_expires TEXT,
        password_reset_used_at TEXT,
        settings_json TEXT,
        created_at TEXT NOT NULL,
        last_login TEXT
    )
    """)

    # Migration for users table CHECK constraint if READER is not yet permitted
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
    users_sql_row = cursor.fetchone()
    if users_sql_row and users_sql_row[0] and "'READER'" not in users_sql_row[0]:
        cursor.execute("""
        CREATE TABLE users_migrated (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OPERATOR', 'VIEWER', 'READER')),
            avatar TEXT,
            is_active INTEGER DEFAULT 1,
            email_verified INTEGER DEFAULT 0,
            verification_token_hash TEXT,
            verification_token_expires TEXT,
            reset_token_hash TEXT,
            reset_token_expires TEXT,
            password_reset_used_at TEXT,
            settings_json TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
        """)
        cursor.execute("""
        INSERT INTO users_migrated (
            id, username, email, full_name, password_hash, salt, role, avatar, is_active,
            email_verified, verification_token_hash, verification_token_expires,
            reset_token_hash, reset_token_expires, password_reset_used_at, settings_json, created_at, last_login
        ) SELECT id, username, email, full_name, password_hash, salt, role, avatar, is_active,
                 email_verified, verification_token_hash, verification_token_expires,
                 reset_token_hash, reset_token_expires, password_reset_used_at, settings_json, created_at, last_login
        FROM users
        """)
        cursor.execute("DROP TABLE users")
        cursor.execute("ALTER TABLE users_migrated RENAME TO users")

    # Schema migration for existing users table columns if missing
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = [c[1] for c in cursor.fetchall()]
    if "email_verified" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
    if "verification_token_hash" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN verification_token_hash TEXT")
    if "verification_token_expires" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN verification_token_expires TEXT")
    if "reset_token_hash" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_token_hash TEXT")
    if "reset_token_expires" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expires TEXT")
    if "password_reset_used_at" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN password_reset_used_at TEXT")
    if "verification_attempts" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN verification_attempts INTEGER DEFAULT 0")

    # 2. Operator Access Requests Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS operator_access_requests (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        full_name TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED')),
        requested_at TEXT NOT NULL,
        reviewed_at TEXT,
        reviewed_by TEXT,
        review_reason TEXT,
        client_ip TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Migration for operator_access_requests table CHECK constraint if REVOKED is not yet permitted
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='operator_access_requests'")
    oar_sql_row = cursor.fetchone()
    if oar_sql_row and oar_sql_row[0] and "'REVOKED'" not in oar_sql_row[0]:
        cursor.execute("""
        CREATE TABLE operator_access_requests_migrated (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED')),
            requested_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by TEXT,
            review_reason TEXT,
            client_ip TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
        cursor.execute("""
        INSERT INTO operator_access_requests_migrated (
            id, user_id, email, full_name, status, requested_at, reviewed_at, reviewed_by, review_reason, client_ip, user_agent
        ) SELECT id, user_id, email, full_name, status, requested_at, reviewed_at, reviewed_by, review_reason, client_ip, user_agent
        FROM operator_access_requests
        """)
        cursor.execute("DROP TABLE operator_access_requests")
        cursor.execute("ALTER TABLE operator_access_requests_migrated RENAME TO operator_access_requests")

    # 3. Permissions Catalog Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL
    )
    """)

    # 4. User Granted Permissions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_permissions (
        user_id TEXT NOT NULL,
        permission_id TEXT NOT NULL,
        granted_by TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        PRIMARY KEY (user_id, permission_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (permission_id) REFERENCES permissions(id)
    )
    """)

    # Seed Permissions Catalog
    for perm_id, name, cat, desc in DEFAULT_PERMISSIONS:
        cursor.execute("""
        INSERT OR IGNORE INTO permissions (id, name, category, description)
        VALUES (?, ?, ?, ?)
        """, (perm_id, name, cat, desc))

    # 5. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        description TEXT NOT NULL,
        ai_confidence REAL NOT NULL,
        risk_score REAL NOT NULL,
        status TEXT NOT NULL,
        action_taken TEXT,
        assigned_to TEXT,
        updated_at TEXT NOT NULL,
        title TEXT,
        affected_device TEXT,
        affected_flows_json TEXT,
        root_cause_json TEXT,
        impact_json TEXT,
        timeline_json TEXT,
        recovery_pct REAL DEFAULT 0.0,
        first_seen TEXT,
        resolved_at TEXT
    )
    """)

    # Check if legacy incidents table with restrictive CHECK constraint needs migration
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='incidents'")
    tbl_row = cursor.fetchone()
    if tbl_row and tbl_row[0] and "CHECK(status IN" in tbl_row[0]:
        cursor.execute("""
        CREATE TABLE incidents_migrated (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            ai_confidence REAL NOT NULL,
            risk_score REAL NOT NULL,
            status TEXT NOT NULL,
            action_taken TEXT,
            assigned_to TEXT,
            updated_at TEXT NOT NULL,
            title TEXT,
            affected_device TEXT,
            affected_flows_json TEXT,
            root_cause_json TEXT,
            impact_json TEXT,
            timeline_json TEXT,
            recovery_pct REAL DEFAULT 0.0,
            first_seen TEXT,
            resolved_at TEXT
        )
        """)
        cursor.execute("""
        INSERT INTO incidents_migrated (
            id, timestamp, severity, category, source_ip, destination_ip, description,
            ai_confidence, risk_score, status, action_taken, assigned_to, updated_at
        ) SELECT id, timestamp, severity, category, source_ip, destination_ip, description,
                 ai_confidence, risk_score, status, action_taken, assigned_to, updated_at
        FROM incidents
        """)
        cursor.execute("DROP TABLE incidents")
        cursor.execute("ALTER TABLE incidents_migrated RENAME TO incidents")

    # Schema migration for incidents table columns
    cursor.execute("PRAGMA table_info(incidents)")
    inc_cols = [c[1] for c in cursor.fetchall()]
    if "title" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN title TEXT")
    if "affected_device" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN affected_device TEXT")
    if "affected_flows_json" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN affected_flows_json TEXT")
    if "root_cause_json" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN root_cause_json TEXT")
    if "impact_json" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN impact_json TEXT")
    if "timeline_json" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN timeline_json TEXT")
    if "recovery_pct" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN recovery_pct REAL DEFAULT 0.0")
    if "first_seen" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN first_seen TEXT")
    if "resolved_at" not in inc_cols:
        cursor.execute("ALTER TABLE incidents ADD COLUMN resolved_at TEXT")

    # 6. Audit Logs Table (Append-only)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        user_id TEXT,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAILURE', 'WARNING')),
        details_json TEXT,
        client_ip TEXT
    )
    """)

    # 7. Security Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        label TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        packet_rate REAL NOT NULL,
        byte_rate REAL NOT NULL,
        confidence REAL NOT NULL,
        risk_score REAL NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        recommended_action TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE'
    )
    """)

    # 8. QoS Policies Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS qos_policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        traffic_class TEXT NOT NULL,
        priority_code TEXT NOT NULL CHECK(priority_code IN ('EF', 'AF', 'BE')),
        min_bandwidth_mbps REAL DEFAULT 0,
        max_bandwidth_mbps REAL DEFAULT 100,
        queue_id INTEGER DEFAULT 0,
        dscp_mark INTEGER DEFAULT 0,
        match_criteria TEXT,
        action TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # 9. Security Policies Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        rule_type TEXT NOT NULL CHECK(rule_type IN ('BLOCK', 'RATE_LIMIT', 'ISOLATE', 'MONITOR')),
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        threshold_pps REAL,
        action TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # 10. Notifications Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('Security', 'QoS', 'Controller', 'Telemetry', 'AI', 'System')),
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
        is_read INTEGER DEFAULT 0,
        read_at TEXT,
        link TEXT
    )
    """)

    # Seed Default QoS Policies if empty
    cursor.execute("SELECT COUNT(*) FROM qos_policies")
    if cursor.fetchone()[0] == 0:
        now = datetime.now(timezone.utc).isoformat()
        default_qos = [
            ("qos_pol_001", "Voice High Priority Expedited", "VOICE", "EF", 10.0, 50.0, 1, 46, "UDP dst_port: 5060, 10000-20000", "ENQUEUE_QUEUE_1", 1, "admin", now, now),
            ("qos_pol_002", "Video Streaming Assured Forwarding", "VIDEO", "AF", 25.0, 100.0, 2, 34, "TCP/UDP dst_port: 1935, 8080, 554", "ENQUEUE_QUEUE_2", 1, "admin", now, now),
            ("qos_pol_003", "Critical Enterprise Applications", "CRITICAL_APPLICATION", "EF", 20.0, 80.0, 1, 40, "TCP dst_port: 443, 8443, 5000", "ENQUEUE_QUEUE_1", 1, "admin", now, now),
            ("qos_pol_004", "Standard Web Traffic", "WEB", "AF", 15.0, 60.0, 2, 26, "TCP dst_port: 80, 8080", "ENQUEUE_QUEUE_2", 1, "admin", now, now),
            ("qos_pol_005", "Bulk File Transfers Best Effort", "FILE_TRANSFER", "BE", 5.0, 30.0, 3, 0, "TCP dst_port: 20, 21, 22, 445", "ENQUEUE_QUEUE_3", 1, "admin", now, now),
            ("qos_pol_006", "Email Services Best Effort", "EMAIL", "BE", 2.0, 15.0, 3, 0, "TCP dst_port: 25, 587, 993, 110", "ENQUEUE_QUEUE_3", 1, "admin", now, now),
            ("qos_pol_007", "P2P Traffic Constrained", "P2P", "BE", 1.0, 5.0, 4, 8, "TCP/UDP dst_port: 6881-6889", "RATE_LIMIT_QUEUE_4", 1, "admin", now, now)
        ]
        cursor.executemany("""
        INSERT INTO qos_policies (id, name, traffic_class, priority_code, min_bandwidth_mbps, max_bandwidth_mbps, queue_id, dscp_mark, match_criteria, action, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_qos)

    # Seed Default Security Policies if empty
    cursor.execute("SELECT COUNT(*) FROM security_policies")
    if cursor.fetchone()[0] == 0:
        now = datetime.now(timezone.utc).isoformat()
        default_sec = [
            ("sec_pol_001", "DDoS Mitigation Threshold", "RATE_LIMIT", "*", "10.0.0.1", "UDP", 15000.0, "RATE_LIMIT", 1, "admin", now, now),
            ("sec_pol_002", "Port Scan Quarantine Rule", "ISOLATE", "*", "*", "TCP", 2500.0, "ISOLATE", 1, "admin", now, now),
            ("sec_pol_003", "Brute Force SSH Defense", "BLOCK", "*", "10.0.0.2", "TCP", 500.0, "BLOCK", 1, "admin", now, now),
            ("sec_pol_004", "ICMP Flood Defense", "RATE_LIMIT", "*", "*", "ICMP", 1000.0, "RATE_LIMIT", 1, "admin", now, now)
        ]
        cursor.executemany("""
        INSERT INTO security_policies (id, name, rule_type, source_ip, destination_ip, protocol, threshold_pps, action, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_sec)

    # Seed Initial Notifications if empty
    cursor.execute("SELECT COUNT(*) FROM notifications")
    if cursor.fetchone()[0] == 0:
        now = datetime.now(timezone.utc).isoformat()
        initial_notifs = [
            ("notif_001", now, "System", "VORTEX-SDN Initialized", "VORTEX-SDN Controller and Intelligence Subsystems ready for operation.", "INFO", 0, None, "/health"),
            ("notif_002", now, "AI", "AI Threat & QoS Models Active", "RandomForest threat detector and QoS multi-class models loaded into runtime memory.", "INFO", 0, None, "/ai"),
            ("notif_003", now, "Controller", "SDN Controller Interface Online", "OpenFlow 1.3 datapath handler listening for switch connections.", "INFO", 0, None, "/topology")
        ]
        cursor.executemany("""
        INSERT INTO notifications (id, timestamp, category, title, message, severity, is_read, read_at, link)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_notifs)

    conn.commit()
    conn.close()

    # Enforce strictly SINGLE ADMIN setup
    bootstrap_single_admin()

def bootstrap_single_admin():
    """
    Enforces strictly ONE administrator for the entire VORTEX-SDN installation.
    The administrator must be the existing VORTEX-SDN user account configured via ADMIN_EMAIL.

    During application initialization:
    1. Read ADMIN_EMAIL from .env.
    2. Detect if more than one ADMIN exists in the database; do not automatically choose one
       or create another, detect the conflict and require administrative intervention.
    3. Find the existing user whose normalized email matches ADMIN_EMAIL.
       If the ADMIN_EMAIL account does not exist, do NOT silently create an insecure administrator.
       Instead, report clearly: "Configured ADMIN_EMAIL account does not exist. Create/verify the account first."
    4. Assign that existing user the ADMIN role.
    5. Keep that account's existing password and email-verification status.
    6. Do not create a second user account for the admin.
    7. Do not require a separate admin signup process.
    8. Do not allow any other account to become ADMIN.
    """
    # 1. Read ADMIN_EMAIL from .env (if not already set in environment)
    if "ADMIN_EMAIL" not in os.environ:
        try:
            from backend.services.email_service import load_env_file
            load_env_file()
        except Exception:
            pass

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if not admin_email:
        msg = "Configured ADMIN_EMAIL account does not exist. Create/verify the account first."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # 2. Find the existing user whose normalized email matches ADMIN_EMAIL
    cursor.execute("SELECT id, username, email, role, password_hash, salt, email_verified, is_active FROM users WHERE LOWER(email) = ?", (admin_email,))
    admin_row = cursor.fetchone()

    # If the ADMIN_EMAIL account does not exist, do NOT silently create an insecure administrator.
    if not admin_row:
        conn.close()
        msg = "Configured ADMIN_EMAIL account does not exist. Create/verify the account first."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    admin_user_id = admin_row["id"]

    # 3. Check for existing ADMIN accounts in database
    cursor.execute("SELECT id, username, email, role FROM users WHERE role = 'ADMIN'")
    existing_admins = cursor.fetchall()

    # If more than one ADMIN exists in the database, do NOT automatically choose one or create another.
    # Detect the conflict and require administrative intervention.
    if len(existing_admins) > 1:
        conn.close()
        conflict_list = [r["email"] for r in existing_admins]
        msg = f"Conflict detected: More than one ADMIN exists in the database ({', '.join(conflict_list)}). Administrative intervention required."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    if len(existing_admins) == 1:
        current_admin_email = existing_admins[0]["email"].strip().lower()
        if current_admin_email != admin_email:
            confirm_val = os.environ.get("ADMIN_TRANSFER_CONFIRM", "").strip().lower()
            if confirm_val in ("true", "1", "yes") and current_admin_email == "vertexsdn@gmail.com":
                conn.close()
                perform_admin_handover(old_admin_email="vertexsdn@gmail.com", target_admin_email=admin_email)
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id, username, email, role, password_hash, salt, email_verified, is_active FROM users WHERE LOWER(email) = ?", (admin_email,))
                admin_row = cursor.fetchone()
                admin_user_id = admin_row["id"]
            else:
                conn.close()
                msg = f"Conflict detected: Existing database ADMIN ({existing_admins[0]['email']}) does not match configured ADMIN_EMAIL ({admin_email}). Administrative intervention required. Set ADMIN_TRANSFER_CONFIRM=true to authorize one-time handover."
                print(f"\n[!] {msg}\n", file=sys.stderr)
                raise RuntimeError(msg)

    # 4. Assign that existing user the ADMIN role.
    # 5. Keep that account's existing password and email-verification status.
    cursor.execute("UPDATE users SET role = 'ADMIN' WHERE id = ?", (admin_user_id,))

    # Grant all permissions to the single admin
    cursor.execute("SELECT id FROM permissions")
    all_perm_ids = [r[0] for r in cursor.fetchall()]
    for p_id in all_perm_ids:
        cursor.execute("""
        INSERT OR IGNORE INTO user_permissions (user_id, permission_id, granted_by, granted_at)
        VALUES (?, ?, 'SYSTEM_BOOTSTRAP', ?)
        """, (admin_user_id, p_id, now))

    # Log admin bootstrap in audit log
    audit_id = f"aud_{uuid.uuid4().hex[:8]}"
    details_json = json.dumps({"action": "ADMIN_VERIFIED", "email": admin_email, "user_id": admin_user_id})
    resource_str = f"User {admin_email}"
    cursor.execute("""
    INSERT INTO audit_logs (id, timestamp, user_id, username, role, action, resource, result, details_json, client_ip)
    VALUES (?, ?, ?, ?, 'ADMIN', 'ADMIN_BOOTSTRAP', ?, 'SUCCESS', ?, '127.0.0.1')
    """, (audit_id, now, admin_user_id, admin_row["username"], resource_str, details_json))

    conn.commit()
    conn.close()

def perform_admin_handover(old_admin_email: str = "vertexsdn@gmail.com", target_admin_email: str = None) -> tuple[bool, str]:
    """
    Controlled, explicit, one-time administrator handover mechanism.
    Transfers the single ADMIN role from old_admin_email to target_admin_email (configured in ADMIN_EMAIL).

    Enforces all strict safety requirements:
    1. Target email must match configured ADMIN_EMAIL.
    2. Target account must already exist in the database.
    3. Target account must be active (is_active == 1) and email-verified (email_verified == 1).
    4. Exactly ONE existing ADMIN must exist in the database.
    5. The existing ADMIN must be exactly old_admin_email (vertexsdn@gmail.com).
    6. Server-side confirmation flag ADMIN_TRANSFER_CONFIRM=true must be provided.
    7. Atomically demotes old admin to OPERATOR and promotes target user to ADMIN.
    8. Preserves passwords, salt, email-verification, and settings for both accounts.
    9. Creates an immutable audit record of the transfer with old admin, new admin, timestamp, action, result.
    """
    if "ADMIN_EMAIL" not in os.environ:
        try:
            from backend.services.email_service import load_env_file
            load_env_file()
        except Exception:
            pass

    if not target_admin_email:
        target_admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

    target_admin_email = (target_admin_email or "").strip().lower()
    old_admin_email = (old_admin_email or "vertexsdn@gmail.com").strip().lower()

    if not target_admin_email:
        msg = "Configured ADMIN_EMAIL account does not exist. Create/verify the account first."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    # 13. Explicit confirmation requirement
    confirm_val = os.environ.get("ADMIN_TRANSFER_CONFIRM", "").strip().lower()
    if confirm_val not in ("true", "1", "yes"):
        msg = f"Admin transfer confirmation not provided. Set ADMIN_TRANSFER_CONFIRM=true to authorize handover from {old_admin_email} to {target_admin_email}."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 4 & 16. Verify existing ADMIN records
    cursor.execute("SELECT id, username, email, role FROM users WHERE role = 'ADMIN'")
    existing_admins = cursor.fetchall()

    if len(existing_admins) > 1:
        conn.close()
        conflict_list = [r["email"] for r in existing_admins]
        msg = f"Conflict detected: More than one ADMIN exists in the database ({', '.join(conflict_list)}). Administrative intervention required."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    if len(existing_admins) == 0:
        conn.close()
        msg = "No existing ADMIN found in database. Administrative intervention required."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    curr_admin = existing_admins[0]
    curr_admin_email = curr_admin["email"].strip().lower()

    # Check if already transferred
    if curr_admin_email == target_admin_email:
        conn.close()
        return True, f"Admin role is already assigned to {target_admin_email}."

    # 5 & 19. Verify that existing admin is exactly old_admin_email (vertexsdn@gmail.com)
    if curr_admin_email != old_admin_email:
        conn.close()
        msg = f"Existing ADMIN is not {old_admin_email} ({curr_admin['email']}). Handover aborted."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    # 2 & 17. Verify target account exists
    cursor.execute("SELECT id, username, email, role, password_hash, salt, email_verified, is_active FROM users WHERE LOWER(email) = ?", (target_admin_email,))
    target_row = cursor.fetchone()

    if not target_row:
        conn.close()
        msg = f"Target account {target_admin_email} does not exist. Create/verify that account first."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    # 3 & 18. Verify active and email-verified
    if not target_row["is_active"]:
        conn.close()
        msg = f"Target account {target_admin_email} is disabled/inactive. Account must be active before transfer."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    if not target_row["email_verified"]:
        conn.close()
        msg = f"Target account {target_admin_email} exists but is not email-verified. Verify the account first."
        print(f"\n[!] {msg}\n", file=sys.stderr)
        raise RuntimeError(msg)

    now = datetime.now(timezone.utc).isoformat()
    old_admin_id = curr_admin["id"]
    new_admin_id = target_row["id"]

    try:
        # Atomic Transaction: Demote old admin, promote target user, grant permissions, write audit log
        cursor.execute("UPDATE users SET role = 'OPERATOR' WHERE id = ?", (old_admin_id,))
        cursor.execute("UPDATE users SET role = 'ADMIN' WHERE id = ?", (new_admin_id,))

        cursor.execute("SELECT id FROM permissions")
        all_perm_ids = [r[0] for r in cursor.fetchall()]
        for p_id in all_perm_ids:
            cursor.execute("""
            INSERT OR IGNORE INTO user_permissions (user_id, permission_id, granted_by, granted_at)
            VALUES (?, ?, 'ADMIN_HANDOVER', ?)
            """, (new_admin_id, p_id, now))

        audit_id = f"aud_{uuid.uuid4().hex[:8]}"
        details = {
            "action": "ADMIN_ROLE_HANDOVER",
            "old_admin": old_admin_email,
            "new_admin": target_admin_email,
            "old_admin_user_id": old_admin_id,
            "new_admin_user_id": new_admin_id,
            "timestamp": now,
            "result": "SUCCESS",
            "authorization": "ADMIN_TRANSFER_CONFIRM"
        }
        cursor.execute("""
        INSERT INTO audit_logs (id, timestamp, user_id, username, role, action, resource, result, details_json, client_ip)
        VALUES (?, ?, ?, ?, 'ADMIN', 'ADMIN_ROLE_HANDOVER', ?, 'SUCCESS', ?, '127.0.0.1')
        """, (audit_id, now, new_admin_id, target_row["username"], f"Admin role transfer: {old_admin_email} -> {target_admin_email}", json.dumps(details)))

        conn.commit()

        # Immediate verification
        cursor.execute("SELECT email FROM users WHERE role = 'ADMIN'")
        admins_after = cursor.fetchall()
        if len(admins_after) != 1 or admins_after[0]["email"].strip().lower() != target_admin_email:
            conn.rollback()
            raise RuntimeError(f"Database consistency verification failed after transfer: {admins_after}")

        conn.close()
        success_msg = f"Successfully transferred single ADMIN role from {old_admin_email} to {target_admin_email}."
        print(f"\n[+] {success_msg}\n")
        return True, success_msg

    except Exception as e:
        conn.rollback()
        conn.close()
        raise RuntimeError(f"Admin handover failed and rolled back: {e}")

def get_user_permissions(user_id: str) -> list[str]:
    """
    Returns list of granular permission string names for a user.
    - ADMIN: all permissions ('*')
    - OPERATOR: view permissions + explicitly assigned permissions in user_permissions
    - READER / VIEWER: view permissions only
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return []

    role = row["role"]
    if role == "ADMIN":
        cursor.execute("SELECT name FROM permissions")
        all_perms = [r["name"] for r in cursor.fetchall()]
        conn.close()
        return list(set(all_perms + ["*"]))

    if role in ("READER", "VIEWER"):
        conn.close()
        return list(READER_VIEW_PERMISSIONS)

    # OPERATOR: standard view permissions + assigned modification permissions
    cursor.execute("""
    SELECT p.name FROM permissions p
    JOIN user_permissions up ON p.id = up.permission_id
    WHERE up.user_id = ?
    """, (user_id,))
    assigned = [r["name"] for r in cursor.fetchall()]
    conn.close()
    return list(set(READER_VIEW_PERMISSIONS + assigned))

def user_has_permission(user_id: str, permission_name: str) -> bool:
    """Checks whether a user holds a specific permission name."""
    perms = get_user_permissions(user_id)
    return ("*" in perms) or (permission_name in perms)

if __name__ == "__main__":
    init_db()
    print(f"Database initialized successfully at: {DB_PATH}")
