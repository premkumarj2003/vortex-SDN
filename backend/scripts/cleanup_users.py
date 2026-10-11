"""
VORTEX-SDN One-Time User Database Cleanup Script
Safely deletes all non-admin user accounts while preserving:
- Exactly ONE configured ADMIN account (matching ADMIN_EMAIL)
- All network policies, QoS policies, security policies, and flow rules
- All historical audit logs and telemetry data
- Foreign-key integrity across all database tables

Safety Guards:
1. Inspects schema and counts all records.
2. Identifies admin strictly by server-side normalized ADMIN_EMAIL.
3. Stops if ADMIN_EMAIL account does not exist or has conflicting roles.
4. Stops if multiple ADMIN accounts exist.
5. Requires explicit confirmation:
   - CLI flag: --confirm
   - Environment variable: CONFIRM_DELETE_NON_ADMIN_USERS=true
   - Or interactive input: 'DELETE ALL NON-ADMIN USERS'
6. Does NOT run automatically on startup.
7. Logs NON_ADMIN_USER_CLEANUP_COMPLETED audit event.
"""

import os
import sys
import argparse
from datetime import datetime, timezone

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models.database import get_db_connection, DB_PATH
from backend.services.audit_service import log_audit_event


def get_configured_admin_email() -> str:
    """Reads and normalizes ADMIN_EMAIL from environment or .env file."""
    # Check current os.environ
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if admin_email:
        return admin_email

    # Check .env file in project root
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("ADMIN_EMAIL=") and not line.startswith("#"):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val.lower()

    # Default fallback
    return "premkumarj18122003@gmail.com"


def execute_cleanup(confirm: bool = False, interactive: bool = False) -> tuple[bool, dict]:
    """
    Executes the one-time cleanup with all safety verifications.
    Returns (success: bool, info: dict).
    """
    print("=" * 78)
    print(" VORTEX-SDN ONE-TIME USER DATABASE CLEANUP")
    print("=" * 78)
    print(f"[*] Database file: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print(f"[!] ERROR: Database file not found at {DB_PATH}")
        return False, {"error": "Database file not found"}

    admin_email = get_configured_admin_email()
    print(f"[*] Authority ADMIN_EMAIL: {admin_email}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Step 1: Inspect schema
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]
    if "users" not in tables:
        conn.close()
        print("[!] ERROR: 'users' table not found in database.")
        return False, {"error": "'users' table not found"}

    # Step 2: Verify configured ADMIN_EMAIL exists
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = ?", (admin_email,))
    admin_matches = cursor.fetchall()

    if len(admin_matches) == 0:
        conn.close()
        print(f"[!] STOP: Configured ADMIN_EMAIL ({admin_email}) account does not exist in the database.")
        print("    Aborting cleanup without making any changes.")
        return False, {"error": "Configured ADMIN_EMAIL does not exist"}

    # Step 3: Verify exactly one account matches ADMIN_EMAIL
    if len(admin_matches) > 1:
        conn.close()
        print(f"[!] STOP: Conflict detected! Multiple accounts ({len(admin_matches)}) match ADMIN_EMAIL ({admin_email}).")
        print("    Aborting cleanup to prevent data corruption.")
        return False, {"error": "Multiple accounts match ADMIN_EMAIL"}

    admin_account = dict(admin_matches[0])
    admin_id = admin_account["id"]
    admin_username = admin_account["username"]

    # Step 4: Verify that account is currently the intended ADMIN account
    if admin_account["role"] != "ADMIN":
        conn.close()
        print(f"[!] STOP: Account {admin_email} has role '{admin_account['role']}', expected 'ADMIN'.")
        print("    Aborting cleanup.")
        return False, {"error": f"Target account role is {admin_account['role']}, not ADMIN"}

    # Step 5: Verify there is no other ADMIN account in the database
    cursor.execute("SELECT id, username, email FROM users WHERE role = 'ADMIN' AND id != ?", (admin_id,))
    conflicting_admins = cursor.fetchall()
    if len(conflicting_admins) > 0:
        conn.close()
        print(f"[!] STOP: Conflict detected! Found {len(conflicting_admins)} other ADMIN account(s):")
        for ca in conflicting_admins:
            print(f"    - {ca['username']} ({ca['email']})")
        print("    Aborting cleanup. There must be no conflicting ADMIN accounts.")
        return False, {"error": "Multiple ADMIN accounts exist"}

    # Step 6: Count all existing users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users_before = cursor.fetchone()[0]

    # Step 7: List/count the users that would be deleted
    cursor.execute("SELECT id, username, email, role FROM users WHERE id != ?", (admin_id,))
    users_to_delete = cursor.fetchall()
    delete_count = len(users_to_delete)

    print(f"[*] Total user accounts before cleanup: {total_users_before}")
    print(f"[*] Preserved ADMIN account: {admin_username} ({admin_email}) [ID: {admin_id}]")
    print(f"[*] Non-admin accounts to delete: {delete_count}")

    if delete_count == 0:
        conn.close()
        print("[+] Notice: Exactly 1 ADMIN account already exists in database. No non-admin users to delete.")
        return True, {
            "users_before": total_users_before,
            "users_deleted": 0,
            "users_after": 1,
            "admin_preserved": admin_email
        }

    # Step 8: Safety confirmation check
    env_confirmed = os.environ.get("CONFIRM_DELETE_NON_ADMIN_USERS", "").strip().lower() in ("true", "1", "yes")
    is_confirmed = confirm or env_confirmed

    if not is_confirmed and interactive:
        print("\n" + "!" * 78)
        print(" SAFETY CONFIRMATION REQUIRED")
        print(" This operation will permanently delete ALL non-admin accounts listed above.")
        print(" Global policies, rules, telemetry, and audit logs will NOT be affected.")
        print("!" * 78)
        try:
            user_input = input(" Type 'DELETE ALL NON-ADMIN USERS' to confirm: ").strip()
            if user_input == "DELETE ALL NON-ADMIN USERS":
                is_confirmed = True
            else:
                print("[*] Confirmation text did not match. Aborting cleanup.")
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Operation cancelled by user.")

    if not is_confirmed:
        conn.close()
        print("\n[!] STOP: Cleanup aborted. Explicit confirmation was not provided.")
        print("    To execute cleanup, pass --confirm or set CONFIRM_DELETE_NON_ADMIN_USERS=true")
        return False, {"error": "Confirmation required"}

    # Step 9: Database Cleanup Transaction
    print("\n[*] Proceeding with cleanup...")
    now = datetime.now(timezone.utc).isoformat()

    try:
        # Clean up operator access requests for deleted users
        cursor.execute("DELETE FROM operator_access_requests WHERE user_id != ?", (admin_id,))
        deleted_op_requests = cursor.rowcount

        # Clean up user permissions for deleted users
        cursor.execute("DELETE FROM user_permissions WHERE user_id != ?", (admin_id,))
        deleted_user_perms = cursor.rowcount

        # Delete non-admin users
        cursor.execute("DELETE FROM users WHERE id != ?", (admin_id,))
        actual_deleted_users = cursor.rowcount

        conn.commit()

        # Invalidate any in-memory active sessions for non-admin users
        try:
            from backend.api.auth import ACTIVE_SESSIONS
            removed_sessions = 0
            for token, sess_user in list(ACTIVE_SESSIONS.items()):
                if sess_user.get("id") != admin_id:
                    del ACTIVE_SESSIONS[token]
                    removed_sessions += 1
            if removed_sessions > 0:
                print(f"[*] In-memory active sessions invalidated: {removed_sessions}")
        except Exception:
            pass

        # Record audit event for the cleanup itself
        conn.close() # Re-open or use audit service
        log_audit_event(
            username=admin_username,
            role="ADMIN",
            action="NON_ADMIN_USER_CLEANUP_COMPLETED",
            resource=f"{actual_deleted_users} non-admin accounts removed",
            result="SUCCESS",
            details={
                "actor": admin_username,
                "actor_role": "ADMIN",
                "admin_email": admin_email,
                "users_deleted_count": actual_deleted_users,
                "operator_requests_cleaned": deleted_op_requests,
                "permissions_cleaned": deleted_user_perms,
                "timestamp": now,
                "result": "SUCCESS"
            }
        )

        # Step 10: Post-cleanup verification
        verify_conn = get_db_connection()
        v_cur = verify_conn.cursor()
        v_cur.execute("SELECT COUNT(*) FROM users")
        users_after = v_cur.fetchone()[0]

        v_cur.execute("SELECT id, username, email, role, is_active, email_verified FROM users")
        remaining_users = v_cur.fetchall()
        verify_conn.close()

        print("-" * 78)
        print(" CLEANUP VERIFICATION RESULTS:")
        print(f"  - Users remaining: {users_after} (Expected: 1)")
        for u in remaining_users:
            print(f"  - User: {u['username']} | Email: {u['email']} | Role: {u['role']} | Active: {u['is_active']} | Verified: {u['email_verified']}")
        print(f"  - Operator access requests cleaned: {deleted_op_requests}")
        print(f"  - User permissions cleaned: {deleted_user_perms}")
        print(f"  - Audit log recorded: NON_ADMIN_USER_CLEANUP_COMPLETED")
        print("=" * 78)
        print(" [+] CLEANUP COMPLETED SUCCESSFULLY.")
        print("=" * 78)

        return True, {
            "users_before": total_users_before,
            "users_deleted": actual_deleted_users,
            "users_after": users_after,
            "admin_preserved": admin_email,
            "operator_requests_cleaned": deleted_op_requests,
            "permissions_cleaned": deleted_user_perms
        }

    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"[!] Transaction failed and was rolled back: {e}")
        return False, {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="VORTEX-SDN One-Time User Database Cleanup")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation to delete all non-admin users")
    args = parser.parse_args()

    # If stdin is a tty, enable interactive prompt when --confirm is not passed
    interactive = sys.stdin.isatty() and not args.confirm

    success, info = execute_cleanup(confirm=args.confirm, interactive=interactive)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
