"""
VORTEX-SDN SMTP Configuration & Verification Utility
Use this script to configure your Gmail SMTP credentials and test live delivery.

Usage:
  Interactive:
    python configure_smtp.py

  Direct:
    python configure_smtp.py <gmail_address> <16_character_app_password>
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.services.email_service import test_smtp_connection, get_smtp_config, load_env_file

def main():
    print("=" * 65)
    print(" VORTEX-SDN Gmail SMTP Configuration Utility")
    print("=" * 65)

    if len(sys.argv) >= 3:
        email = sys.argv[1].strip()
        pwd = sys.argv[2].strip().replace(" ", "")
    else:
        print("\nEnter your Gmail credentials to enable live email verification:")
        try:
            email = input("Gmail Address (e.g. user@gmail.com): ").strip()
            pwd = input("Gmail 16-character App Password: ").strip().replace(" ", "")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return

    if not email or not pwd:
        print("\n[-] Error: Both Gmail address and App Password are required.")
        return

    if len(pwd) != 16:
        print(f"\n[!] Warning: Gmail App Passwords are normally 16 characters (you entered {len(pwd)} chars).")

    existing_base = (os.environ.get("APP_BASE_URL") or "http://127.0.0.1:5000").strip().strip("'\"").rstrip("/")
    env_content = f"""# VORTEX-SDN Environment Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME={email}
SMTP_PASSWORD={pwd}
MAIL_FROM={email}
APP_BASE_URL={existing_base}
SECRET_KEY=vortex-security-secret-key-2026
"""

    env_path = os.path.join(BASE_DIR, ".env")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(env_content)

    print(f"\n[+] Wrote configuration to {env_path}")
    os.environ["SMTP_HOST"] = "smtp.gmail.com"
    os.environ["SMTP_PORT"] = "587"
    os.environ["SMTP_USERNAME"] = email
    os.environ["SMTP_PASSWORD"] = pwd
    os.environ["MAIL_FROM"] = email
    os.environ["APP_BASE_URL"] = existing_base

    print("\n[+] Testing live SMTP connection...")
    success, message = test_smtp_connection(to_email=email)

    if success:
        print("\n" + "=" * 65)
        print(" [SUCCESS] GMAIL SMTP IS FULLY OPERATIONAL!")
        print(f" A test verification email was delivered to: {email}")
        print(" You can now open http://127.0.0.1:5000/register and register your account.")
        print("=" * 65 + "\n")
    else:
        print("\n" + "=" * 65)
        print(" [-] SMTP TEST FAILED")
        print(f" Details: {message}")
        print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
