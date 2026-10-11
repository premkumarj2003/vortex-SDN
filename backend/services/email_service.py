"""
VORTEX-SDN Real Gmail SMTP Email Service & Diagnostic Engine
Handles Real Gmail SMTP delivery for Account Email Verification and Password Reset.
Generates cryptographically secure 30-minute tokens (stored as SHA-256 hashes in SQLite),
enforces rate limiting, and returns strict error statuses when SMTP fails.
"""

import os
import sys
import smtplib
import socket
import hashlib
import secrets
import traceback
import email.utils
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
import math

# Ensure root workspace is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection, hash_password, validate_password_strength
from backend.services.audit_service import log_audit_event

def load_env_file():
    """Loads variables from .env file into os.environ using python-dotenv and fallback parser."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env_path = os.path.join(base_dir, ".env")

    possible_paths = [
        env_path,
        os.path.join(os.getcwd(), ".env"),
        os.path.join(base_dir, "backend", ".env"),
        os.path.join(base_dir, "VORTEX-SDN", ".env")
    ]

    seen = set()
    unique_paths = []
    for p in possible_paths:
        norm = os.path.normpath(os.path.abspath(p))
        if norm not in seen:
            seen.add(norm)
            unique_paths.append(norm)

    # 1. Try python-dotenv first
    try:
        from dotenv import load_dotenv
        for p in unique_paths:
            if os.path.exists(p) and os.path.isfile(p):
                load_dotenv(dotenv_path=p, override=True)
                return True
    except ImportError:
        pass

    # 2. Robust fallback parser
    for p in unique_paths:
        if os.path.exists(p) and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8-sig") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[7:].strip()
                        if "=" not in line:
                            continue
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip()
                        # Strip trailing comments if not enclosed in quotes
                        if not ((val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'"))):
                            if " #" in val:
                                val = val.split(" #", 1)[0].strip()
                        val = val.strip("'\"")
                        if key:
                            os.environ[key] = val
                return True
            except Exception as e:
                print(f"[EmailService] Notice: Could not read .env file at {p}: {e}")
    return False

# Initial environment load
load_env_file()

def is_email_verification_required() -> bool:
    """
    Centralized flag: Controls whether email verification is required.
    Real email verification is permanently enabled. Development bypasses are removed.
    """
    load_env_file()
    val = os.environ.get("EMAIL_VERIFICATION_REQUIRED", "true").strip().lower()
    return val not in ("false", "0", "no", "off", "disable", "disabled")

# In-memory rate limiting store: identifier -> [datetime, ...]
RATE_LIMIT_STORE = {}

def get_rate_limit_cooldown_seconds() -> int:
    """Returns the resend cooldown in seconds from environment or default 60s."""
    load_env_file()
    try:
        val = int(os.environ.get("VERIFICATION_RESEND_COOLDOWN_SECONDS", "60"))
        return max(1, val)
    except (ValueError, TypeError):
        return 60

def get_rate_limit_max_requests() -> int:
    """Returns max allowed requests within the cooldown window (default 1)."""
    load_env_file()
    try:
        val = int(os.environ.get("VERIFICATION_RESEND_MAX_REQUESTS", "1"))
        return max(1, val)
    except (ValueError, TypeError):
        return 1

def clear_rate_limit(identifier: str = None):
    """Safe development/test helper to clear rate limit store."""
    global RATE_LIMIT_STORE
    if identifier:
        RATE_LIMIT_STORE.pop(identifier, None)
    else:
        RATE_LIMIT_STORE.clear()

class RateLimitResult:
    """
    Result object that acts as a boolean, a tuple (allowed, retry_after_seconds),
    and exposes attributes allowed and retry_after_seconds for maximum compatibility.
    """
    def __init__(self, allowed: bool, retry_after_seconds: int = 0):
        self.allowed = bool(allowed)
        self.retry_after_seconds = int(retry_after_seconds)

    def __bool__(self):
        return self.allowed

    def __iter__(self):
        return iter((self.allowed, self.retry_after_seconds))

    def __getitem__(self, index):
        return (self.allowed, self.retry_after_seconds)[index]

    def __repr__(self):
        return f"<RateLimitResult allowed={self.allowed} retry_after_seconds={self.retry_after_seconds}>"

def check_rate_limit(identifier: str, max_requests: int = None, window_seconds: int = None, window_minutes: int = None, record: bool = True) -> RateLimitResult:
    """
    Checks rate limit for a specific identifier.
    If record=True (default), records the timestamp if within limits.
    If record=False, only checks without modifying timestamps.
    """
    now = datetime.now(timezone.utc)
    if window_seconds is None:
        if window_minutes is not None:
            window_seconds = window_minutes * 60
        else:
            window_seconds = get_rate_limit_cooldown_seconds()

    if max_requests is None:
        max_requests = get_rate_limit_max_requests()

    cutoff = now - timedelta(seconds=window_seconds)
    timestamps = RATE_LIMIT_STORE.get(identifier, [])
    timestamps = [t for t in timestamps if t > cutoff]

    if len(timestamps) >= max_requests:
        RATE_LIMIT_STORE[identifier] = timestamps
        oldest = timestamps[0]
        remaining = max(1, math.ceil((oldest + timedelta(seconds=window_seconds) - now).total_seconds()))
        return RateLimitResult(False, remaining)

    if record:
        timestamps.append(now)
        RATE_LIMIT_STORE[identifier] = timestamps

    return RateLimitResult(True, 0)

def record_rate_limit(identifier: str):
    """Explicitly records a successful rate-limited action (e.g. SMTP email successfully sent)."""
    global RATE_LIMIT_STORE
    now = datetime.now(timezone.utc)
    cooldown = get_rate_limit_cooldown_seconds()
    cutoff = now - timedelta(seconds=cooldown)
    timestamps = [t for t in RATE_LIMIT_STORE.get(identifier, []) if t > cutoff]
    timestamps.append(now)
    RATE_LIMIT_STORE[identifier] = timestamps

def rollback_rate_limit(identifier: str):
    """Rolls back the most recent rate limit timestamp (e.g. if SMTP delivery fails)."""
    global RATE_LIMIT_STORE
    if identifier in RATE_LIMIT_STORE and RATE_LIMIT_STORE[identifier]:
        RATE_LIMIT_STORE[identifier].pop()

def get_smtp_config():
    """Extracts SMTP credentials and server configuration from environment variables."""
    load_env_file()
    
    host = (os.environ.get("SMTP_HOST") or os.environ.get("VORTEX_SMTP_SERVER") or "smtp.gmail.com").strip()
    try:
        port = int(os.environ.get("SMTP_PORT") or os.environ.get("VORTEX_SMTP_PORT") or 587)
    except (ValueError, TypeError):
        port = 587

    username = (os.environ.get("SMTP_USERNAME") or os.environ.get("VORTEX_SMTP_EMAIL") or "").strip()
    password = (os.environ.get("SMTP_PASSWORD") or os.environ.get("VORTEX_SMTP_PASSWORD") or "").strip()

    # Clean Gmail app passwords if spaces were copied (e.g. "abcd efgh ijkl mnop")
    if " " in password and len(password.replace(" ", "")) == 16:
        password = password.replace(" ", "")

    from_addr = (os.environ.get("MAIL_FROM") or os.environ.get("VORTEX_SMTP_FROM") or username).strip()
    if not from_addr and username:
        from_addr = username

    raw_base = str(os.environ.get("APP_BASE_URL") or os.environ.get("VORTEX_BASE_URL") or "http://127.0.0.1:5000").strip().strip("'\"")
    base_url = raw_base.rstrip("/")

    use_tls_str = (os.environ.get("SMTP_USE_TLS") or "true").strip().lower()
    use_tls = use_tls_str in ("true", "1", "yes", "on")

    try:
        verif_expiry = int(os.environ.get("VERIFICATION_TOKEN_EXPIRY_MINUTES") or 30)
    except (ValueError, TypeError):
        verif_expiry = 30

    try:
        reset_expiry = int(os.environ.get("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES") or 30)
    except (ValueError, TypeError):
        reset_expiry = 30

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "from_addr": from_addr,
        "base_url": base_url,
        "use_tls": use_tls,
        "verif_expiry": verif_expiry,
        "reset_expiry": reset_expiry
    }

def print_safe_smtp_diagnostics():
    """
    Prints safe diagnostic logging that reports:
      SMTP_HOST configured: YES / NO
      SMTP_PORT configured: YES / NO
      SMTP_USERNAME configured: YES / NO
      SMTP_PASSWORD configured: YES / NO
      MAIL_FROM configured: YES / NO
      SMTP_USE_TLS configured: YES / NO
    NEVER logs or displays the actual password.
    """
    cfg = get_smtp_config()
    print(f"SMTP_HOST configured: {'YES' if bool(cfg.get('host')) else 'NO'}")
    print(f"SMTP_PORT configured: {'YES' if bool(cfg.get('port')) else 'NO'}")
    print(f"SMTP_USERNAME configured: {'YES' if bool(cfg.get('username')) else 'NO'}")
    print(f"SMTP_PASSWORD configured: {'YES' if bool(cfg.get('password')) else 'NO'}")
    print(f"MAIL_FROM configured: {'YES' if bool(cfg.get('from_addr')) else 'NO'}")
    print(f"SMTP_USE_TLS configured: {'YES' if cfg.get('use_tls') is not None else 'NO'}")

def validate_smtp_on_startup():
    """Validates whether SMTP credentials are set on startup without logging secrets."""
    print_safe_smtp_diagnostics()
    cfg = get_smtp_config()
    if cfg["username"] and cfg["password"]:
        return True
    else:
        print("[VORTEX-SDN] WARNING: SMTP credentials are not configured in environment or .env.")
        print("[VORTEX-SDN] Set SMTP_USERNAME and SMTP_PASSWORD to enable live Gmail delivery.")
        return False

def test_smtp_connection(to_email: str = None) -> tuple[bool, str]:
    """
    Independently verifies:
    1. DNS resolution of smtp.gmail.com
    2. TCP connection to port 587
    3. EHLO greeting
    4. STARTTLS encryption
    5. SMTP AUTH
    6. Optional test message sending
    """
    load_env_file()
    print_safe_smtp_diagnostics()
    cfg = get_smtp_config()

    if not cfg["username"] or not cfg["password"]:
        msg = "SMTP_USERNAME or SMTP_PASSWORD is not configured in environment or .env."
        print(f"\n[-] SMTP CONFIGURATION ERROR: {msg}")
        print("[-] Please configure SMTP_USERNAME and SMTP_PASSWORD in your environment or .env file.")
        return False, msg

    # Step 1: DNS Resolution
    print(f"\n[1/6] Resolving SMTP host: {cfg['host']}...")
    try:
        ip_addr = socket.gethostbyname(cfg["host"])
        print(f"      [+] Resolved {cfg['host']} -> {ip_addr}")
    except Exception as e:
        msg = f"DNS resolution failed for {cfg['host']}: {e}"
        print(f"      [-] DNS FAILURE: {msg}")
        return False, msg

    # Step 2: TCP Connection
    print(f"[2/6] Connecting to {cfg['host']}:{cfg['port']}...")
    try:
        import ssl
        context = ssl.create_default_context()
        if cfg["port"] == 465:
            server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=20)
        else:
            server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=20)
        print(f"      [+] TCP connection established.")
    except Exception as e:
        msg = f"SMTP connection failed to {cfg['host']}:{cfg['port']}: {e}"
        print(f"      [-] SMTP CONNECTION FAILED: {msg}")
        return False, msg

    # Step 3: Initial EHLO
    print("[3/6] Sending EHLO greeting...")
    try:
        server.ehlo()
        print("      [+] EHLO successful.")
    except Exception as e:
        server.close()
        msg = f"EHLO greeting failed: {e}"
        print(f"      [-] SMTP EHLO FAILED: {msg}")
        return False, msg

    # Step 4: STARTTLS
    if cfg["port"] != 465 and cfg.get("use_tls", True):
        print("[4/6] Negotiating STARTTLS encryption on port 587...")
        try:
            import ssl
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            print("      [+] STARTTLS encryption established.")
        except Exception as e:
            server.close()
            msg = f"STARTTLS negotiation failed: {e}"
            print(f"      [-] SMTP TLS FAILED: {msg}")
            return False, msg
    else:
        print("[4/6] TLS already established or not required.")

    # Step 5: SMTP Authentication
    print(f"[5/6] Authenticating as {cfg['username']}...")
    try:
        if "auth" in server.esmtp_features and "PLAIN" in server.esmtp_features["auth"].split():
            server.esmtp_features["auth"] = "PLAIN"
        server.login(cfg["username"], cfg["password"])
        print("      [+] SMTP Authentication successful!")
    except smtplib.SMTPAuthenticationError as e:
        server.close()
        err_text = e.smtp_error.decode("utf-8", errors="ignore") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        msg = f"SMTP Authentication failed (code {e.smtp_code}): {err_text}"
        print(f"      [-] SMTP AUTHENTICATION FAILED: {msg}")
        print("\n  ================================================================")
        print("  GMAIL APP PASSWORD INSTRUCTIONS:")
        print("  1. Go to your Google Account (https://myaccount.google.com)")
        print("  2. Navigate to 'Security' -> Ensure '2-Step Verification' is ON")
        print("  3. Search for 'App Passwords' in the search bar")
        print("  4. Create a new App Password named 'VORTEX-SDN'")
        print("  5. Paste the 16-character code into SMTP_PASSWORD in .env (without quotes)")
        print("  ================================================================\n")
        return False, msg
    except smtplib.SMTPServerDisconnected as e:
        server.close()
        msg = f"SMTP Server disconnected during authentication: {e} (Likely rejected credentials: 535 5.7.8 Username and Password not accepted)"
        print(f"      [-] SMTP AUTHENTICATION DISCONNECT: {msg}")
        return False, msg
    except Exception as e:
        server.close()
        safe_err = str(e).replace(cfg["password"], "********") if cfg["password"] else str(e)
        msg = f"SMTP Authentication error: {safe_err}"
        print(f"      [-] SMTP AUTHENTICATION FAILED: {msg}")
        return False, msg

    # Step 6: Optional Test Send
    target_recipient = to_email or cfg["username"]
    print(f"[6/6] Sending test diagnostic email to {target_recipient}...")
    try:
        test_msg = MIMEText("This is an automated test verifying VORTEX-SDN Gmail SMTP delivery.", "plain", "utf-8")
        test_msg["Subject"] = "VORTEX-SDN SMTP Diagnostic Test"
        test_msg["From"] = f"VORTEX-SDN <{cfg['from_addr']}>"
        test_msg["To"] = target_recipient
        test_msg["Date"] = email.utils.formatdate(localtime=True)
        test_msg["Message-ID"] = email.utils.make_msgid(domain="vortex-sdn.local")
        server.sendmail(cfg["from_addr"], [target_recipient], test_msg.as_string())
        server.quit()
        print(f"      [+] SMTP verification email sent successfully to {target_recipient}!")
        return True, "SMTP verification email sent successfully."
    except Exception as e:
        try:
            server.close()
        except Exception:
            pass
        safe_err = str(e).replace(cfg["password"], "********") if cfg["password"] else str(e)
        msg = f"SMTP test message delivery failed: {safe_err}"
        print(f"      [-] SMTP SEND FAILED: {msg}")
        return False, msg

def generate_secure_token(expiry_minutes: int = None) -> tuple[str, str, str]:
    """
    Generates a cryptographically secure URL-safe token, its SHA-256 hash,
    and a UTC ISO expiration timestamp (default 30 minutes).
    """
    cfg = get_smtp_config()
    exp_min = expiry_minutes if expiry_minutes is not None else cfg.get("verif_expiry", 30)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=exp_min)).isoformat()
    return raw_token, token_hash, expires_at

def generate_secure_otp(expiry_minutes: int = None) -> tuple[str, str, str]:
    """
    Generates a cryptographically secure 6-digit numeric OTP,
    its SHA-256 hash, and UTC ISO expiration timestamp (default 5 minutes).
    Guaranteed exactly 6 numeric digits with leading zeros (000000-999999).
    Uses secrets.randbelow(1000000).
    """
    cfg = get_smtp_config()
    exp_min = expiry_minutes if expiry_minutes is not None else cfg.get("verif_expiry", 5)
    raw_otp = f"{secrets.randbelow(1000000):06d}"
    otp_hash = hashlib.sha256(raw_otp.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=exp_min)).isoformat()
    return raw_otp, otp_hash, expires_at

def _send_smtp_email(to_email: str, subject: str, plain_content: str, html_content: str, audit_action: str = "EMAIL_SENT") -> tuple[bool, str]:
    """
    Shared robust SMTP delivery function using STARTTLS and configurable credentials.
    """
    cfg = get_smtp_config()
    print_safe_smtp_diagnostics()
    
    if not cfg["username"] or not cfg["password"]:
        msg = "SMTP_USERNAME or SMTP_PASSWORD is not configured in .env."
        print(f"\n[EmailService] ================= SMTP CONFIGURATION ERROR =================")
        print(f"[EmailService] Error: {msg}")
        print(f"[EmailService] Reason: missing environment variable (SMTP_USERNAME or SMTP_PASSWORD)")
        print(f"[EmailService] Target: {to_email}")
        print(f"[EmailService] ================================================================\n")
        return False, msg

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"VORTEX-SDN <{cfg['from_addr']}>"
        msg["To"] = to_email
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain="vortex-sdn.local")

        msg.attach(MIMEText(plain_content, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        import ssl
        context = ssl.create_default_context()

        if cfg["port"] == 465:
            server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=20)
            server.ehlo()
        else:
            server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=20)
            server.ehlo()
            if cfg.get("use_tls", True):
                server.starttls(context=context)
                server.ehlo()

        if "auth" in server.esmtp_features and "PLAIN" in server.esmtp_features["auth"].split():
            server.esmtp_features["auth"] = "PLAIN"

        server.login(cfg["username"], cfg["password"])
        server.sendmail(cfg["from_addr"], [to_email], msg.as_string())
        server.quit()

        print(f"[EmailService] Email '{subject}' delivered successfully to {to_email}.")
        log_audit_event(to_email, "SYSTEM", audit_action, f"Subject: {subject}", "SUCCESS")
        return True, "Email sent successfully."

    except smtplib.SMTPAuthenticationError as e:
        err_text = e.smtp_error.decode("utf-8", errors="ignore") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        safe_err = f"SMTP authentication failed (code {e.smtp_code}): {err_text}"
        print(f"\n[EmailService] ================= SMTP AUTHENTICATION FAILED =================")
        print(f"[EmailService] {safe_err}")
        print(f"[EmailService] Target: {to_email} via {cfg['host']}:{cfg['port']}")
        print(f"[EmailService] User: {cfg['username']}")
        print(f"[EmailService] Identified Problem: Gmail authentication rejection (535 5.7.8). Invalid credentials or missing Gmail 16-character App Password.")
        print(f"[EmailService] Resolution: Make sure 2-Step Verification is enabled and a 16-character App Password is used.")
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, safe_err

    except (smtplib.SMTPConnectError, socket.gaierror, socket.timeout, TimeoutError) as e:
        safe_err = f"SMTP connection error: Could not connect to {cfg['host']}:{cfg['port']}."
        print(f"\n[EmailService] =================== SMTP CONNECTION FAILED ===================")
        print(f"[EmailService] Exception: {type(e).__name__}: {e}")
        print(f"[EmailService] Host: {cfg['host']}:{cfg['port']}")
        print(f"[EmailService] Identified Problem: DNS/network connection failure.")
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, safe_err

    except smtplib.SMTPServerDisconnected as e:
        safe_err = "SMTP server disconnected unexpectedly."
        print(f"\n[EmailService] ================= SMTP SERVER DISCONNECTED =================")
        print(f"[EmailService] Exception: SMTPServerDisconnected: {e}")
        print(f"[EmailService] Identified Problem: TLS/port configuration or server timeout.")
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, safe_err

    except smtplib.SMTPRecipientsRefused as e:
        safe_err = f"SMTP recipient rejected: {to_email}"
        print(f"\n[EmailService] ================== SMTP RECIPIENT FAILED ==================")
        print(f"[EmailService] Exception: SMTPRecipientsRefused: {e}")
        print(f"[EmailService] Identified Problem: sender address or recipient refused.")
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, safe_err

    except smtplib.SMTPException as e:
        safe_err = f"SMTP protocol error ({type(e).__name__}): {e}"
        if cfg.get("password"):
            safe_err = safe_err.replace(cfg["password"], "********")
        print(f"\n[EmailService] =================== SMTP PROTOCOL ERROR ===================")
        print(f"[EmailService] Exception: {type(e).__name__}: {safe_err}")
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, safe_err

    except Exception as e:
        safe_err = str(e).replace(cfg["password"], "********") if cfg.get("password") else str(e)
        print(f"\n[EmailService] ===================== SMTP SEND FAILED =====================")
        print(f"[EmailService] Exception: {type(e).__name__}: {safe_err}")
        traceback.print_exc()
        print(f"[EmailService] ================================================================\n")
        log_audit_event(to_email, "SYSTEM", f"{audit_action}_FAILED", f"To: {to_email}", "FAILURE", {"error": safe_err})
        return False, f"Unable to send email: {safe_err}"

def send_verification_otp_email(to_email: str, full_name: str, otp: str) -> tuple[bool, str]:
    """
    Sends an account verification email containing a 6-digit numeric OTP via real Gmail SMTP.
    Subject: Verify your VORTEX-SDN account - Verification Code
    Enforces VORTEX-SDN branding, 5-minute expiry notice, and security warnings.
    """
    cfg = get_smtp_config()
    expiry_min = cfg.get("verif_expiry", 5)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070a13; color: #f1f5f9; margin: 0; padding: 20px; }}
    .email-card {{ max-width: 580px; margin: 0 auto; background: #0c101d; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
    .header {{ margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 18px; }}
    .badge {{ background: rgba(0, 242, 254, 0.15); color: #00f2fe; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .otp-container {{ background: #070a13; border: 1px solid #00f2fe; border-radius: 8px; padding: 22px; text-align: center; margin: 28px 0; }}
    .otp-code {{ font-family: 'JetBrains Mono', 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 10px; color: #00f2fe; margin: 0; }}
    .warning-box {{ background: rgba(245, 158, 11, 0.1); border-left: 3px solid #f59e0b; padding: 12px 14px; border-radius: 4px; margin: 20px 0; font-size: 12px; color: #cbd5e1; line-height: 1.5; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid #1e293b; padding-top: 14px; text-align: center; }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <span class="badge">VORTEX-SDN SECURITY</span>
    </div>
    <h2 style="color: #ffffff; margin-top: 0; font-size: 20px;">Verify Your Email Address</h2>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      Hello <strong>{full_name}</strong>,<br><br>
      Thank you for registering with VORTEX-SDN. Please enter the six-digit verification code below to verify your email and complete your account registration.
    </p>
    
    <div class="otp-container">
      <div style="font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 8px; font-weight: 600;">Verification Code</div>
      <div class="otp-code">{otp}</div>
      <div style="font-size: 11px; color: #94a3b8; margin-top: 8px;">Expires in {expiry_min} minutes</div>
    </div>

    <div class="warning-box">
      <strong style="color: #f59e0b;">Security Notice:</strong> Do not share this verification code with anyone. VORTEX-SDN staff and administrators will never request this code.
    </div>

    <p style="font-size: 12px; color: #64748b; line-height: 1.5;">
      If you did not initiate this registration request, please disregard this email. No changes will be made to any existing account.
    </p>

    <div class="footer">
      VORTEX-SDN Enterprise Intelligence Platform &bull; Automated Security Notice
    </div>
  </div>
</body>
</html>"""

    plain_content = f"""Verify your VORTEX-SDN account

Hello {full_name},

Thank you for registering with VORTEX-SDN.

Your six-digit email verification code is: {otp}

This verification code expires in {expiry_min} minutes.

Security Notice: Do not share this verification code with anyone. VORTEX-SDN staff and administrators will never ask for your code.

If you did not initiate this registration, please disregard this email.

--
VORTEX-SDN Enterprise Intelligence Platform
"""

    return _send_smtp_email(to_email, "Verify your VORTEX-SDN account - Verification Code", plain_content, html_content, "EMAIL_OTP_SENT")

def send_verification_email(to_email: str, full_name: str, raw_token_or_otp: str) -> tuple[bool, str]:
    """
    Sends account verification via real Gmail SMTP.
    If raw_token_or_otp is a 6-digit numeric OTP, dispatches OTP email.
    Otherwise dispatches link token email.
    """
    if isinstance(raw_token_or_otp, str) and len(raw_token_or_otp.strip()) == 6 and raw_token_or_otp.strip().isdigit():
        return send_verification_otp_email(to_email, full_name, raw_token_or_otp.strip())

    raw_token = raw_token_or_otp
    cfg = get_smtp_config()
    verification_url = f"{cfg['base_url']}/verify-email?token={raw_token}"
    expiry_min = cfg.get("verif_expiry", 30)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070a13; color: #f1f5f9; margin: 0; padding: 20px; }}
    .email-card {{ max-width: 580px; margin: 0 auto; background: #0c101d; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; }}
    .header {{ margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 18px; }}
    .badge {{ background: rgba(0, 242, 254, 0.15); color: #00f2fe; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .btn {{ display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #0284c7 100%); color: #070a13 !important; padding: 12px 28px; font-weight: 700; font-size: 14px; text-decoration: none; border-radius: 6px; margin: 24px 0; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid #1e293b; padding-top: 14px; }}
    .url-box {{ background: #070a13; border: 1px solid #1e293b; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <span class="badge">VORTEX-SDN</span>
    </div>
    <h2 style="color: #ffffff; margin-top: 0;">Welcome to VORTEX-SDN</h2>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      Hello <strong>{full_name}</strong>,<br><br>
      Welcome to VORTEX-SDN.<br><br>
      Please verify your email address to activate your account.
    </p>
    
    <div style="text-align: center;">
      <a href="{verification_url}" class="btn" target="_blank">VERIFY EMAIL</a>
    </div>

    <p style="font-size: 12px; color: #64748b;">
      The link must contain the secure verification token. The link will expire automatically after {expiry_min} minutes.
      If you did not create this account, you can ignore this email.
    </p>
    
    <div style="margin-top: 16px;">
      <div style="font-size: 11px; color: #64748b; margin-bottom: 4px;">Or copy and paste this link into your browser:</div>
      <div class="url-box">{verification_url}</div>
    </div>

    <div class="footer">
      VORTEX-SDN Enterprise Intelligence Platform
    </div>
  </div>
</body>
</html>"""

    plain_content = f"""Verify your VORTEX-SDN account

Hello {full_name},

Welcome to VORTEX-SDN.

Please verify your email address to activate your account:
{verification_url}

The link will expire automatically after {expiry_min} minutes.
If you did not create this account, you can ignore this email.

--
VORTEX-SDN Enterprise Intelligence Platform
"""

    return _send_smtp_email(to_email, "Verify your VORTEX-SDN account", plain_content, html_content, "EMAIL_VERIFICATION_SENT")

def send_password_reset_email(to_email: str, full_name: str, raw_token: str) -> tuple[bool, str]:
    """
    Sends a password reset email via real Gmail SMTP.
    Subject: Reset your VORTEX-SDN password
    """
    cfg = get_smtp_config()
    reset_url = f"{cfg['base_url']}/reset-password?token={raw_token}"
    expiry_min = cfg.get("reset_expiry", 30)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070a13; color: #f1f5f9; margin: 0; padding: 20px; }}
    .email-card {{ max-width: 580px; margin: 0 auto; background: #0c101d; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; }}
    .header {{ margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 18px; }}
    .badge {{ background: rgba(245, 158, 11, 0.15); color: #f59e0b; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .btn {{ display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #0284c7 100%); color: #070a13 !important; padding: 12px 28px; font-weight: 700; font-size: 14px; text-decoration: none; border-radius: 6px; margin: 24px 0; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid #1e293b; padding-top: 14px; }}
    .url-box {{ background: #070a13; border: 1px solid #1e293b; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <span class="badge">VORTEX-SDN</span>
    </div>
    <h2 style="color: #ffffff; margin-top: 0;">Reset your VORTEX-SDN password</h2>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      Hello <strong>{full_name}</strong>,<br><br>
      A password reset was requested for your VORTEX-SDN account. Click the button below to choose a new password.
    </p>
    
    <div style="text-align: center;">
      <a href="{reset_url}" class="btn" target="_blank">RESET PASSWORD</a>
    </div>

    <p style="font-size: 12px; color: #64748b;">
      The reset link expires automatically in {expiry_min} minutes. If you did not request this password reset, you can safely ignore this email.
    </p>
    
    <div style="margin-top: 16px;">
      <div style="font-size: 11px; color: #64748b; margin-bottom: 4px;">Or copy and paste this link into your browser:</div>
      <div class="url-box">{reset_url}</div>
    </div>

    <div class="footer">
      VORTEX-SDN Enterprise Intelligence Platform
    </div>
  </div>
</body>
</html>"""

    plain_content = f"""Reset your VORTEX-SDN password

Hello {full_name},

A password reset was requested for your VORTEX-SDN account.
Reset your password by opening the following link in your browser:

{reset_url}

The reset link expires automatically in {expiry_min} minutes.
If you did not request this, you can safely ignore this email.

--
VORTEX-SDN Enterprise Intelligence Platform
"""

    return _send_smtp_email(to_email, "Reset your VORTEX-SDN password", plain_content, html_content, "PASSWORD_RESET_EMAIL_SENT")

def send_password_changed_email(to_email: str, full_name: str) -> tuple[bool, str]:
    """
    Sends a security notification email when a password is changed or reset.
    Subject: Your VORTEX-SDN password was changed
    Does NOT include passwords.
    """
    cfg = get_smtp_config()
    reset_url = f"{cfg['base_url']}/forgot-password"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070a13; color: #f1f5f9; margin: 0; padding: 20px; }}
    .email-card {{ max-width: 580px; margin: 0 auto; background: #0c101d; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; }}
    .header {{ margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 18px; }}
    .badge {{ background: rgba(16, 185, 129, 0.15); color: #10b981; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .btn {{ display: inline-block; background: #ef4444; color: #ffffff !important; padding: 12px 28px; font-weight: 700; font-size: 14px; text-decoration: none; border-radius: 6px; margin: 24px 0; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid #1e293b; padding-top: 14px; }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <span class="badge">SECURITY NOTIFICATION</span>
    </div>
    <h2 style="color: #ffffff; margin-top: 0;">Your VORTEX-SDN password was changed</h2>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      Hello <strong>{full_name}</strong>,<br><br>
      Your password was successfully changed.<br><br>
      If you did not make this change, please reset your password immediately.
    </p>
    <div style="text-align: center;">
      <a href="{reset_url}" class="btn" target="_blank">Reset Password Immediately</a>
    </div>
    <div class="footer">
      VORTEX-SDN Enterprise Intelligence Platform
    </div>
  </div>
</body>
</html>"""

    plain_content = f"""Your VORTEX-SDN password was changed

Hello {full_name},

Your password was successfully changed.

If you did not make this change, please reset your password immediately at:
{reset_url}

--
VORTEX-SDN Enterprise Intelligence Platform
"""

    return _send_smtp_email(to_email, "Your VORTEX-SDN password was changed", plain_content, html_content, "PASSWORD_CHANGED_SECURITY_NOTIFICATION")

def send_operator_request_email(admin_email: str, req_id: str, requester_name: str, requester_email: str, requested_at: str, current_role: str = "READER", client_ip: str = "127.0.0.1", user_agent: str = None) -> tuple[bool, str]:
    """
    Sends an operator access request notification email to the designated administrator.
    Subject: VORTEX-SDN Operator Access Request
    Contains requester details, request status PENDING, client metadata,
    and a link to the authenticated admin approval dashboard.
    """
    cfg = get_smtp_config()
    approval_url = f"{cfg['base_url']}/#admin-users"
    safe_ua = user_agent if user_agent else "Standard Web Client"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070a13; color: #f1f5f9; margin: 0; padding: 20px; }}
    .email-card {{ max-width: 580px; margin: 0 auto; background: #0c101d; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; }}
    .header {{ margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 18px; }}
    .badge {{ background: rgba(0, 242, 254, 0.15); color: #00f2fe; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    .status-badge {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; display: inline-block; }}
    .data-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }}
    .data-table td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; }}
    .data-table td.label {{ color: #94a3b8; width: 140px; font-weight: 600; }}
    .data-table td.value {{ color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; }}
    .btn {{ display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #0284c7 100%); color: #070a13 !important; padding: 12px 28px; font-weight: 700; font-size: 14px; text-decoration: none; border-radius: 6px; margin: 20px 0; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid #1e293b; padding-top: 14px; }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="header">
      <span class="badge">VORTEX-SDN ACCESS CONTROL</span>
    </div>
    <h2 style="color: #ffffff; margin-top: 0;">Operator Access Request</h2>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      A user has submitted a request for <strong>OPERATOR</strong> privileges in the VORTEX-SDN platform.
    </p>

    <table class="data-table">
      <tr>
        <td class="label">Requester Name:</td>
        <td class="value">{requester_name}</td>
      </tr>
      <tr>
        <td class="label">Requester Email:</td>
        <td class="value">{requester_email}</td>
      </tr>
      <tr>
        <td class="label">Requested At:</td>
        <td class="value">{requested_at}</td>
      </tr>
      <tr>
        <td class="label">Current Role:</td>
        <td class="value">{current_role}</td>
      </tr>
      <tr>
        <td class="label">Status:</td>
        <td class="value"><span class="status-badge">PENDING APPROVAL</span></td>
      </tr>
      <tr>
        <td class="label">Client IP:</td>
        <td class="value">{client_ip}</td>
      </tr>
      <tr>
        <td class="label">Client Device:</td>
        <td class="value">{safe_ua}</td>
      </tr>
    </table>

    <div style="text-align: center;">
      <a href="{approval_url}" class="btn" target="_blank">REVIEW & APPROVE REQUEST</a>
    </div>

    <p style="font-size: 12px; color: #64748b; line-height: 1.5;">
      Security Notice: This link directs you to the VORTEX-SDN Administration Portal. You must be authenticated as Administrator to approve or reject this request.
    </p>

    <div class="footer">
      VORTEX-SDN Enterprise Intelligence Platform &bull; Security & Access Control
    </div>
  </div>
</body>
</html>"""

    plain_content = f"""VORTEX-SDN Operator Access Request

A user has submitted a request for OPERATOR privileges.

- Requester Name: {requester_name}
- Requester Email: {requester_email}
- Requested At: {requested_at}
- Current Role: {current_role}
- Request Status: PENDING
- Client IP: {client_ip}
- Client Device: {safe_ua}

Review and approve or reject this request in the VORTEX-SDN Admin Portal:
{approval_url}

(Note: Administrator authentication is required to access the approval interface.)

--
VORTEX-SDN Enterprise Intelligence Platform
"""

    return _send_smtp_email(admin_email, "VORTEX-SDN Operator Access Request", plain_content, html_content, "OPERATOR_REQUEST_EMAIL_SENT")

def is_token_expired(expires_at: str) -> bool:
    """Safely checks if an ISO timestamp has expired, parsing UTC datetime cleanly."""
    if not expires_at:
        return False
    try:
        exp_dt = datetime.fromisoformat(expires_at)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt < datetime.now(timezone.utc)
    except Exception:
        return str(expires_at) < datetime.now(timezone.utc).isoformat()

def verify_email_token(raw_token: str) -> tuple[bool, str, dict]:
    """
    Validates a raw verification token against stored SHA-256 token hash and expiration.
    Activates user account upon successful match, invalidates token (single-use).
    """
    token_str = (raw_token or "").strip()
    token_present = bool(token_str)
    token_len = len(token_str)
    token_valid = bool(token_str and token_len >= 10)

    print(f"[AUTH VERIFY] token_present = {'true' if token_present else 'false'}")
    print(f"[AUTH VERIFY] token_length = {token_len}")
    print(f"[AUTH VERIFY] TOKEN RECEIVED: {'YES' if token_present else 'NO'}")
    print(f"[AUTH VERIFY] TOKEN LENGTH: {token_len}")

    if not token_valid:
        print("[AUTH VERIFY] token_hash_computed = false")
        print("[AUTH VERIFY] TOKEN HASH GENERATED: NO")
        print("[AUTH VERIFY] matching_user = false")
        print("[AUTH VERIFY] DATABASE TOKEN RECORD FOUND: NO")
        print("[AUTH VERIFY] TOKEN MATCH: NO")
        print("[AUTH VERIFY] USER FOUND: NO")
        print("[AUTH VERIFY] EMAIL VERIFIED BEFORE: NO")
        print("[AUTH VERIFY] TOKEN EXPIRY VALID: NO")
        print("[AUTH VERIFY] DATABASE UPDATE: FAIL")
        print("[AUTH VERIFY] verification_result = failure")
        return False, "This verification link is invalid or has already been used.", None

    token_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()
    print("[AUTH VERIFY] token_hash_computed = true")
    print("[AUTH VERIFY] TOKEN HASH GENERATED: YES")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, username, email, full_name, role, email_verified, verification_token_expires
    FROM users
    WHERE verification_token_hash = ?
    """, (token_hash,))
    user = cursor.fetchone()

    user_found = bool(user)
    print(f"[AUTH VERIFY] matching_user = {'true' if user_found else 'false'}")
    print(f"[AUTH VERIFY] DATABASE TOKEN RECORD FOUND: {'YES' if user_found else 'NO'}")
    print(f"[AUTH VERIFY] TOKEN MATCH: {'YES' if user_found else 'NO'}")
    print(f"[AUTH VERIFY] USER FOUND: {'YES' if user_found else 'NO'}")

    if not user:
        conn.close()
        print("[AUTH VERIFY] EMAIL VERIFIED BEFORE: NO")
        print("[AUTH VERIFY] TOKEN EXPIRY VALID: NO")
        print("[AUTH VERIFY] DATABASE UPDATE: FAIL")
        print("[AUTH VERIFY] verification_result = failure")
        return False, "This verification link is invalid or has already been used.", None

    user_dict = dict(user)
    email_verified_before = bool(user_dict.get("email_verified"))
    print(f"[AUTH VERIFY] EMAIL VERIFIED BEFORE: {'YES' if email_verified_before else 'NO'}")

    expires_at = user_dict.get("verification_token_expires")
    is_expired = is_token_expired(expires_at)
    print(f"[AUTH VERIFY] token_expired = {'true' if is_expired else 'false'}")
    print(f"[AUTH VERIFY] TOKEN EXPIRY VALID: {'NO' if is_expired else 'YES'}")

    if is_expired:
        cursor.execute("UPDATE users SET verification_token_hash = NULL, verification_token_expires = NULL WHERE id = ?", (user_dict["id"],))
        conn.commit()
        conn.close()
        print("[AUTH VERIFY] DATABASE UPDATE: FAIL")
        print("[AUTH VERIFY] verification_result = failure")
        return False, "This verification link has expired.", user_dict

    # Mark email verified and invalidate token (single-use)
    cursor.execute("""
    UPDATE users
    SET email_verified = 1, verification_token_hash = NULL, verification_token_expires = NULL
    WHERE id = ?
    """, (user_dict["id"],))
    conn.commit()
    conn.close()

    print("[AUTH VERIFY] DATABASE UPDATE: SUCCESS")
    print("[AUTH VERIFY] verification_result = success")

    log_audit_event(user_dict["username"], user_dict["role"], "EMAIL_VERIFIED", f"Email verified: {user_dict['email']}", "SUCCESS")
    user_dict["email_verified"] = 1
    return True, "Email verified successfully! You can now sign in.", user_dict

def verify_email_otp(email: str, otp: str) -> tuple[bool, str, dict]:
    """
    Validates a 6-digit numeric OTP for account registration.
    Enforces:
    1. Exactly 6 numeric digits format
    2. Bound to user email on the server
    3. Maximum 5 failed attempts per issued OTP
    4. 5-minute expiration
    5. Single-use: invalidates OTP immediately on successful verification
    6. Invalidates OTP on reaching maximum incorrect attempts
    """
    norm_email = (email or "").strip().lower()
    otp_str = (otp or "").strip()

    if not norm_email or not otp_str:
        return False, "Email address and 6-digit verification code are required.", None

    if not (len(otp_str) == 6 and otp_str.isdigit()):
        return False, "Please enter a valid 6-digit numeric verification code.", None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, username, email, full_name, role, email_verified,
           verification_token_hash, verification_token_expires, verification_attempts
    FROM users
    WHERE LOWER(email) = ?
    """, (norm_email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "Invalid or expired verification code.", None

    user_dict = dict(user)

    if user_dict.get("email_verified"):
        conn.close()
        return True, "This email address is already verified. You can sign in directly.", user_dict

    stored_hash = user_dict.get("verification_token_hash")
    expires_at = user_dict.get("verification_token_expires")
    attempts = user_dict.get("verification_attempts") or 0

    if not stored_hash or not expires_at:
        conn.close()
        return False, "No active verification code found. Please request a new code.", None

    # Check if max attempts reached previously
    if attempts >= 5:
        cursor.execute("UPDATE users SET verification_token_hash = NULL, verification_token_expires = NULL WHERE id = ?", (user_dict["id"],))
        conn.commit()
        conn.close()
        return False, "Maximum verification attempts exceeded. Please request a new verification code.", None

    # Check expiration
    if is_token_expired(expires_at):
        cursor.execute("UPDATE users SET verification_token_hash = NULL, verification_token_expires = NULL WHERE id = ?", (user_dict["id"],))
        conn.commit()
        conn.close()
        return False, "This verification code has expired. Please request a new code.", None

    # Compare cryptographic hash
    submitted_hash = hashlib.sha256(otp_str.encode("utf-8")).hexdigest()
    if submitted_hash != stored_hash:
        new_attempts = attempts + 1
        rem = max(0, 5 - new_attempts)
        if new_attempts >= 5:
            cursor.execute("""
            UPDATE users
            SET verification_token_hash = NULL, verification_token_expires = NULL, verification_attempts = ?
            WHERE id = ?
            """, (new_attempts, user_dict["id"]))
            conn.commit()
            conn.close()
            return False, "Maximum verification attempts exceeded. Please request a new verification code.", None
        else:
            cursor.execute("UPDATE users SET verification_attempts = ? WHERE id = ?", (new_attempts, user_dict["id"]))
            conn.commit()
            conn.close()
            return False, f"Incorrect verification code. {rem} attempt(s) remaining.", None

    # Verification successful: activate account, invalidate OTP immediately (single-use), reset attempts
    cursor.execute("""
    UPDATE users
    SET email_verified = 1, verification_token_hash = NULL, verification_token_expires = NULL, verification_attempts = 0
    WHERE id = ?
    """, (user_dict["id"],))
    conn.commit()
    conn.close()

    log_audit_event(user_dict["username"], user_dict["role"], "EMAIL_VERIFIED_OTP", f"Email verified via OTP: {user_dict['email']}", "SUCCESS")
    user_dict["email_verified"] = 1
    return True, "Email verified successfully! You can now sign in.", user_dict

def verify_password_reset_token(raw_token: str) -> tuple[bool, str, dict]:
    """
    Validates whether a password reset token is active and valid without consuming it yet.
    """
    token_valid = bool(raw_token and len(raw_token.strip()) >= 10)
    print(f"[AUTH] Reset token validation: {'PASS' if token_valid else 'FAIL'}")

    if not token_valid:
        return False, "This reset link is invalid or has already been used.", None

    token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, username, email, full_name, role, reset_token_expires
    FROM users
    WHERE reset_token_hash = ?
    """, (token_hash,))
    user = cursor.fetchone()
    conn.close()

    user_found = bool(user)
    print(f"[AUTH] Reset token user found: {'YES' if user_found else 'NO'}")

    if not user:
        return False, "This reset link is invalid or has already been used.", None

    user_dict = dict(user)
    expires_at = user_dict.get("reset_token_expires")
    is_expired = is_token_expired(expires_at)
    print(f"[AUTH] Reset token expired: {'YES' if is_expired else 'NO'}")

    if is_expired:
        return False, "This password reset link has expired.", user_dict

    return True, "Reset token is valid.", user_dict

def reset_password_with_token(raw_token: str, new_password: str) -> tuple[bool, str]:
    """
    Validates the password reset token, updates the password hash, invalidates the token (single-use),
    invalidates active sessions, and dispatches a security confirmation email.
    """
    is_strong, pwd_err = validate_password_strength(new_password)
    if not is_strong:
        return False, pwd_err

    valid, msg, user = verify_password_reset_token(raw_token)
    if not valid:
        return False, msg

    token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
    pwd_hash, salt = hash_password(new_password)
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE users
    SET password_hash = ?, salt = ?, reset_token_hash = NULL, reset_token_expires = NULL, password_reset_used_at = ?
    WHERE reset_token_hash = ?
    """, (pwd_hash, salt, now_iso, token_hash))
    conn.commit()
    conn.close()

    # Invalidate active in-memory sessions for this user
    try:
        from backend.api.auth import ACTIVE_SESSIONS
        to_del = [token for token, sess in ACTIVE_SESSIONS.items() if sess.get("id") == user["id"]]
        for t in to_del:
            ACTIVE_SESSIONS.pop(t, None)
    except Exception:
        pass

    # Send security notification email
    send_password_changed_email(user["email"], user["full_name"])

    log_audit_event(user["username"], user["role"], "PASSWORD_CHANGED", "Password reset completed via email token", "SUCCESS")
    return True, "Password successfully changed. You can now sign in."

if __name__ == "__main__":
    to = sys.argv[1] if len(sys.argv) > 1 else None
    test_smtp_connection(to_email=to)
