#!/usr/bin/env python3
"""
===============================================================================
VORTEX-SDN Launcher & Orchestrator CLI
AI-Driven SDN Controller for Intelligent Network Security and QoS Management
===============================================================================
"""

import sys
import os
import argparse
import webbrowser
import time

BANNER = r"""
===============================================================================
                     __      ______  _____ _______ ________   __
                     \ \    / / __ \|  __ \__   __|  ____\ \ / /
                      \ \  / / |  | | |__) | | |  | |__   \ V / 
                       \ \/ /| |  | |  _  /  | |  |  __|   > <  
                        \  / | |__| | | \ \  | |  | |____ / . \ 
                         \/   \____/|_|  \_\ |_|  |______/_/ \_\
                                       -SDN-
      AI-Driven Software-Defined Network Controller & Intelligence Platform
===============================================================================
"""

def train_models():
    print("[1/3] Generating synthetic datasets for Security and QoS...")
    from ai.generate_datasets import generate_all
    generate_all()

    print("[2/3] Training Security Threat Detection Model (RandomForest + IsolationForest)...")
    from ai.train_security_model import train_security_model
    train_security_model()

    print("[3/3] Training QoS Traffic Classification Model (Multi-Class RF)...")
    from ai.train_qos_model import train_qos_model
    train_qos_model()

    print("\n[+] All AI models and evaluation metrics successfully trained and persisted!")

def run_tests():
    print("Running VORTEX-SDN Automated Test Suite...\n")
    import pytest
    pytest.main(["-v", "tests/test_vortex.py"])

def start_server(port=5000, open_browser=True):
    from backend.api.server import create_app
    app = create_app()

    url = f"http://127.0.0.1:{port}"
    print(BANNER)
    print(f"[*] VORTEX-SDN Server running at: {url}")
    print(f"[+] Real-time Telemetry: Active (5s polling)")
    print(f"[+] Security AI & QoS Classifiers: Online")
    print(f"[+] VORTEX AI Assistant: Ready")
    print("\nAccess the Web Interface:")
    print(f"  - Login:    {url}/login")
    print(f"  - Register: {url}/register")
    print("\nPress Ctrl+C to terminate.")
    print("=" * 79)

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

def show_ryu_instructions():
    print(BANNER)
    print("Ryu Controller Instructions (Linux / WSL / Ubuntu):")
    print("-------------------------------------------------------------------------------")
    print("1. Install Ryu in Python 3.9/3.10 environment:")
    print("   pip install ryu eventlet\n")
    print("2. Run the VORTEX Ryu Controller:")
    print("   ryu-manager controller/vortex_controller.py --ofp-tcp-listen-port 6653\n")
    print("3. In a separate terminal, launch Mininet:")
    print("   sudo python network/topologies/vortex_topology.py\n")
    print("4. Launch the VORTEX Dashboard:")
    print("   python run_vortex.py --server\n")

def main():
    parser = argparse.ArgumentParser(description="VORTEX-SDN Launcher")
    parser.add_argument("--train", action="store_true", help="Generate synthetic datasets and train ML models")
    parser.add_argument("--test", action="store_true", help="Run automated test suite")
    parser.add_argument("--server", action="store_true", help="Start Flask server and Web UI")
    parser.add_argument("--controller", action="store_true", help="Display Ryu controller startup commands")
    parser.add_argument("--port", type=int, default=5000, help="Port to run server on (default: 5000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    parser.add_argument("--test-smtp", nargs="?", const="", help="Run safe backend SMTP connection and delivery test (optional: recipient email)")
    parser.add_argument("--handover-admin", action="store_true", help="Execute controlled one-time administrator role handover to configured ADMIN_EMAIL")

    args = parser.parse_args()

    if args.train:
        train_models()
    elif args.test:
        run_tests()
    elif args.handover_admin:
        os.environ["ADMIN_TRANSFER_CONFIRM"] = "true"
        from backend.models.database import perform_admin_handover
        success, msg = perform_admin_handover(old_admin_email="vertexsdn@gmail.com")
        print("=" * 79)
        print("VORTEX-SDN Controlled Administrator Handover")
        print("=" * 79)
        print(f"[+] Status: {msg}")
        print("[+] Current Single Administrator: " + os.environ.get("ADMIN_EMAIL", "").strip().lower())
        print("=" * 79)
    elif args.test_smtp is not None:
        from backend.services.email_service import test_smtp_connection
        target = args.test_smtp.strip() if args.test_smtp else None
        test_smtp_connection(to_email=target)
    elif args.controller:
        show_ryu_instructions()
    else:
        # Default action: start server
        start_server(port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
