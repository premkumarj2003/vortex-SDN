"""
Responsive & Functional Validation Script for VORTEX-SDN
Tests HTML page serving, CSS asset availability, viewport declarations, and API routes.
"""
import requests
import re
import os

BASE_URL = "http://127.0.0.1:5000"

def test_html_pages():
    pages = [
        "/",
        "/login",
        "/register",
        "/verify-email",
        "/forgot-password",
        "/reset-password"
    ]
    print("[*] Testing HTML pages...")
    for page in pages:
        res = requests.get(f"{BASE_URL}{page}", timeout=5)
        assert res.status_code == 200, f"Page {page} failed with status {res.status_code}"
        # Check viewport meta tag
        has_viewport = re.search(r'<meta[^>]*name=["\']viewport["\'][^>]*content=["\'][^"\']*width=device-width[^"\']*["\']', res.text, re.IGNORECASE)
        assert has_viewport, f"Page {page} is missing viewport meta tag!"
        print(f"  [+] {page:20} -> HTTP 200, Viewport declaration verified")

def test_css_assets():
    css_files = [
        "/css/variables.css",
        "/css/base.css",
        "/css/layout.css",
        "/css/sidebar.css",
        "/css/topbar.css",
        "/css/cards.css",
        "/css/dashboard.css",
        "/css/tables.css",
        "/css/charts.css",
        "/css/topology.css",
        "/css/modals.css",
        "/css/chatbot.css",
        "/css/digital_twin.css",
        "/css/predictive.css",
        "/css/root_cause.css",
        "/css/settings.css",
        "/css/responsive.css",
        "/css/login.css"
    ]
    print("\n[*] Testing CSS assets...")
    for css in css_files:
        res = requests.get(f"{BASE_URL}{css}", timeout=5)
        assert res.status_code == 200, f"CSS {css} failed with status {res.status_code}"
        # Check balanced brackets
        open_braces = res.text.count('{')
        close_braces = res.text.count('}')
        assert open_braces == close_braces, f"CSS {css} has unbalanced braces: {open_braces} != {close_braces}"
        print(f"  [+] {css:25} -> HTTP 200, Valid syntax ({open_braces} blocks)")

def test_api_health_and_roles():
    print("\n[*] Testing Backend APIs & Role Protection...")
    # Health endpoint
    h = requests.get(f"{BASE_URL}/api/health", timeout=5)
    assert h.status_code == 200
    print(f"  [+] /api/health          -> HTTP 200 (Status: {h.json().get('status')})")

    # Telemetry endpoint
    t = requests.get(f"{BASE_URL}/api/telemetry/live", timeout=5)
    assert t.status_code == 200
    print(f"  [+] /api/telemetry/live  -> HTTP 200 (Live telemetry OK)")

    # Topology endpoint
    topo = requests.get(f"{BASE_URL}/api/topology", timeout=5)
    assert topo.status_code == 200
    print(f"  [+] /api/topology        -> HTTP 200 (Nodes: {len(topo.json().get('nodes', []))})")

    # Admin route protection for unauthenticated / unauthorized requests
    admin = requests.get(f"{BASE_URL}/api/admin/users", timeout=5)
    # Must be 401 Unauthorized or 403 Forbidden without valid session
    assert admin.status_code in [401, 403], f"Admin route security violated: got {admin.status_code}"
    print(f"  [+] /api/admin/users     -> HTTP {admin.status_code} (Properly protected)")

if __name__ == "__main__":
    test_html_pages()
    test_css_assets()
    test_api_health_and_roles()
    print("\n[SUCCESS] All responsive HTML, CSS, and API tests passed flawlessly!")
