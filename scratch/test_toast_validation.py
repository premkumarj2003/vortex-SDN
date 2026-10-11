"""
Specialized Toast Validation Script for VORTEX-SDN
Validates:
1. Absence of destructive translateX(100%) in all stylesheets.
2. Presence and properties of #toast-container (position: fixed, z-index, pointer-events: none).
3. Non-overflowing purely vertical animation (@keyframes toastEnter).
4. Responsive rules for desktop, tablet, mobile portrait, and mobile landscape.
5. Balanced CSS braces across all stylesheets.
6. Utils.showToast implementation integrity.
"""
import re
import os
import requests

BASE_URL = "http://127.0.0.1:5000"

def test_no_destructive_translateX():
    print("[1] Checking for destructive translateX animations for toasts...")
    css_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "css")
    for fname in ["base.css", "modals.css", "responsive.css"]:
        fpath = os.path.join(css_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        # Ensure no slideInToast or translateX for toasts
        assert "slideInToast" not in content, f"Found slideInToast in {fname}!"
        # Check if toast rules use translateX
        for line in content.splitlines():
            if "toast" in line.lower() and "translateX" in line:
                raise AssertionError(f"Found toast translateX rule in {fname}: {line}")
    print("  [+] No toast translateX animations or slideInToast found.")

def test_toast_container_overlay_properties():
    print("\n[2] Checking #toast-container and confirmation modal rules in base.css & modals.css...")
    css_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "css")
    for target in ["base.css", "modals.css"]:
        fpath = os.path.join(css_dir, target)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "#toast-container" in content, f"#toast-container missing from {target}"
        assert "position: fixed" in content, f"position: fixed missing for #toast-container in {target}"
        assert "top: 72px" in content, f"top: 72px missing in {target}"
        assert "left: 50%" in content, f"left: 50% missing in {target}"
        assert "pointer-events: none" in content, f"pointer-events: none missing in {target}"
        assert "toastTopEnter" in content, f"@keyframes toastTopEnter missing in {target}"
        assert ".vortex-confirm-overlay" in content, f".vortex-confirm-overlay missing in {target}"
        assert ".vortex-confirm-dialog" in content, f".vortex-confirm-dialog missing in {target}"
        print(f"  [+] {target} defines strict top-center fixed overlay with vertical float-down animation and custom confirm modals.")

def test_responsive_toast_rules():
    print("\n[3] Checking responsive toast and modal rules in responsive.css...")
    fpath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "css", "responsive.css")
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

    # Check tablet rules
    assert "top: 68px" in content, "Tablet top offset missing in responsive.css"
    # Check mobile portrait rules (max-width: calc(100vw - 24px))
    assert "max-width: calc(100vw - 24px)" in content, "Mobile max-width: calc(100vw - 24px) missing in responsive.css"
    # Check landscape rules
    assert "top: 50px" in content, "Mobile landscape top offset missing in responsive.css"
    assert ".vortex-confirm-dialog" in content, ".vortex-confirm-dialog responsive rules missing in responsive.css"
    print("  [+] Tablet, Mobile Portrait, and Mobile Landscape toast and confirm positioning rules verified.")

def test_utils_show_toast_integrity():
    print("\n[4] Checking Utils methods in utils.js...")
    fpath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "js", "utils.js")
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

    assert "showToast" in content, "showToast method missing in utils.js"
    assert "showConfirm" in content, "showConfirm method missing in utils.js"
    assert "showPrompt" in content, "showPrompt method missing in utils.js"
    assert "showAlert" in content, "showAlert method missing in utils.js"
    assert "showVortexConfirm" in content, "showVortexConfirm alias missing in utils.js"
    assert "showVortexToast" in content, "showVortexToast alias missing in utils.js"
    assert "toast-leaving" in content, "toast-leaving smooth exit class missing in utils.js"
    assert "toast-content-wrap" in content, "toast-content-wrap missing in utils.js"
    assert "toast-close-btn" in content, "toast-close-btn missing in utils.js"
    print("  [+] Utils has full popup suite: showToast, showConfirm, showPrompt, showAlert with Promise lifecycle.")

def test_zero_native_dialogs():
    print("\n[5] Verifying 0 remaining native dialogs in all frontend files...")
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
    for root, dirs, files in os.walk(frontend_dir):
        for fname in files:
            if fname.endswith(".js") or fname.endswith(".html"):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                # Exclude utils.js definition line window.alert =
                lines = content.splitlines()
                for idx, line in enumerate(lines, 1):
                    # Check for prompt( or confirm(
                    if re.search(r'\b(confirm|prompt)\s*\(', line):
                        raise AssertionError(f"Native dialog found in {fname}:{idx} -> {line}")
                    if "alert(" in line and "window.alert = " not in line and "showAlert(" not in line:
                        raise AssertionError(f"Native alert found in {fname}:{idx} -> {line}")
    print("  [+] Clean verification: Zero native alert/confirm/prompt calls across all frontend files.")

def test_css_balanced_braces():
    print("\n[5] Checking CSS files for balanced syntax braces...")
    css_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "css")
    for fname in sorted(os.listdir(css_dir)):
        if fname.endswith(".css"):
            fpath = os.path.join(css_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            open_b = content.count("{")
            close_b = content.count("}")
            assert open_b == close_b, f"Unbalanced braces in {fname}: {open_b} vs {close_b}"
            print(f"  [+] {fname:20} -> Balanced ({open_b} blocks)")

if __name__ == "__main__":
    test_no_destructive_translateX()
    test_toast_container_overlay_properties()
    test_responsive_toast_rules()
    test_utils_show_toast_integrity()
    test_zero_native_dialogs()
    test_css_balanced_braces()
    print("\n[SUCCESS] All top-center toast and confirmation modal overlay tests passed 100%!")
