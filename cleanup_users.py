"""
VORTEX-SDN Root Launcher for One-Time User Database Cleanup
Delegates directly to backend.scripts.cleanup_users.
"""

from backend.scripts.cleanup_users import main

if __name__ == "__main__":
    main()
