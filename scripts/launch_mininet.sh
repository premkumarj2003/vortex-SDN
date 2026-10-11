#!/usr/bin/env bash
# VORTEX-SDN Mininet Mesh Topology Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

PID_DIR="$SCRIPT_DIR/.vortex_pids"
mkdir -p "$PID_DIR"
echo $$ > "$PID_DIR/mininet_term.pid"

echo "==============================================================================="
echo "                    VORTEX-SDN MININET MESH TOPOLOGY                           "
echo "                 4 OVS Switches (s1-s4) + 4 Hosts (h1-h4)                      "
echo "==============================================================================="

export PYTHONPATH="$SCRIPT_DIR"
echo "[*] Project Root: $SCRIPT_DIR"

# Launch Mininet with exact root Python PID recorded safely in workspace PID directory
if [ "$EUID" -eq 0 ]; then
    SUDO_CMD=""
else
    SUDO_CMD="sudo"
fi

$SUDO_CMD python3 -c "
import os
pid_dir = '$PID_DIR'
os.makedirs(pid_dir, exist_ok=True)
with open(os.path.join(pid_dir, 'mininet_exact.pid'), 'w') as f:
    f.write(str(os.getpid()))
os.execvp('python3', ['python3', 'network/topologies/vortex_topology.py'])
"

EXIT_CODE=$?
echo "[!] Mininet session exited with code $EXIT_CODE"
exec bash