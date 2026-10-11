#!/usr/bin/env bash
# VORTEX-SDN Ryu OpenFlow 1.3 Controller Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

PID_DIR="$SCRIPT_DIR/.vortex_pids"
mkdir -p "$PID_DIR"
echo $$ > "$PID_DIR/ryu_term.pid"

echo "==============================================================================="
echo "                 VORTEX-SDN RYU OPENFLOW 1.3 CONTROLLER                        "
echo "                       Listening on 0.0.0.0:6653                               "
echo "==============================================================================="

export PYTHONPATH="$SCRIPT_DIR"
echo "[*] Project Root: $SCRIPT_DIR"

/home/prem/VORTEX-SDN/.venv-ryu/bin/ryu-manager controller.vortex_controller --ofp-tcp-listen-port 6653 &
RYU_PID=$!
echo $RYU_PID > "$PID_DIR/ryu_exact.pid"
echo "[*] Ryu Controller exact PID $RYU_PID recorded to $PID_DIR/ryu_exact.pid"

wait $RYU_PID
EXIT_CODE=$?
echo "[!] Ryu Controller exited with code $EXIT_CODE"
exec bash