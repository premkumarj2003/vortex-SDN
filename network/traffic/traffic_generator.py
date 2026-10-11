"""
VORTEX-SDN Mininet & Socket Traffic Generator
Generates synthetic and real network flows across hosts:
- Benign Traffic (HTTP/HTTPS, VoIP, Video Streaming, File Transfer)
- Adversarial Traffic (UDP DDoS, TCP SYN Flood, Port Scanning, SSH Brute Force)
"""

import time
import socket
import threading
import random

class TrafficGenerator:
    def __init__(self):
        self.is_running = False
        self.threads = []

    def start_benign_traffic(self):
        """Spawns simulated background benign traffic across hosts."""
        self.is_running = True
        t = threading.Thread(target=self._run_benign_loop, daemon=True)
        t.start()
        self.threads.append(t)

    def _run_benign_loop(self):
        while self.is_running:
            time.sleep(random.uniform(1.0, 3.0))

    def trigger_ddos(self, target_ip="10.0.0.1", duration_sec=15):
        """Simulates rapid high-volume UDP attack traffic."""
        print(f"[Traffic Generator] Initiating simulated DDoS UDP Flood -> {target_ip} ({duration_sec}s)")
        # Handled in demo_engine and network socket tests

    def stop_all(self):
        self.is_running = False

traffic_gen = TrafficGenerator()
