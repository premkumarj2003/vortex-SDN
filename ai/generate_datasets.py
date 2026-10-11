"""
VORTEX-SDN Synthetic Dataset Generator
Generates realistic, mathematically grounded training data for:
1. Security Threat Detection (DDoS, Port Scan, Brute Force, Flood, Anomaly, Benign)
2. QoS Application Classification (Voice, Video, Web, File Transfer, Email, P2P, Best Effort, Critical)

LABEL: SYNTHETIC TRAINING DATA
"""

import os
import csv
import random
import numpy as np

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "datasets")
os.makedirs(DATASET_DIR, exist_ok=True)

SECURITY_DATASET_PATH = os.path.join(DATASET_DIR, "security_dataset.csv")
QOS_DATASET_PATH = os.path.join(DATASET_DIR, "qos_dataset.csv")

def generate_security_dataset(num_samples=6000):
    """
    Generates synthetic security training dataset with realistic feature distributions.
    Header comment explicitly tags dataset as SYNTHETIC TRAINING DATA.
    """
    print(f"Generating Security Dataset ({num_samples} samples)...")
    np.random.seed(42)
    random.seed(42)

    categories = [
        ("BENIGN", 0.45),
        ("DDOS", 0.15),
        ("PORT_SCAN", 0.12),
        ("BRUTE_FORCE", 0.10),
        ("FLOOD", 0.10),
        ("ANOMALY", 0.08)
    ]

    rows = []
    headers = [
        "packet_rate",
        "byte_rate",
        "packets",
        "bytes",
        "flow_duration",
        "source_port",
        "destination_port",
        "protocol_num", # 6=TCP, 17=UDP, 1=ICMP
        "unique_destinations",
        "connection_frequency",
        "packet_size",
        "destination_frequency",
        "source_frequency",
        "label", # BENIGN or ATTACK
        "attack_type"
    ]

    for cat_name, fraction in categories:
        count = int(num_samples * fraction)
        for _ in range(count):
            if cat_name == "BENIGN":
                # Standard web, media, api, internal traffic
                flow_duration = max(0.5, np.random.exponential(15.0))
                protocol_num = random.choice([6, 6, 6, 17, 17, 1])
                destination_port = random.choice([80, 443, 8080, 53, 22, 5060, 1935, 3306])
                source_port = random.randint(1024, 65535)
                packet_size = int(np.random.normal(750, 300))
                packet_size = max(64, min(1500, packet_size))
                packet_rate = float(np.random.gamma(2.5, 20.0))
                packets = max(5, int(packet_rate * flow_duration))
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = random.randint(1, 4)
                connection_frequency = float(np.random.exponential(1.5))
                destination_frequency = float(np.random.gamma(2.0, 5.0))
                source_frequency = float(np.random.gamma(2.0, 5.0))
                label = "BENIGN"
                attack_type = "BENIGN"

            elif cat_name == "DDOS":
                # Massive packet rate and byte rate, short/medium duration, single destination
                flow_duration = max(1.0, np.random.exponential(30.0))
                protocol_num = random.choice([17, 17, 6, 1])
                destination_port = random.choice([80, 443, 8080, 53])
                source_port = random.randint(1024, 65535)
                packet_size = int(np.random.normal(512, 120))
                packet_size = max(64, min(1400, packet_size))
                packet_rate = float(np.random.gamma(50.0, 500.0) + 15000.0)
                packets = int(packet_rate * flow_duration)
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = 1
                connection_frequency = float(np.random.gamma(10.0, 50.0))
                destination_frequency = float(np.random.gamma(20.0, 100.0))
                source_frequency = float(np.random.gamma(15.0, 80.0))
                label = "ATTACK"
                attack_type = "DDOS"

            elif cat_name == "PORT_SCAN":
                # Very rapid sequential connection attempts across many destination ports, small packets
                flow_duration = max(0.1, np.random.exponential(2.0))
                protocol_num = 6 # TCP SYN
                destination_port = random.randint(20, 10000)
                source_port = random.randint(30000, 65000)
                packet_size = random.choice([40, 52, 60, 64])
                packet_rate = float(np.random.gamma(15.0, 150.0) + 1500.0)
                packets = max(2, int(packet_rate * flow_duration))
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = random.randint(15, 80)
                connection_frequency = float(np.random.gamma(15.0, 30.0))
                destination_frequency = float(np.random.exponential(1.2))
                source_frequency = float(np.random.gamma(25.0, 40.0))
                label = "ATTACK"
                attack_type = "PORT_SCAN"

            elif cat_name == "BRUTE_FORCE":
                # Repeated connection attempts to specific auth ports (SSH 22, RDP 3389, FTP 21)
                flow_duration = max(0.5, np.random.exponential(5.0))
                protocol_num = 6
                destination_port = random.choice([22, 21, 3389, 23, 8080])
                source_port = random.randint(1024, 65535)
                packet_size = int(np.random.normal(120, 30))
                packet_size = max(60, min(300, packet_size))
                packet_rate = float(np.random.gamma(5.0, 60.0) + 200.0)
                packets = max(10, int(packet_rate * flow_duration))
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = random.randint(1, 3)
                connection_frequency = float(np.random.gamma(20.0, 15.0))
                destination_frequency = float(np.random.gamma(15.0, 20.0))
                source_frequency = float(np.random.gamma(18.0, 25.0))
                label = "ATTACK"
                attack_type = "BRUTE_FORCE"

            elif cat_name == "FLOOD":
                # SYN or UDP flood with high packet rate, moderate byte rate
                flow_duration = max(0.5, np.random.exponential(10.0))
                protocol_num = random.choice([6, 17, 1])
                destination_port = random.choice([80, 443, 53, 123])
                source_port = random.randint(1024, 65535)
                packet_size = random.choice([64, 128, 256])
                packet_rate = float(np.random.gamma(30.0, 300.0) + 8000.0)
                packets = int(packet_rate * flow_duration)
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = random.randint(1, 2)
                connection_frequency = float(np.random.gamma(12.0, 40.0))
                destination_frequency = float(np.random.gamma(15.0, 60.0))
                source_frequency = float(np.random.gamma(20.0, 50.0))
                label = "ATTACK"
                attack_type = "FLOOD"

            elif cat_name == "ANOMALY":
                # Unorthodox port usage, unusual packet rate / payload asymmetry
                flow_duration = max(0.2, np.random.exponential(8.0))
                protocol_num = random.choice([6, 17])
                destination_port = random.randint(10000, 60000)
                source_port = random.randint(1024, 65535)
                packet_size = int(np.random.choice([1480, 40, 1200]))
                packet_rate = float(np.random.gamma(8.0, 100.0) + 1200.0)
                packets = int(packet_rate * flow_duration)
                byte_rate = packet_rate * packet_size
                bytes_total = int(packets * packet_size)
                unique_destinations = random.randint(3, 12)
                connection_frequency = float(np.random.exponential(8.0))
                destination_frequency = float(np.random.exponential(6.0))
                source_frequency = float(np.random.exponential(10.0))
                label = "ATTACK"
                attack_type = "ANOMALY"

            rows.append([
                round(packet_rate, 2),
                round(byte_rate, 2),
                packets,
                bytes_total,
                round(flow_duration, 2),
                source_port,
                destination_port,
                protocol_num,
                unique_destinations,
                round(connection_frequency, 2),
                packet_size,
                round(destination_frequency, 2),
                round(source_frequency, 2),
                label,
                attack_type
            ])

    random.shuffle(rows)

    with open(SECURITY_DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        f.write("# SYNTHETIC TRAINING DATA - VORTEX-SDN SECURITY INTELLIGENCE ENGINE\n")
        f.write("# Generated for training and evaluation. Clearly identified as synthetic.\n")
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"Saved {len(rows)} security records to: {SECURITY_DATASET_PATH}")
    return SECURITY_DATASET_PATH

def generate_qos_dataset(num_samples=6000):
    """
    Generates synthetic QoS classification training dataset with realistic networking parameters.
    Header comment explicitly tags dataset as SYNTHETIC TRAINING DATA.
    """
    print(f"Generating QoS Dataset ({num_samples} samples)...")
    np.random.seed(84)
    random.seed(84)

    classes = [
        ("VOICE", 0.15),
        ("VIDEO", 0.20),
        ("WEB", 0.25),
        ("FILE_TRANSFER", 0.15),
        ("EMAIL", 0.08),
        ("P2P", 0.07),
        ("CRITICAL", 0.05),
        ("BEST_EFFORT", 0.05)
    ]

    rows = []
    headers = [
        "packet_rate",
        "byte_rate",
        "packet_size",
        "protocol_num", # 6=TCP, 17=UDP
        "destination_port",
        "flow_duration",
        "latency_ms",
        "jitter_ms",
        "packet_loss_pct",
        "throughput_mbps",
        "traffic_class"
    ]

    for class_name, fraction in classes:
        count = int(num_samples * fraction)
        for _ in range(count):
            if class_name == "VOICE":
                # VoIP: Small packets, constant rate, low latency requirement, UDP
                packet_size = int(np.random.normal(160, 25))
                packet_size = max(80, min(300, packet_size))
                packet_rate = float(np.random.normal(50.0, 8.0)) # ~50 packets/sec (G.711 / Opus)
                packet_rate = max(20.0, packet_rate)
                byte_rate = packet_rate * packet_size
                protocol_num = 17 # UDP
                destination_port = random.choice([5060, 5061, 10000, 16384, 18000])
                flow_duration = max(5.0, np.random.exponential(90.0))
                latency_ms = max(5.0, np.random.normal(18.0, 4.0))
                jitter_ms = max(0.5, np.random.normal(2.5, 0.8))
                packet_loss_pct = max(0.0, np.random.normal(0.2, 0.1))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "VIDEO":
                # Video Streaming: Large packets, bursty, moderate latency, TCP or UDP
                packet_size = int(np.random.normal(1350, 100))
                packet_size = max(800, min(1500, packet_size))
                packet_rate = float(np.random.gamma(12.0, 25.0) + 100.0) # ~400 pps (HD/4K)
                byte_rate = packet_rate * packet_size
                protocol_num = random.choice([6, 17, 6])
                destination_port = random.choice([1935, 8080, 443, 554, 8554])
                flow_duration = max(10.0, np.random.exponential(180.0))
                latency_ms = max(12.0, np.random.normal(32.0, 8.0))
                jitter_ms = max(1.0, np.random.normal(6.0, 2.0))
                packet_loss_pct = max(0.0, np.random.normal(0.4, 0.2))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "WEB":
                # Web browsing: Bursty TCP, medium size packets, medium latency tolerance
                packet_size = int(np.random.normal(850, 250))
                packet_size = max(100, min(1460, packet_size))
                packet_rate = float(np.random.exponential(45.0) + 10.0)
                byte_rate = packet_rate * packet_size
                protocol_num = 6 # TCP
                destination_port = random.choice([80, 443, 8080, 8443])
                flow_duration = max(0.5, np.random.exponential(12.0))
                latency_ms = max(15.0, np.random.normal(45.0, 12.0))
                jitter_ms = max(2.0, np.random.normal(10.0, 3.5))
                packet_loss_pct = max(0.0, np.random.normal(0.8, 0.3))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "FILE_TRANSFER":
                # Bulk FTP/SFTP/SMB: Maximum packet size, sustained TCP throughput, latency tolerant
                packet_size = int(np.random.normal(1460, 20))
                packet_size = max(1200, min(1500, packet_size))
                packet_rate = float(np.random.gamma(18.0, 35.0) + 250.0)
                byte_rate = packet_rate * packet_size
                protocol_num = 6 # TCP
                destination_port = random.choice([20, 21, 22, 445, 873])
                flow_duration = max(20.0, np.random.exponential(300.0))
                latency_ms = max(20.0, np.random.normal(65.0, 18.0))
                jitter_ms = max(3.0, np.random.normal(14.0, 5.0))
                packet_loss_pct = max(0.0, np.random.normal(1.2, 0.4))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "EMAIL":
                # SMTP/IMAP: Small to medium packets, sporadic bursts, high latency tolerance
                packet_size = int(np.random.normal(600, 200))
                packet_size = max(100, min(1300, packet_size))
                packet_rate = float(np.random.exponential(15.0) + 4.0)
                byte_rate = packet_rate * packet_size
                protocol_num = 6
                destination_port = random.choice([25, 587, 993, 110, 465])
                flow_duration = max(1.0, np.random.exponential(8.0))
                latency_ms = max(25.0, np.random.normal(80.0, 20.0))
                jitter_ms = max(4.0, np.random.normal(18.0, 6.0))
                packet_loss_pct = max(0.0, np.random.normal(1.5, 0.5))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "P2P":
                # Torrent/P2P: Continuous multi-port connections, moderate packet size, low priority
                packet_size = int(np.random.normal(1100, 300))
                packet_size = max(200, min(1480, packet_size))
                packet_rate = float(np.random.gamma(10.0, 20.0) + 50.0)
                byte_rate = packet_rate * packet_size
                protocol_num = random.choice([6, 17])
                destination_port = random.randint(6881, 6889)
                flow_duration = max(30.0, np.random.exponential(400.0))
                latency_ms = max(35.0, np.random.normal(110.0, 30.0))
                jitter_ms = max(8.0, np.random.normal(28.0, 9.0))
                packet_loss_pct = max(0.1, np.random.normal(2.5, 0.8))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "CRITICAL":
                # Real-time control/finance: High priority, lowest latency, zero loss tolerance
                packet_size = int(np.random.normal(350, 80))
                packet_size = max(100, min(800, packet_size))
                packet_rate = float(np.random.normal(120.0, 20.0))
                byte_rate = packet_rate * packet_size
                protocol_num = 6
                destination_port = random.choice([443, 8443, 5000, 9000])
                flow_duration = max(10.0, np.random.exponential(120.0))
                latency_ms = max(2.0, np.random.normal(8.0, 2.0))
                jitter_ms = max(0.2, np.random.normal(1.0, 0.3))
                packet_loss_pct = max(0.0, np.random.normal(0.02, 0.01))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            elif class_name == "BEST_EFFORT":
                # Background sync, telemetry, general traffic
                packet_size = int(np.random.normal(500, 150))
                packet_size = max(80, min(1200, packet_size))
                packet_rate = float(np.random.exponential(25.0) + 5.0)
                byte_rate = packet_rate * packet_size
                protocol_num = random.choice([6, 17])
                destination_port = random.choice([80, 8080, 3000, 5000])
                flow_duration = max(2.0, np.random.exponential(20.0))
                latency_ms = max(20.0, np.random.normal(70.0, 15.0))
                jitter_ms = max(3.0, np.random.normal(15.0, 4.0))
                packet_loss_pct = max(0.0, np.random.normal(1.0, 0.3))
                throughput_mbps = (byte_rate * 8) / 1_000_000

            rows.append([
                round(packet_rate, 2),
                round(byte_rate, 2),
                packet_size,
                protocol_num,
                destination_port,
                round(flow_duration, 2),
                round(latency_ms, 2),
                round(jitter_ms, 2),
                round(packet_loss_pct, 3),
                round(throughput_mbps, 4),
                class_name
            ])

    random.shuffle(rows)

    with open(QOS_DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        f.write("# SYNTHETIC TRAINING DATA - VORTEX-SDN QOS INTELLIGENCE ENGINE\n")
        f.write("# Generated for training and evaluation. Clearly identified as synthetic.\n")
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"Saved {len(rows)} QoS records to: {QOS_DATASET_PATH}")
    return QOS_DATASET_PATH

def generate_all():
    sec_path = generate_security_dataset(6000)
    qos_path = generate_qos_dataset(6000)
    return sec_path, qos_path

if __name__ == "__main__":
    generate_all()
    print("All synthetic datasets generated successfully!")
