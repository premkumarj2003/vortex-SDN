"""
VORTEX-SDN Security Feature Engineering
Converts raw OpenFlow flow statistics into normalized feature vectors for AI inference.
"""

import time

def extract_security_features(flow: dict) -> dict:
    """
    Extracts and formats all 13 security feature dimensions required by the ML model.
    """
    protocol = str(flow.get("protocol", "TCP")).upper()
    proto_num = 6 if protocol == "TCP" else (17 if protocol == "UDP" else 1)

    packet_rate = float(flow.get("packet_rate", 0.0))
    byte_rate = float(flow.get("byte_rate", 0.0))
    packets = int(flow.get("packets", 1))
    bytes_total = int(flow.get("bytes", 64))
    duration = max(0.1, float(flow.get("duration", 1.0)))

    # Derived packet size
    packet_size = int(bytes_total / max(1, packets)) if packets > 0 else 512

    return {
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "packets": packets,
        "bytes": bytes_total,
        "flow_duration": duration,
        "source_port": int(flow.get("source_port", 0) or 0),
        "destination_port": int(flow.get("destination_port", 0) or 0),
        "protocol_num": proto_num,
        "unique_destinations": int(flow.get("unique_destinations", 1)),
        "connection_frequency": float(flow.get("connection_frequency", 1.0)),
        "packet_size": packet_size,
        "destination_frequency": float(flow.get("destination_frequency", 1.0)),
        "source_frequency": float(flow.get("source_frequency", 1.0))
    }
