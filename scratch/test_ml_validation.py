import os
import sys
import time
import warnings
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
import pandas as pd
from ai.inference import AIInferenceEngine
from security.feature_engineering import extract_security_features
from security.detector import SecurityDetector

print("=== 1. MODEL RELOAD TEST ===")
t0 = time.time()
engine = AIInferenceEngine()
engine.load_models()
load_time = time.time() - t0
print(f"Model loaded successfully in {load_time * 1000:.2f} ms.")
print(f"Status: sec_loaded={engine.sec_loaded}, classes={engine.sec_classes}")
assert engine.sec_loaded is True

print("\n=== 2. FEATURE COMPATIBILITY & INFERENCE TEST ===")
test_flow = {
    "flow_id": "flw_bench_01",
    "dpid": "0000000000000001",
    "source_ip": "192.168.10.50",
    "destination_ip": "172.16.0.1",
    "source_port": 49152,
    "destination_port": 80,
    "protocol": "TCP",
    "packets": 12000,
    "bytes": 9600000,
    "duration": 0.5,
    "packet_rate": 24000.0,
    "byte_rate": 19200000.0,
    "connection_frequency": 85.0,
    "destination_frequency": 150.0,
    "source_frequency": 140.0,
    "unique_destinations": 1
}

feats = extract_security_features(test_flow)
print("Extracted 13 runtime features:")
for k, v in feats.items():
    print(f"  {k}: {v}")

with warnings.catch_warnings(record=True) as captured_warnings:
    warnings.simplefilter("always")
    t_start = time.perf_counter()
    pred = engine.predict_security(feats)
    t_single = (time.perf_counter() - t_start) * 1000.0
    print(f"\nSingle-flow inference latency: {t_single:.3f} ms")
    print("Prediction result:", pred)
    print("Captured warnings:", [str(w.message) for w in captured_warnings])
    assert len(captured_warnings) == 0, f"Unexpected warnings: {captured_warnings}"
    assert pred["label"] in ("BENIGN", "ATTACK")
    assert pred["model_status"] == "ONLINE"

print("\n=== 3. BATCH INFERENCE BENCHMARK (100 flows) ===")
t_batch_start = time.perf_counter()
for _ in range(100):
    engine.predict_security(feats)
t_batch = (time.perf_counter() - t_batch_start) * 1000.0 / 100.0
print(f"Average per-flow batch latency: {t_batch:.3f} ms ({1000.0 / t_batch:.0f} flows/sec)")

print("\n=== 4. BENIGN FLOW INFERENCE TEST ===")
benign_flow = {
    "flow_id": "flw_benign_01",
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.1",
    "source_port": 52140,
    "destination_port": 443,
    "protocol": "TCP",
    "packets": 45,
    "bytes": 35000,
    "duration": 5.0,
    "packet_rate": 9.0,
    "byte_rate": 7000.0,
    "connection_frequency": 1.2,
    "destination_frequency": 3.0,
    "source_frequency": 3.0,
    "unique_destinations": 1
}
benign_feats = extract_security_features(benign_flow)
benign_pred = engine.predict_security(benign_feats)
print("Benign flow prediction:", benign_pred)
assert benign_pred["label"] == "BENIGN"
assert benign_pred["severity"] == "LOW"

print("\n=== 5. EXISTING VORTEX DETECTOR PIPELINE TEST ===")
detector = SecurityDetector()
res_flow = detector.evaluate_flow(dict(test_flow))
print("Detector evaluated flow:")
print(f"  threat_label: {res_flow.get('threat_label')}")
print(f"  attack_type: {res_flow.get('attack_type')}")
print(f"  ai_confidence: {res_flow.get('ai_confidence')}")
print(f"  severity: {res_flow.get('severity')}")
print(f"  recommended_action: {res_flow.get('recommended_action')}")
assert "threat_label" in res_flow
assert res_flow["threat_label"] in ("BENIGN", "ATTACK")

print("\n=== ALL COMPATIBILITY & INFERENCE TESTS PASSED ===")
