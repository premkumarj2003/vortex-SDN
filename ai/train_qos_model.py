"""
VORTEX-SDN QoS AI Model Training Pipeline
Trains a multi-class RandomForest classifier to categorize network traffic into:
VOICE, VIDEO, WEB, FILE_TRANSFER, EMAIL, P2P, BEST_EFFORT, CRITICAL.
Computes and records genuine validation metrics.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "data", "datasets", "qos_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "ai", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "qos_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "qos_metrics.json")

os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLS = [
    "packet_rate",
    "byte_rate",
    "packet_size",
    "protocol_num",
    "destination_port",
    "flow_duration",
    "latency_ms",
    "jitter_ms",
    "packet_loss_pct",
    "throughput_mbps"
]

def train_qos_model():
    print("=" * 60)
    print("VORTEX-SDN: Training QoS Traffic Classification Model")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}. Generating synthetic QoS dataset first...")
        from ai.generate_datasets import generate_qos_dataset
        generate_qos_dataset()

    # Load dataset, skipping comments
    df = pd.read_csv(DATASET_PATH, comment="#")
    print(f"Loaded {len(df)} samples from {DATASET_PATH}")
    print(f"Feature count: {len(FEATURE_COLS)}")
    print(f"Class breakdown:\n{df['traffic_class'].value_counts()}")

    X = df[FEATURE_COLS]
    y = df["traffic_class"]

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=84, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest Classifier
    print("Training RandomForestClassifier for QoS...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=3,
        random_state=84,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    # Predictions & Metrics
    y_pred = clf.predict(X_test_scaled)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    classes = list(clf.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

    importances = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(
            zip(FEATURE_COLS, clf.feature_importances_),
            key=lambda x: x[1],
            reverse=True
        )
    }

    print("-" * 60)
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1 Score:  {f1 * 100:.2f}%")
    print("-" * 60)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=classes))

    # Save Model Artifact
    model_payload = {
        "classifier": clf,
        "scaler": scaler,
        "features": FEATURE_COLS,
        "classes": classes,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "RandomForestClassifier",
        "version": "1.0.0"
    }

    joblib.dump(model_payload, MODEL_PATH)
    print(f"Saved QoS model artifact to: {MODEL_PATH}")

    # Save Metrics JSON
    metrics_payload = {
        "model_name": "VORTEX QoS Traffic Classifier",
        "model_type": "Multi-Class Random Forest Classifier",
        "version": "1.0.0",
        "status": "HEALTHY",
        "dataset_source": "SYNTHETIC TRAINING DATA (6,000 observations)",
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "classes": classes,
        "confusion_matrix": cm,
        "feature_importance": importances,
        "last_trained": datetime.now(timezone.utc).isoformat(),
        "inference_count": 0
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"Saved metrics to: {METRICS_PATH}")

    return metrics_payload

if __name__ == "__main__":
    train_qos_model()
