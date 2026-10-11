"""
VORTEX-SDN Security AI Model Training Pipeline
Trains a high-performance RandomForestClassifier + IsolationForest ensemble for network attack detection
using the authentic CICIDS2017 benchmark dataset.
Computes and persists actual mathematical evaluation metrics (Accuracy, Precision, Recall, F1, FPR).
"""

import os
import sys
import json
import joblib
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CICIDS_PROCESSED_PATH = os.path.join(BASE_DIR, "data", "datasets", "cicids2017", "processed", "cicids2017_vortex.csv")
SYNTHETIC_DATASET_PATH = os.path.join(BASE_DIR, "data", "datasets", "security_dataset.csv")

MODEL_DIR = os.path.join(BASE_DIR, "ai", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "security_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "security_metrics.json")

os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLS = [
    "packet_rate",
    "byte_rate",
    "packets",
    "bytes",
    "flow_duration",
    "source_port",
    "destination_port",
    "protocol_num",
    "unique_destinations",
    "connection_frequency",
    "packet_size",
    "destination_frequency",
    "source_frequency"
]

def train_security_model(use_synthetic: bool = False, dataset_path: str = None) -> dict:
    print("=" * 60)
    print("VORTEX-SDN: Training Security Threat Detection Model")
    print("=" * 60)

    # 1. Dataset Selection & Strict Verification
    if use_synthetic:
        target_path = dataset_path or SYNTHETIC_DATASET_PATH
        dataset_source_name = "SYNTHETIC TRAINING DATA (6,000 observations)"
        print(f"[Mode] EXPLICIT OPT-IN: Training with synthetic dataset at: {target_path}")
        if not os.path.exists(target_path):
            print(f"Synthetic dataset not found at {target_path}. Generating synthetic dataset...")
            from ai.generate_datasets import generate_security_dataset
            generate_security_dataset()
    else:
        target_path = dataset_path or CICIDS_PROCESSED_PATH
        dataset_source_name = "CICIDS2017"
        print(f"[Mode] OFFICIAL BENCHMARK: Training with CICIDS2017 dataset at: {target_path}")
        
        if not os.path.exists(target_path):
            error_msg = (
                "CICIDS2017 dataset is required for real security model training. "
                "Download/prepare the dataset first. Run: python -m ai.prepare_cicids2017"
            )
            print(f"\n[ERROR] {error_msg}\n")
            raise FileNotFoundError(error_msg)

    # 2. Ingest Dataset
    print(f"Loading dataset from: {target_path}")
    df = pd.read_csv(target_path, comment="#")
    print(f"Loaded {len(df):,} observations.")
    print(f"Features: {len(FEATURE_COLS)} dimensions -> {FEATURE_COLS}")
    print(f"\nClass Distribution:\n{df['attack_type'].value_counts()}\n")

    # Verify all feature columns exist
    missing_cols = [c for c in FEATURE_COLS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset is missing required VORTEX feature columns: {missing_cols}")

    X = df[FEATURE_COLS]
    y_attack = df["attack_type"]
    y_binary = (df["label"] == "ATTACK").astype(int)

    # 3. Leakage-Aware Stratified Train / Test Split
    print("Performing 80/20 leakage-aware stratified train/test split...")
    X_train, X_test, y_train, y_test, yb_train, yb_test = train_test_split(
        X, y_attack, y_binary, test_size=0.20, random_state=42, stratify=y_attack
    )
    print(f"Training observations: {len(X_train):,}")
    print(f"Testing observations:  {len(X_test):,}")

    # 4. Fit StandardScaler
    print("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5. Train Multi-Class Random Forest with balanced class weighting
    print("Training RandomForestClassifier (n_estimators=120, max_depth=16, class_weight='balanced')...")
    rf_clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_clf.fit(X_train_scaled, y_train)

    # 6. Train Unsupervised Isolation Forest Anomaly Detector on Benign Traffic
    print("Training IsolationForest Anomaly Detector on Benign observations...")
    benign_train = X_train_scaled[yb_train == 0]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(benign_train)

    # 7. Evaluate on Held-out Test Set
    print("\n" + "=" * 60)
    print("EVALUATION ON HELD-OUT TEST SET")
    print("=" * 60)
    y_pred = rf_clf.predict(X_test_scaled)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Binary Security Detection Metrics (BENIGN vs MALICIOUS)
    yb_pred = (y_pred != "BENIGN").astype(int)
    malicious_recall = float(recall_score(yb_test, yb_pred, pos_label=1, zero_division=0))
    malicious_precision = float(precision_score(yb_test, yb_pred, pos_label=1, zero_division=0))

    # False Positive Rate on Benign Traffic (FP / (FP + TN))
    tn = int(np.sum((yb_test == 0) & (yb_pred == 0)))
    fp = int(np.sum((yb_test == 0) & (yb_pred == 1)))
    fpr = float(fp / max(1, (fp + tn)))

    classes = list(rf_clf.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

    # Feature Importance
    importances = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(
            zip(FEATURE_COLS, rf_clf.feature_importances_),
            key=lambda x: x[1],
            reverse=True
        )
    }

    print(f"Accuracy:           {acc * 100:.2f}%")
    print(f"Precision:          {prec * 100:.2f}%")
    print(f"Recall:             {rec * 100:.2f}%")
    print(f"F1 Score:           {f1 * 100:.2f}%")
    print(f"Malicious Recall:   {malicious_recall * 100:.2f}%")
    print(f"Malicious Precision:{malicious_precision * 100:.2f}%")
    print(f"False Positive Rate:{fpr * 100:.2f}%")
    print("-" * 60)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=classes, zero_division=0))

    # 8. Save Pipeline Artifact (Fully compatible with existing inference engine)
    model_payload = {
        "classifier": rf_clf,
        "isolation_forest": iso_forest,
        "scaler": scaler,
        "features": FEATURE_COLS,
        "classes": classes,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "RandomForestClassifier + IsolationForest",
        "version": "2.0.0"
    }

    joblib.dump(model_payload, MODEL_PATH)
    print(f"Saved model artifact to: {MODEL_PATH} ({os.path.getsize(MODEL_PATH) / 1024 / 1024:.2f} MB)")

    # 9. Save Real Metrics JSON
    metrics_payload = {
        "model_name": "VORTEX Security Threat Classifier",
        "model_type": "Random Forest + Isolation Forest Ensemble",
        "version": "2.0.0",
        "status": "HEALTHY",
        "dataset_source": dataset_source_name,
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "malicious_recall": round(malicious_recall, 4),
        "malicious_precision": round(malicious_precision, 4),
        "false_positive_rate": round(fpr, 4),
        "classes": classes,
        "confusion_matrix": cm,
        "class_distribution": df["attack_type"].value_counts().to_dict(),
        "feature_importance": importances,
        "last_trained": datetime.now(timezone.utc).isoformat(),
        "inference_count": 0
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"Saved metrics metadata to: {METRICS_PATH}")

    # Reload inference engine singleton with the newly trained model
    try:
        from ai.inference import ai_engine
        ai_engine.load_models()
        print("Successfully reloaded AI inference engine with new model artifact.")
    except Exception as e:
        print(f"[Warning] Could not reload ai_engine in current process: {e}")

    return metrics_payload

def main():
    parser = argparse.ArgumentParser(description="VORTEX-SDN Security Model Trainer")
    parser.add_argument(
        "--dataset",
        type=str,
        default="cicids2017",
        help="Dataset to train with: 'cicids2017' (default) or custom CSV path"
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Explicitly train using synthetic dataset instead of CICIDS2017"
    )
    args = parser.parse_args()

    if args.synthetic:
        train_security_model(use_synthetic=True)
    elif args.dataset != "cicids2017" and os.path.exists(args.dataset):
        train_security_model(use_synthetic=False, dataset_path=args.dataset)
    else:
        train_security_model(use_synthetic=False)

if __name__ == "__main__":
    main()
