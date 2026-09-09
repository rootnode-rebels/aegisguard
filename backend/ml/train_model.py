"""
Machine Learning Training Script for Account Hijacking Anomaly Detection.
Trains Scikit-learn Isolation Forest and Random Forest behavioral risk classifiers.
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.joblib")

FEATURE_COLUMNS = [
    "geo_velocity_kmh",
    "distance_km",
    "device_distance",
    "ip_reputation",
    "failed_attempts_burst",
    "circadian_anomaly",
    "bot_signature"
]

def generate_synthetic_telemetry(num_samples: int = 5000):
    """
    Generates realistic cyber telemetry for normal sessions and hijacking attacks.
    """
    np.random.seed(42)
    rows = []

    # 1. Normal Legitimate Logins (75% of data)
    num_normal = int(num_samples * 0.75)
    for _ in range(num_normal):
        geo_velocity = float(np.random.exponential(scale=15.0)) # typical commuting/walking speeds
        distance = float(np.random.exponential(scale=20.0))
        device_distance = float(np.random.choice([0.0, 0.25], p=[0.85, 0.15])) # familiar or slight update
        ip_rep = float(np.random.choice([0.0, 0.05], p=[0.9, 0.1])) # residential IP
        failures = int(np.random.choice([0, 1], p=[0.95, 0.05])) # 0 or 1 typo
        circadian = float(np.random.choice([0.1, 0.3], p=[0.85, 0.15]))
        bot_sig = 0.0 # real browser
        label = 0 # Normal
        rows.append([geo_velocity, distance, device_distance, ip_rep, failures, circadian, bot_sig, label])

    # 2. Impossible Travel Attacks (8% of data)
    num_travel = int(num_samples * 0.08)
    for _ in range(num_travel):
        geo_velocity = float(np.random.uniform(900.0, 8000.0)) # Mach 1 to supersonic cross-continental
        distance = float(np.random.uniform(1500.0, 12000.0))
        device_distance = float(np.random.choice([0.75, 1.0], p=[0.3, 0.7])) # foreign device
        ip_rep = float(np.random.choice([0.2, 0.75], p=[0.5, 0.5]))
        failures = int(np.random.choice([0, 1, 2]))
        circadian = float(np.random.choice([0.4, 0.7]))
        bot_sig = float(np.random.choice([0.0, 0.5]))
        label = 1 # Suspicious / Hijack
        rows.append([geo_velocity, distance, device_distance, ip_rep, failures, circadian, bot_sig, label])

    # 3. Credential Stuffing / Tor Exit Attacks (8% of data)
    num_stuffing = int(num_samples * 0.08)
    for _ in range(num_stuffing):
        geo_velocity = float(np.random.uniform(200.0, 3000.0))
        distance = float(np.random.uniform(500.0, 5000.0))
        device_distance = 1.0 # completely unknown device
        ip_rep = 1.0 # Confirmed Tor / Malicious Proxy
        failures = int(np.random.choice([0, 1, 2]))
        circadian = float(np.random.choice([0.5, 0.8]))
        bot_sig = float(np.random.choice([0.5, 1.0]))
        label = 1
        rows.append([geo_velocity, distance, device_distance, ip_rep, failures, circadian, bot_sig, label])

    # 4. Brute Force Velocity Takeover (9% of data)
    num_brute = int(num_samples * 0.09)
    for _ in range(num_brute):
        geo_velocity = float(np.random.uniform(50.0, 1000.0))
        distance = float(np.random.uniform(10.0, 1000.0))
        device_distance = float(np.random.choice([0.5, 1.0]))
        ip_rep = float(np.random.choice([0.5, 0.75, 1.0]))
        failures = int(np.random.randint(4, 12)) # high burst of failed attempts
        circadian = float(np.random.choice([0.3, 0.7]))
        bot_sig = float(np.random.choice([0.0, 1.0]))
        label = 1
        rows.append([geo_velocity, distance, device_distance, ip_rep, failures, circadian, bot_sig, label])

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])
    return df

def train_and_save_model():
    print("[ML Train] Generating synthetic security telemetry...")
    df = generate_synthetic_telemetry(num_samples=6000)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("[ML Train] Fitting Feature Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[ML Train] Training Scikit-learn Isolation Forest (Unsupervised Anomaly Detector)...")
    iso_forest = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
    iso_forest.fit(X_train_scaled)

    print("[ML Train] Training Scikit-learn Random Forest Classifier (Supervised Risk Calibrator)...")
    rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf_classifier.fit(X_train, y_train)

    # Evaluation
    preds_proba = rf_classifier.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, preds_proba)
    print(f"[ML Train] Random Forest ROC-AUC: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, rf_classifier.predict(X_test), target_names=["Normal", "Hijack Attempt"]))

    print("Feature Importances:")
    for col, imp in zip(FEATURE_COLUMNS, rf_classifier.feature_importances_):
        print(f"  • {col:25s}: {imp:.4f}")

    # Package pipeline
    artifact = {
        "scaler": scaler,
        "isolation_forest": iso_forest,
        "random_forest": rf_classifier,
        "features": FEATURE_COLUMNS,
        "auc_score": auc
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(artifact, MODEL_PATH)
    print(f"[ML Train] Model successfully exported to: {MODEL_PATH}")

if __name__ == "__main__":
    train_and_save_model()
