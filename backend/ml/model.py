"""
Real-Time Machine Learning Inference Engine for Account Hijacking Detection.
Evaluates behavioral feature vectors and computes calibrated risk scores and explainable factors.
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, List

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.joblib")

class MLRiskEngine:
    def __init__(self):
        self.model_data = None
        self.scaler = None
        self.iso_forest = None
        self.random_forest = None
        self.features = [
            "geo_velocity_kmh",
            "distance_km",
            "device_distance",
            "ip_reputation",
            "failed_attempts_burst",
            "circadian_anomaly",
            "bot_signature"
        ]
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model_data = joblib.load(MODEL_PATH)
                self.scaler = self.model_data.get("scaler")
                self.iso_forest = self.model_data.get("isolation_forest")
                self.random_forest = self.model_data.get("random_forest")
                self.features = self.model_data.get("features", self.features)
                print("[ML Engine] Pre-trained behavioral models loaded successfully.")
            except Exception as e:
                print(f"[ML Engine] Failed loading model file ({e}). Using deterministic fallback.")
                self.model_data = None

    def evaluate_risk(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Infers risk score (0-100), risk level, policy action, and itemized explainable AI factors.
        """
        # Build feature vector as DataFrame with feature names
        import pandas as pd
        vector_df = pd.DataFrame([[float(feature_dict.get(col, 0.0)) for col in self.features]], columns=self.features)

        # 1. Scikit-learn Random Forest probability (if available)
        rf_score = None
        iso_anomaly = False
        if self.random_forest is not None:
            try:
                probs = self.random_forest.predict_proba(vector_df)[0]
                rf_score = probs[1] * 100.0 # Probability of hijacking
                if self.iso_forest is not None and self.scaler is not None:
                    scaled = self.scaler.transform(vector_df)
                    iso_pred = self.iso_forest.predict(scaled)[0]
                    iso_anomaly = (iso_pred == -1)
            except Exception as e:
                print(f"[ML Engine] Inference error: {e}")
                rf_score = None

        # 2. Explainable Factor Calculation
        geo_vel = feature_dict.get("geo_velocity_kmh", 0.0)
        dist_km = feature_dict.get("distance_km", 0.0)
        dev_dist = feature_dict.get("device_distance", 0.0)
        ip_rep = feature_dict.get("ip_reputation", 0.0)
        failures = feature_dict.get("failed_attempts_burst", 0)
        bot_sig = feature_dict.get("bot_signature", 0.0)

        # Baseline heuristic risk factor points
        factors: List[Dict[str, Any]] = []
        rule_score = 0.0

        # Factor A: Geo-Velocity / Impossible Travel
        if geo_vel >= 900.0:
            pts = min(55.0, 35.0 + (geo_vel / 300.0))
            factors.append({
                "factor": "Impossible Travel Detected",
                "detail": f"Travel velocity of {geo_vel:,.0f} km/h over {dist_km:,.0f} km exceeds commercial flight speed.",
                "weight": round(pts, 1),
                "severity": "CRITICAL"
            })
            rule_score += pts
        elif geo_vel >= 250.0:
            factors.append({
                "factor": "High Travel Velocity",
                "detail": f"Speed of {geo_vel:,.0f} km/h between locations.",
                "weight": 15.0,
                "severity": "WARNING"
            })
            rule_score += 15.0

        # Factor B: IP Reputation (Tor / Datacenter / Proxy)
        if ip_rep >= 0.9:
            factors.append({
                "factor": "Tor Exit Node / Anonymizing Proxy",
                "detail": "Incoming IP is a verified Tor exit relay.",
                "weight": 35.0,
                "severity": "CRITICAL"
            })
            rule_score += 35.0
        elif ip_rep >= 0.5:
            factors.append({
                "factor": "Datacenter / Commercial VPN IP",
                "detail": "Connection originated from an automated hosting facility.",
                "weight": 20.0,
                "severity": "WARNING"
            })
            rule_score += 20.0

        # Factor C: Device Fingerprint Distance
        if dev_dist >= 0.8:
            factors.append({
                "factor": "Completely Unrecognized Device",
                "detail": "Hardware canvas, OS, and screen signature diverge from user history.",
                "weight": 25.0,
                "severity": "WARNING"
            })
            rule_score += 25.0
        elif dev_dist >= 0.4:
            factors.append({
                "factor": "New Device Signature",
                "detail": "Device parameters have partial variance.",
                "weight": 12.0,
                "severity": "INFO"
            })
            rule_score += 12.0

        # Factor D: Failed Attempt Bursts
        if failures >= 4:
            factors.append({
                "factor": "Brute Force Burst",
                "detail": f"{failures} rapid failed login attempts recorded within 15 minutes.",
                "weight": 30.0,
                "severity": "CRITICAL"
            })
            rule_score += 30.0
        elif failures >= 2:
            factors.append({
                "factor": "Repeated Failed Attempts",
                "detail": f"{failures} failed attempts recently.",
                "weight": 15.0,
                "severity": "WARNING"
            })
            rule_score += 15.0

        # Factor E: Bot / Automated Browser Signature
        if bot_sig >= 0.8:
            factors.append({
                "factor": "Automated Headless Client",
                "detail": "User-Agent or webdriver indicates automation tooling.",
                "weight": 25.0,
                "severity": "CRITICAL"
            })
            rule_score += 25.0

        # Ensemble Score (Combining Random Forest + Rules + Isolation Anomaly)
        if rf_score is not None:
            composite_score = (rf_score * 0.6) + (min(100.0, rule_score) * 0.4)
            if iso_anomaly:
                composite_score = min(100.0, composite_score + 10.0)
        else:
            composite_score = min(100.0, rule_score)

        final_score = round(max(0.0, min(100.0, composite_score)), 1)

        # Policy Mapping
        if final_score < 40.0:
            risk_level = "LOW"
            action = "ALLOW"
        elif final_score < 70.0:
            risk_level = "MEDIUM"
            action = "STEP_UP_MFA"
        elif final_score < 90.0:
            risk_level = "HIGH"
            action = "BLOCK_SESSION"
        else:
            risk_level = "CRITICAL"
            action = "BLOCK_SESSION"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "action": action,
            "explainable_factors": factors,
            "isolation_forest_outlier": iso_anomaly,
            "features": feature_dict
        }

ml_engine = MLRiskEngine()
