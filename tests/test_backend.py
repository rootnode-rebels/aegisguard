"""
Automated Backend & Machine Learning Verification Suite.
Validates Database operations, Password security, Rate limiting, ML Inference, and CloudWatch telemetry.
"""
import sys
import os
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_manager import db
from backend.security.auth import hash_password, verify_password, validate_password_strength
from backend.security.rate_limiter import rate_limiter
from backend.ml.feature_extractor import haversine_distance_km, calculate_geo_velocity, extract_features
from backend.ml.model import ml_engine
from backend.ml.tf_autoencoder import tf_autoencoder
from backend.monitoring.cloudwatch_service import cloudwatch
from backend.security.sanitizer import sanitize_mongo_dict, sanitize_string, sanitize_email

class TestAccountHijackSystem(unittest.TestCase):

    def test_01_database_operations(self):
        """Validates MongoDB-compatible collection mutations."""
        test_email = "test_user_ci@example.com"
        db.users.delete_many({"email": test_email})

        # Insert
        insert_res = db.users.insert_one({
            "email": test_email,
            "full_name": "CI Test User",
            "status": "ACTIVE"
        })
        self.assertIn("inserted_id", insert_res)

        # Find
        user = db.users.find_one({"email": test_email})
        self.assertIsNotNone(user)
        self.assertEqual(user["full_name"], "CI Test User")

        # Update
        updated = db.users.update_one({"email": test_email}, {"$set": {"status": "RESTRICTED"}})
        self.assertTrue(updated)
        user_after = db.users.find_one({"email": test_email})
        self.assertEqual(user_after["status"], "RESTRICTED")

        # Cleanup
        db.users.delete_many({"email": test_email})
        self.assertIsNone(db.users.find_one({"email": test_email}))
        print("[TEST] Database operations: PASSED")

    def test_02_password_security(self):
        """Validates PBKDF2 hashing, salting, and constant-time verification."""
        password = "SecurePassword#2026"
        pw_hash, salt = hash_password(password)

        self.assertNotEqual(password, pw_hash)
        self.assertTrue(len(salt) >= 16)
        self.assertTrue(verify_password(password, pw_hash, salt))
        self.assertFalse(verify_password("WrongPassword123", pw_hash, salt))

        # Complexity validator
        valid, _ = validate_password_strength("Short1!")
        self.assertFalse(valid)
        valid, _ = validate_password_strength("ValidPassword123#")
        self.assertTrue(valid)
        print("[TEST] Password security & PBKDF2: PASSED")

    def test_03_rate_limiter(self):
        """Validates sliding window brute-force lockout."""
        ip = "192.0.2.99"
        rate_limiter.record_success(ip)

        # 4 failures should not lock
        for _ in range(4):
            is_locked, _ = rate_limiter.record_failure(ip)
            self.assertFalse(is_locked)

        # 5th failure triggers lockout
        is_locked, rem = rate_limiter.record_failure(ip)
        self.assertTrue(is_locked)
        self.assertGreater(rem, 0)

        # Clear
        rate_limiter.record_success(ip)
        is_locked_after, _ = rate_limiter.is_locked(ip)
        self.assertFalse(is_locked_after)
        print("[TEST] Rate limiter brute-force defense: PASSED")

    def test_04_ml_risk_engine(self):
        """Validates ML risk scoring against legitimate and attack profiles."""
        # 1. Normal legitimate login
        normal_features = {
            "geo_velocity_kmh": 15.0,
            "distance_km": 5.0,
            "device_distance": 0.0,
            "ip_reputation": 0.0,
            "failed_attempts_burst": 0,
            "circadian_anomaly": 0.1,
            "bot_signature": 0.0
        }
        res_normal = ml_engine.evaluate_risk(normal_features)
        self.assertLess(res_normal["risk_score"], 40.0)
        self.assertEqual(res_normal["action"], "ALLOW")

        # 2. Impossible Travel Attack (London to Tokyo in 2 minutes -> 8,000 km/h)
        travel_features = {
            "geo_velocity_kmh": 8500.0,
            "distance_km": 9500.0,
            "device_distance": 0.8,
            "ip_reputation": 0.1,
            "failed_attempts_burst": 0,
            "circadian_anomaly": 0.4,
            "bot_signature": 0.0
        }
        res_travel = ml_engine.evaluate_risk(travel_features)
        self.assertGreaterEqual(res_travel["risk_score"], 70.0)
        self.assertEqual(res_travel["action"], "BLOCK_SESSION")
        self.assertTrue(any("Impossible Travel" in f["factor"] for f in res_travel["explainable_factors"]))

        # 3. Credential Stuffing from Tor Exit Node
        tor_features = {
            "geo_velocity_kmh": 200.0,
            "distance_km": 1000.0,
            "device_distance": 1.0,
            "ip_reputation": 1.0, # Tor
            "failed_attempts_burst": 1,
            "circadian_anomaly": 0.5,
            "bot_signature": 1.0
        }
        res_tor = ml_engine.evaluate_risk(tor_features)
        self.assertGreaterEqual(res_tor["risk_score"], 70.0)
        self.assertEqual(res_tor["action"], "BLOCK_SESSION")
        print("[TEST] ML Risk Engine & Anomaly Detection: PASSED")

    def test_05_tensorflow_autoencoder(self):
        """Validates Deep Autoencoder reconstruction loss."""
        normal_vec = [15.0, 10.0, 0.0, 0.0, 0.0, 0.1, 0.0]
        loss_normal = tf_autoencoder.compute_reconstruction_loss(normal_vec)
        self.assertFalse(loss_normal["neural_anomaly_detected"])

        anom_vec = [8000.0, 9000.0, 1.0, 1.0, 8.0, 0.9, 1.0]
        loss_anom = tf_autoencoder.compute_reconstruction_loss(anom_vec)
        self.assertTrue(loss_anom["neural_anomaly_detected"])
        self.assertGreater(loss_anom["mse_reconstruction_error"], loss_normal["mse_reconstruction_error"])
        print("[TEST] Deep Autoencoder Neural Reconstruction: PASSED")

    def test_06_cloudwatch_monitoring(self):
        """Validates CloudWatch metrics aggregation and log stream."""
        cloudwatch.record_invocation("/test/api", latency_ms=4.2)
        cloudwatch.record_security_decision(risk_score=92.0, action="BLOCK_SESSION")
        summary = cloudwatch.get_dashboard_summary()

        self.assertGreater(summary["metrics"]["Invocations"], 0)
        self.assertGreater(summary["metrics"]["BlockedHijacks"], 0)
        self.assertTrue(len(summary["alarms"]) >= 2)
        print("[TEST] CloudWatch Monitoring & Metrics: PASSED")

    def test_07_advanced_security_hardening(self):
        """Validates anti-injection sanitization, prototype pollution defense, and dual rate limiting."""
        # 1. NoSQL operator and prototype pollution injection
        malicious_input = {
            "$where": "this.password == 'admin'",
            "$gt": "",
            "__proto__": {"polluted": True},
            "constructor": "evil",
            "username": "<script>alert('XSS')</script>admin",
            "nested": {
                "$ne": None,
                "clean_key": "safe_val"
            }
        }
        sanitized = sanitize_mongo_dict(malicious_input)
        self.assertNotIn("$where", sanitized)
        self.assertNotIn("$gt", sanitized)
        self.assertNotIn("__proto__", sanitized)
        self.assertNotIn("constructor", sanitized)
        self.assertNotIn("<script>", sanitized.get("username", ""))
        self.assertIn("&lt;script&gt;", sanitized.get("username", ""))
        self.assertNotIn("$ne", sanitized.get("nested", {}))
        self.assertEqual(sanitized.get("nested", {}).get("clean_key"), "safe_val")

        # 2. Dual rate limiter test (Account-level key)
        acct_key = "acct:targeted_user@corp.com"
        rate_limiter.record_success(acct_key)
        for _ in range(4):
            rate_limiter.record_failure(acct_key)
        is_locked, _ = rate_limiter.record_failure(acct_key)
        self.assertTrue(is_locked)
        rate_limiter.record_success(acct_key)
        is_locked_after, _ = rate_limiter.is_locked(acct_key)
        self.assertFalse(is_locked_after)
        print("[TEST] Advanced Security Hardening (Anti-Injection & Dual Rate Limiting): PASSED")

if __name__ == "__main__":
    unittest.main()

