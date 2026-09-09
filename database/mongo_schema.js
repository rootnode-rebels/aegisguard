// MongoDB Database Schema & Indexes for Account Hijacking Detection System
// Target Database: account_security_db

// 1. Users Collection
// Stores user identity, cryptographic password hash, salt, account status, and baseline behavior profile
db.createCollection("users", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["email", "password_hash", "salt", "status", "created_at"],
      properties: {
        email: { bsonType: "string", pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$" },
        full_name: { bsonType: "string" },
        password_hash: { bsonType: "string" },
        salt: { bsonType: "string" },
        status: { enum: ["ACTIVE", "LOCKED", "RESTRICTED", "MFA_REQUIRED"] },
        created_at: { bsonType: "string" },
        updated_at: { bsonType: "string" },
        trusted_devices: { bsonType: "array" },
        baseline_profile: {
          bsonType: "object",
          properties: {
            typical_login_hours: { bsonType: "array" },
            primary_locations: { bsonType: "array" },
            known_ips: { bsonType: "array" },
            avg_session_duration: { bsonType: "number" }
          }
        }
      }
    }
  }
});
db.users.createIndex({ "email": 1 }, { unique: true });

// 2. Active Sessions Collection (With TTL Index for Automatic Expiry)
db.createCollection("active_sessions");
db.active_sessions.createIndex({ "session_token": 1 }, { unique: true });
db.active_sessions.createIndex({ "user_id": 1 });
db.active_sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 }); // MongoDB TTL auto-cleanup

// 3. Security Events Collection
// Real-time security telemetry for all login attempts, risk scores, and attack vectors
db.createCollection("security_events");
db.security_events.createIndex({ "user_email": 1 });
db.security_events.createIndex({ "timestamp": -1 });
db.security_events.createIndex({ "risk_level": 1 });
db.security_events.createIndex({ "ip_address": 1 });

// 4. Password Resets Collection (With TTL)
db.createCollection("password_resets");
db.password_resets.createIndex({ "reset_token": 1 }, { unique: true });
db.password_resets.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

// 5. CloudWatch Logs & Metrics Collection
db.createCollection("cloudwatch_logs");
db.cloudwatch_logs.createIndex({ "timestamp": -1 });
db.cloudwatch_logs.createIndex({ "log_group": 1 });
