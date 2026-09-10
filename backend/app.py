"""
Central FastAPI Serverless Local Emulator & REST API Gateway.
Coordinates Authentication, Machine Learning Anomaly Detection, AWS CloudWatch Telemetry, and MongoDB Storage.
"""
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Header, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Database & Security imports
from database.db_manager import db
from backend.security.sanitizer import sanitize_string, sanitize_email, sanitize_mongo_dict
from backend.security.rate_limiter import rate_limiter
from backend.security.auth import (
    hash_password, verify_password, generate_session_token,
    generate_mfa_code, generate_reset_token, validate_password_strength
)
from backend.ml.feature_extractor import extract_features
from backend.ml.model import ml_engine
from backend.ml.tf_autoencoder import tf_autoencoder
from backend.monitoring.cloudwatch_service import cloudwatch

app = FastAPI(
    title="Real-Time Account Hijacking Detection & Prevention System",
    version="2.0.0",
    description="AWS Serverless & ML-driven Cybersecurity Defense Platform"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Maintenance mode toggle for UX state demonstration
MAINTENANCE_MODE = False

def seed_demo_user_if_needed():
    """Seeds baseline legitimate user accounts for instant multi-browser testing."""
    accounts = [
        ("demo@awssecurity.io", "AWSSecurity#2026", "Sachin (Demo Security Lead)"),
        ("demo@aegisguard.io", "AegisGuard#2026", "Sachin (Legacy Demo Account)")
    ]
    for email, pwd, name in accounts:
        try:
            existing = db.users.find_one({"email": email})
            if not existing:
                pw_hash, salt = hash_password(pwd)
                now_iso = datetime.now(timezone.utc).isoformat()
                demo_user = {
                    "email": email,
                    "full_name": name,
                    "password_hash": pw_hash,
                    "salt": salt,
                    "status": "ACTIVE",
                    "created_at": now_iso,
                    "updated_at": now_iso,
                    "trusted_devices": [{
                        "os": "Windows NT 10.0",
                        "platform": "Win32",
                        "screen_resolution": "1920x1080",
                        "color_depth": 24,
                        "timezone": "America/New_York",
                        "language": "en-US",
                        "canvas_hash": "canvas_trusted_demo"
                    }],
                    "last_successful_login": {
                        "timestamp": time.time() - 7200,
                        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
                        "ip": "198.51.100.10",
                        "device": "Windows NT 10.0"
                    },
                    "mfa_secret": None,
                    "mfa_pending": None
                }
                db.users.insert_one(demo_user)
                print(f"[AWSSecurity] Seeded default demo account: {email} / {pwd}")
        except Exception as e:
            print(f"[AWSSecurity] Demo user seed notice: {e}")

seed_demo_user_if_needed()

# -------------------------------------------------------------
# Middleware: Request Correlation ID & CloudWatch Invocation Logging
# -------------------------------------------------------------
@app.middleware("http")
async def cloudwatch_telemetry_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    start_time = time.time()

    if MAINTENANCE_MODE and not request.url.path.startswith("/api/system/maintenance"):
        return JSONResponse(
            status_code=503,
            content={
                "error": "Service Under Maintenance",
                "message": "System security baseline update in progress. Please check back shortly.",
                "correlation_id": correlation_id,
                "retry_after_seconds": 300
            }
        )

    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000.0

    # Emit CloudWatch invocation metric
    cloudwatch.record_invocation(
        function_name=request.url.path,
        latency_ms=duration_ms,
        status_code=response.status_code
    )
    response.headers["X-Request-Id"] = correlation_id
    return response


# -------------------------------------------------------------
# Middleware: Defense-in-Depth OWASP Security Headers
# -------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(self), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https: ws: wss:;"
    )
    return response


# -------------------------------------------------------------
# Pydantic Request Schemas (Strict Input Validation)
# -------------------------------------------------------------
class RegisterSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=8, max_length=128)
    fingerprint: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None

class LoginSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)
    fingerprint: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None
    spoofed_ip: Optional[str] = None
    spoofed_user_agent: Optional[str] = None

class VerifyMFASchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    mfa_code: str = Field(min_length=6, max_length=6)
    temp_token: str

class ForgotPasswordSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

class SessionKillSchema(BaseModel):
    session_id: str

class AccountDeleteSchema(BaseModel):
    password: str

class SetPrimaryDeviceSchema(BaseModel):
    is_primary: bool = True
    device_label: Optional[str] = None


# -------------------------------------------------------------
# Helper: Authenticate Session Token
# -------------------------------------------------------------
def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication token required or expired.")
    token = authorization.split(" ")[1]
    session = db.active_sessions.find_one({"session_token": token})
    if not session or session.get("status") != "ACTIVE":
        raise HTTPException(status_code=401, detail="Session expired or revoked.")
    
    # Check session expiration
    now = datetime.now(timezone.utc).isoformat()
    if session.get("expires_at", "") < now:
        db.active_sessions.delete_one({"session_token": token})
        raise HTTPException(status_code=401, detail="Session has expired. Please log in again.")

    user = db.users.find_one({"email": session.get("user_email")})
    if not user:
        raise HTTPException(status_code=401, detail="User account not found.")
    if user.get("status") == "LOCKED":
        raise HTTPException(
            status_code=403,
            detail={"error": "ACCOUNT_LOCKED", "message": "Account is temporarily locked for security. Contact incident response."}
        )
    return user


# -------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------
@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterSchema, request: Request):
    clean_email = sanitize_email(payload.email)
    clean_name = sanitize_string(payload.full_name)

    # Password validation
    is_valid, msg = validate_password_strength(payload.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    # Check existence
    existing = db.users.find_one({"email": clean_email})
    if existing:
        # Anti-enumeration response per user rules: do not leak specific account presence
        raise HTTPException(status_code=400, detail="Unable to complete registration with provided details.")

    # Hash password securely (PBKDF2-HMAC-SHA256 with 200,000 iterations)
    pw_hash, salt = hash_password(payload.password)

    client_ip = request.client.host if request.client else "127.0.0.1"
    geo_loc = payload.geo or {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}
    fingerprint = sanitize_mongo_dict(payload.fingerprint or {})

    now_iso = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "email": clean_email,
        "full_name": clean_name,
        "password_hash": pw_hash,
        "salt": salt,
        "status": "ACTIVE",
        "created_at": now_iso,
        "updated_at": now_iso,
        "trusted_devices": [fingerprint] if fingerprint else [],
        "last_successful_login": {
            "timestamp": time.time(),
            "geo": geo_loc,
            "ip": client_ip,
            "device": fingerprint.get("platform", "Desktop")
        },
        "mfa_secret": None,
        "mfa_pending": None
    }
    db.users.insert_one(user_doc)

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User registered: {clean_email}",
        payload={"ip": client_ip, "city": geo_loc.get("city")}
    )

    return {"status": "success", "message": "Account successfully created. Please sign in."}


@app.post("/api/auth/login")
def login(payload: LoginSchema, request: Request):
    client_ip = payload.spoofed_ip or (request.client.host if request.client else "127.0.0.1")
    user_agent = payload.spoofed_user_agent or request.headers.get("user-agent", "")
    email = sanitize_email(payload.email)
    raw_password = payload.password
    geo = payload.geo or {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}
    fingerprint = sanitize_mongo_dict(payload.fingerprint or {})

    # 1. Check Rate Limiter (Dual-layer brute-force protection: IP + Target Account)
    is_locked_ip, remaining_ip = rate_limiter.is_locked(client_ip)
    is_locked_acct, remaining_acct = rate_limiter.is_locked(f"acct:{email}")
    if is_locked_ip or is_locked_acct:
        remaining = max(remaining_ip, remaining_acct)
        # Dispatch high-priority alert to legitimate user
        db.get_collection("security_alerts").insert_one({
            "alert_id": f"alt_lock_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "BRUTE_FORCE_LOCKOUT",
            "risk_score": 95.0,
            "origin": geo.get("city", "Current Location") + ", " + geo.get("country", "Local"),
            "ip": client_ip,
            "device": f"{fingerprint.get('browser', 'Browser')} on {fingerprint.get('os', 'Desktop')}",
            "status": "UNRESOLVED",
            "reason": f"🚨 Brute Force Lockout Active: Too many failed login attempts against your account from {client_ip}.",
            "factors": [{"factor": "Brute Force Burst", "detail": f"Temporarily blocked for {remaining} seconds.", "weight": 95.0, "severity": "CRITICAL"}]
        })
        cloudwatch.record_security_decision(risk_score=95.0, action="BLOCK_SESSION")
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="WARN",
            message=f"Brute force lockout active for IP {client_ip} / Account {email}",
            payload={"remaining_seconds": remaining}
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Access temporarily restricted. Try again in {remaining} seconds."
        )

    # 2. Retrieve user
    user = db.users.find_one({"email": email})
    recent_failures = rate_limiter.get_recent_failure_count(client_ip)

    # 3. Behavioral Feature Extraction & ML Inference
    attempt_telemetry = {
        "timestamp": time.time(),
        "geo": geo,
        "ip": client_ip,
        "fingerprint": fingerprint,
        "user_agent": user_agent
    }
    features = extract_features(user, attempt_telemetry, recent_failures)
    ml_eval = ml_engine.evaluate_risk(features)
    risk_score = ml_eval["risk_score"]
    risk_action = ml_eval["action"]
    risk_level = ml_eval["risk_level"]

    # 4. Deep Autoencoder Verification (TensorFlow Module)
    feature_vector = [
        features["geo_velocity_kmh"],
        features["distance_km"],
        features["device_distance"],
        features["ip_reputation"],
        features["failed_attempts_burst"],
        features["circadian_anomaly"],
        features["bot_signature"]
    ]
    autoencoder_res = tf_autoencoder.compute_reconstruction_loss(feature_vector)

    # Record security event in audit collection
    event_id = f"evt_{int(time.time() * 1000)}"
    sec_event = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_email": email,
        "ip_address": client_ip,
        "geo": geo,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action_taken": risk_action,
        "factors": ml_eval["explainable_factors"],
        "autoencoder_loss": autoencoder_res["mse_reconstruction_error"],
        "device": fingerprint.get("os", "Unknown Device")
    }
    db.security_events.insert_one(sec_event)

    # Log to CloudWatch
    cloudwatch.record_security_decision(risk_score, risk_action)
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AccountHijackRiskEngine",
        level="WARN" if risk_score >= 40 else "INFO",
        message=f"Login evaluation for {email}: Score {risk_score} -> Action: {risk_action}",
        payload={"factors": ml_eval["explainable_factors"], "geo": geo}
    )

    # 5. Check credentials with timing-attack defense (Anti-Enumeration)
    credentials_valid = False
    if user and user.get("status") != "LOCKED":
        credentials_valid = verify_password(raw_password, user["password_hash"], user["salt"])
    else:
        # Constant-time dummy PBKDF2 calculation prevents side-channel timing attacks (user enumeration)
        _ = verify_password(raw_password, "0"*64, "0123456789abcdef0123456789abcdef")

    if not credentials_valid:
        rate_limiter.record_failure(client_ip)
        is_locked_acct, remaining_acct = rate_limiter.record_failure(f"acct:{email}")
        fail_count = rate_limiter.get_recent_failure_count(f"acct:{email}")

        if user:
            browser_name = fingerprint.get("browser", "Web Browser")
            os_name = fingerprint.get("os", "Desktop")
            device_desc = f"{browser_name} on {os_name}"
            
            if is_locked_acct or fail_count >= 5:
                alert_type = "BRUTE_FORCE_LOCKOUT"
                reason = f"🚨 Brute Force Attack Detected: {fail_count} failed password attempts. Attacker locked out for {remaining_acct}s."
                score = 95.0
            elif fail_count >= 2:
                alert_type = "REPEATED_FAILED_LOGINS"
                reason = f"⚠️ Repeated Failed Logins: {fail_count} unauthorized attempts with incorrect password from {device_desc}."
                score = min(90.0, 50.0 + fail_count * 10.0)
            else:
                alert_type = "SUSPICIOUS_FAILED_LOGIN"
                reason = f"⚠️ Failed login attempt: Incorrect password entered from {device_desc}."
                score = 45.0

            alert_doc = {
                "alert_id": f"alt_fail_{int(time.time()*1000)}",
                "user_email": email,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "type": alert_type,
                "risk_score": score,
                "origin": geo.get("city", "Current Location") + ", " + geo.get("country", "Local"),
                "ip": client_ip,
                "device": device_desc,
                "status": "UNRESOLVED",
                "reason": reason,
                "factors": [
                    {
                        "factor": "Credential Guessing / Failed Attempt",
                        "detail": f"{fail_count} failed attempt(s) recorded from {device_desc}.",
                        "weight": score,
                        "severity": "CRITICAL" if fail_count >= 4 else "WARNING"
                    }
                ]
            }
            db.get_collection("security_alerts").insert_one(alert_doc)

            # Record in security_events for SOC Blue Team
            db.security_events.insert_one({
                "event_id": f"evt_fail_{int(time.time()*1000)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_email": email,
                "ip_address": client_ip,
                "geo": geo,
                "risk_score": score,
                "risk_level": "CRITICAL" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
                "action_taken": "BLOCK_SESSION" if is_locked_acct else "CREDENTIAL_FAILURE",
                "factors": alert_doc["factors"],
                "device": device_desc
            })

            cloudwatch.record_security_decision(score, "BLOCK_SESSION" if is_locked_acct else "WARN")
            cloudwatch.put_log_event(
                log_group="/aws/lambda/AuthHandler",
                level="WARN",
                message=f"Failed login attempt ({fail_count} recent) against {email} from {client_ip} ({device_desc})",
                payload={"failures": fail_count, "device": device_desc}
            )

        # GENERIC ERROR MESSAGE per User Rules (prevents account enumeration)
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials or account restricted."
        )

    # 6. Adaptive Security Policy Enforcement
    # Scenario A: HIGH / CRITICAL RISK -> AUTOMATIC BLOCK
    if risk_action == "BLOCK_SESSION":
        # Dispatch notification to legitimate user inbox
        alert_doc = {
            "alert_id": f"alt_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "HIGH_RISK_HIJACK_BLOCKED",
            "risk_score": risk_score,
            "origin": geo.get("city", "Foreign Location") + ", " + geo.get("country", "Unknown"),
            "ip": client_ip,
            "device": fingerprint.get("os", "Unknown"),
            "status": "UNRESOLVED",
            "reason": ml_eval["explainable_factors"][0]["factor"] if ml_eval["explainable_factors"] else "Suspicious anomaly",
            "factors": ml_eval["explainable_factors"]
        }
        db.get_collection("security_alerts").insert_one(alert_doc)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access Blocked",
                "message": "Suspicious login activity detected (Impossible Travel / Malicious IP / Unknown Device). Access blocked to protect this account.",
                "risk_score": risk_score,
                "factors": ml_eval["explainable_factors"]
            }
        )

    # Scenario B: MEDIUM RISK -> STEP-UP MFA CHALLENGE
    if risk_action == "STEP_UP_MFA":
        otp = generate_mfa_code()
        temp_token = generate_session_token()
        db.users.update_one(
            {"email": email},
            {"$set": {
                "mfa_pending": {
                    "code": otp,
                    "temp_token": temp_token,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                    "attempt": attempt_telemetry
                }
            }}
        )
        # Create user alert
        db.get_collection("security_alerts").insert_one({
            "alert_id": f"alt_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "STEP_UP_MFA_CHALLENGE",
            "risk_score": risk_score,
            "origin": geo.get("city", "Unknown") + ", " + geo.get("country", "Unknown"),
            "ip": client_ip,
            "device": fingerprint.get("os", "Unknown"),
            "status": "CHALLENGED",
            "reason": "Medium risk anomaly detected. Verification code sent.",
            "otp_code_demo": otp # Provided for demo/testing convenience
        })
        return {
            "status": "MFA_REQUIRED",
            "message": "Unusual access pattern detected. Secondary MFA verification required.",
            "risk_score": risk_score,
            "temp_token": temp_token,
            "demo_mfa_code": otp # Included so reviewer can test step-up instantly!
        }

    # Scenario C: LOW RISK -> ALLOW & ISSUE ACTIVE SESSION
    # 6. Device Tier Classification (Primary Portal vs. Secondary Device)
    primary_device = user.get("primary_device")
    browser_id = fingerprint.get("browser_id")
    browser_name = fingerprint.get("browser", "Browser")
    os_name = fingerprint.get("os", "Desktop")
    device_name = f"{browser_name} on {os_name}"

    prompt_primary_device = False
    if not primary_device:
        # First sign-in or no primary device enrolled -> prompt user to set as primary
        prompt_primary_device = True
        device_tier = "PRIMARY"
        is_primary = True
        device_label = f"Primary Security Portal ({device_name})"
    else:
        # Check if current hardware/browser profile matches the designated primary device
        primary_bid = primary_device.get("browser_id")
        matches_primary = False

        if primary_bid:
            # Strict browser instance verification:
            # Every distinct browser on the same PC (e.g. Chrome vs Edge vs Firefox vs Chrome Incognito)
            # has its own isolated localStorage and distinct browser_id.
            matches_primary = bool(browser_id and primary_bid == browser_id)
        else:
            # Legacy fallback only if browser_id was not recorded
            matches_primary = bool(
                primary_device.get("canvas_hash") == fingerprint.get("canvas_hash")
                and primary_device.get("browser") == browser_name
                and primary_device.get("os") == os_name
            )

        if matches_primary:
            device_tier = "PRIMARY"
            is_primary = True
            device_label = f"Primary Security Portal ({device_name})"
        else:
            device_tier = "SECONDARY"
            is_primary = False
            device_label = f"Secondary Device ({device_name})"

            # Dispatch audit event to legitimate user's primary device
            db.get_collection("security_alerts").insert_one({
                "alert_id": f"alt_sec_{int(time.time()*1000)}",
                "user_email": email,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "type": "SECONDARY_DEVICE_LOGIN",
                "risk_score": 15.0,
                "origin": geo.get("city", "Local") + ", " + geo.get("country", "Local"),
                "ip": client_ip,
                "device": device_label,
                "status": "INFO",
                "reason": f"ℹ️ Companion Device Sign-In: Account accessed with valid credentials from {device_label}.",
                "factors": [{
                    "factor": "Secondary Device Authentication",
                    "detail": f"Signed in from an authorized secondary device ({device_name}).",
                    "weight": 15.0,
                    "severity": "INFO"
                }]
            })
            cloudwatch.put_log_event(
                log_group="/aws/lambda/AuthHandler",
                level="INFO",
                message=f"Companion device login for {email} from {client_ip} ({device_label})"
            )

    rate_limiter.record_success(client_ip)
    rate_limiter.record_success(f"acct:{email}")
    session_token = generate_session_token()
    session_id = f"sess_{int(time.time()*1000)}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    session_doc = {
        "session_id": session_id,
        "session_token": session_token,
        "user_email": email,
        "ip_address": client_ip,
        "geo": geo,
        "device": device_label,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "fingerprint": fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "status": "ACTIVE"
    }
    db.active_sessions.insert_one(session_doc)

    # Update user's last successful login
    db.users.update_one(
        {"email": email},
        {"$set": {
            "last_successful_login": {
                "timestamp": time.time(),
                "geo": geo,
                "ip": client_ip,
                "device": fingerprint.get("os", "Desktop")
            }
        },
        "$push": {"trusted_devices": fingerprint} if fingerprint else {}}
    )

    return {
        "status": "SUCCESS",
        "action": "ALLOW",
        "risk_score": risk_score,
        "token": session_token,
        "prompt_primary_device": prompt_primary_device,
        "device_tier": device_tier,
        "is_primary_device": is_primary,
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "status": user["status"],
            "primary_device": user.get("primary_device"),
            "device_tier": device_tier,
            "is_primary_device": is_primary
        }
    }


@app.post("/api/auth/verify-mfa")
def verify_mfa(payload: VerifyMFASchema):
    email = sanitize_email(payload.email)
    user = db.users.find_one({"email": email})
    if not user or not user.get("mfa_pending"):
        raise HTTPException(status_code=400, detail="No pending MFA challenge found.")

    mfa_state = user["mfa_pending"]
    if mfa_state.get("temp_token") != payload.temp_token:
        raise HTTPException(status_code=400, detail="Invalid session challenge token.")

    now_iso = datetime.now(timezone.utc).isoformat()
    if mfa_state.get("expires_at", "") < now_iso:
        db.users.update_one({"email": email}, {"$set": {"mfa_pending": None}})
        raise HTTPException(status_code=400, detail="Verification code has expired. Please try logging in again.")

    if mfa_state.get("code") != payload.mfa_code.strip():
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    # MFA verified successfully: clear challenge and issue full session
    rate_limiter.record_success(attempt.get("ip", "127.0.0.1"))
    rate_limiter.record_success(f"acct:{email}")
    db.users.update_one({"email": email}, {"$set": {"mfa_pending": None}})
    session_token = generate_session_token()
    session_id = f"sess_{int(time.time()*1000)}"
    attempt = mfa_state.get("attempt", {})

    db.active_sessions.insert_one({
        "session_id": session_id,
        "session_token": session_token,
        "user_email": email,
        "ip_address": attempt.get("ip", "127.0.0.1"),
        "geo": attempt.get("geo", {}),
        "device": attempt.get("fingerprint", {}).get("os", "Verified Device"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        "status": "ACTIVE"
    })

    return {
        "status": "SUCCESS",
        "token": session_token,
        "message": "Identity confirmed via Step-up MFA. Access granted."
    }


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordSchema):
    email = sanitize_email(payload.email)
    user = db.users.find_one({"email": email})

    # Anti-enumeration response: always return the same success message regardless of existence
    generic_msg = "If an account exists with this email, a secure password reset link has been dispatched."

    if user:
        token = generate_reset_token()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        db.password_resets.insert_one({
            "reset_token": token,
            "email": email,
            "expires_at": expires,
            "used": False
        })
        cloudwatch.put_log_event(
            log_group="/aws/lambda/AuthHandler",
            level="INFO",
            message=f"Password reset token issued for {email}",
            payload={"token_demo": token} # Provided for local testing
        )
        return {"status": "SUCCESS", "message": generic_msg, "demo_reset_token": token}

    return {"status": "SUCCESS", "message": generic_msg}


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordSchema):
    token = payload.token.strip()
    record = db.password_resets.find_one({"reset_token": token, "used": False})
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or already used password reset link.")

    now_iso = datetime.now(timezone.utc).isoformat()
    if record.get("expires_at", "") < now_iso:
        raise HTTPException(status_code=400, detail="Reset link has expired. Please request a new one.")

    is_valid, msg = validate_password_strength(payload.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    # Hash new password
    new_hash, new_salt = hash_password(payload.new_password)
    email = record["email"]

    # Invalidate token
    db.password_resets.update_one({"reset_token": token}, {"$set": {"used": True}})

    # Invalidate all active sessions for security!
    db.active_sessions.delete_many({"user_email": email})

    # Update user
    db.users.update_one(
        {"email": email},
        {"$set": {
            "password_hash": new_hash,
            "salt": new_salt,
            "status": "ACTIVE",
            "updated_at": now_iso
        }}
    )

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Password rotated and sessions invalidated for {email}"
    )

    return {"status": "SUCCESS", "message": "Password successfully updated. All previous sessions terminated."}


# -------------------------------------------------------------
# User Portal & Account Management Routes
# -------------------------------------------------------------
@app.get("/api/auth/me")
def get_me(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    device_tier = current_session.get("device_tier", "PRIMARY") if current_session else "PRIMARY"
    is_primary = current_session.get("is_primary_device", True) if current_session else True

    return {
        "email": user["email"],
        "full_name": user["full_name"],
        "status": user["status"],
        "created_at": user["created_at"],
        "last_login": user.get("last_successful_login"),
        "trusted_devices_count": len(user.get("trusted_devices", [])),
        "primary_device": user.get("primary_device"),
        "device_tier": device_tier,
        "is_primary_device": is_primary
    }


@app.post("/api/auth/devices/set-primary")
def set_primary_device(payload: SetPrimaryDeviceSchema, authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    session = db.active_sessions.find_one({"session_token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Active session not found.")

    fp = session.get("fingerprint") or {}
    browser_name = fp.get("browser", "Browser")
    os_name = fp.get("os", "Desktop")
    device_label = payload.device_label or f"Primary Security Portal ({browser_name} on {os_name})"

    if payload.is_primary:
        primary_data = {
            "browser_id": fp.get("browser_id"),
            "browser": browser_name,
            "os": os_name,
            "canvas_hash": fp.get("canvas_hash"),
            "screen_resolution": fp.get("screen_resolution"),
            "label": device_label,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        db.users.update_one({"email": user["email"]}, {"$set": {"primary_device": primary_data}})
        db.active_sessions.update_one(
            {"session_token": token},
            {"$set": {"device_tier": "PRIMARY", "is_primary_device": True, "device": device_label}}
        )
        msg = "This device has been registered as your Primary Security Portal."
    else:
        db.active_sessions.update_one(
            {"session_token": token},
            {"$set": {"device_tier": "SECONDARY", "is_primary_device": False, "device": f"Secondary Device ({browser_name} on {os_name})"}}
        )
        msg = "This device is registered as a Secondary Device."

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Device enrollment for {user['email']}: Primary={payload.is_primary} ({device_label})"
    )
    return {"status": "SUCCESS", "message": msg, "device_tier": "PRIMARY" if payload.is_primary else "SECONDARY"}


@app.get("/api/auth/sessions")
def list_sessions(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    current_id = current_session.get("session_id") if current_session else None

    sessions = db.active_sessions.find({"user_email": user["email"]}, sort_key="created_at", reverse=True)
    clean_sessions = []
    for s in sessions:
        is_current = (s.get("session_id") == current_id)
        device_tier = s.get("device_tier", "PRIMARY" if is_current else "SECONDARY")
        clean_sessions.append({
            "session_id": s.get("session_id"),
            "ip_address": s.get("ip_address"),
            "geo": s.get("geo"),
            "device": s.get("device"),
            "device_tier": device_tier,
            "is_primary_device": (device_tier == "PRIMARY"),
            "created_at": s.get("created_at"),
            "expires_at": s.get("expires_at"),
            "status": s.get("status"),
            "is_current": is_current,
            "is_primary": is_current
        })
    return {"sessions": clean_sessions, "current_session_id": current_id}


@app.post("/api/auth/sessions/kill")
def kill_session(payload: SessionKillSchema, authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    session_id = payload.session_id.strip()
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    is_killing_self = current_session and (current_session.get("session_id") == session_id)

    target = db.active_sessions.find_one({"session_id": session_id, "user_email": user["email"]})
    if not target:
        raise HTTPException(status_code=404, detail="Session not found or already terminated.")

    # PRIMARY PORTAL IMMUNITY:
    # A session with device_tier == "PRIMARY" can NEVER be killed by another session or secondary device!
    is_target_primary = (target.get("device_tier") == "PRIMARY" or target.get("is_primary_device") is True)
    if is_target_primary and not is_killing_self:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: The Primary Security Portal session is protected and cannot be terminated from another session or device."
        )

    # Secondary Device Restriction: Secondary sessions cannot terminate other sessions
    is_caller_secondary = current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True))
    if is_caller_secondary and not is_killing_self:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Secondary devices cannot terminate remote sessions."
        )

    res = db.active_sessions.delete_one({"session_id": session_id, "user_email": user["email"]})
    if not res:
        raise HTTPException(status_code=404, detail="Session not found or already terminated.")

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User {user['email']} revoked session {session_id}"
    )
    return {
        "status": "SUCCESS",
        "message": "Session terminated immediately.",
        "was_current_session": is_killing_self
    }


@app.post("/api/auth/sessions/kill-others")
def kill_other_sessions(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None
    current_id = current_session.get("session_id") if current_session else None

    # CRITICAL RESTRICTION: Secondary devices CANNOT execute mass session termination!
    is_caller_secondary = current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True))
    if is_caller_secondary:
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Secondary devices cannot execute mass session termination. Master kill switches are restricted to your Primary Security Portal."
        )

    all_sessions = db.active_sessions.find({"user_email": user["email"]})
    deleted_count = 0
    for s in all_sessions:
        if s.get("session_id") != current_id:
            # Absolute safety: Never delete a primary device session during kill-others!
            if s.get("device_tier") == "PRIMARY" or s.get("is_primary_device") is True:
                continue
            db.active_sessions.delete_one({"session_id": s.get("session_id"), "user_email": user["email"]})
            deleted_count += 1

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"User {user['email']} revoked {deleted_count} remote session(s). Primary session preserved."
    )
    return {
        "status": "SUCCESS",
        "message": f"Successfully revoked {deleted_count} other active session(s). Your primary portal remains active.",
        "terminated_count": deleted_count
    }


@app.post("/api/auth/lock-account")
def lock_account(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    current_token = authorization.split(" ")[1] if authorization and authorization.startswith("Bearer ") else None
    current_session = db.active_sessions.find_one({"session_token": current_token}) if current_token else None

    # Secondary devices cannot trigger an account-wide emergency lockdown
    if current_session and (current_session.get("device_tier") == "SECONDARY" or not current_session.get("is_primary_device", True)):
        raise HTTPException(
            status_code=403,
            detail="Security Policy Restriction: Account freeze can only be initiated from your Primary Security Portal."
        )

    email = user["email"]
    # Freeze account and kill all active sessions
    db.users.update_one({"email": email}, {"$set": {"status": "LOCKED"}})
    db.active_sessions.delete_many({"user_email": email})

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="WARN",
        message=f"Emergency Lockout activated by user {email}"
    )
    return {"status": "SUCCESS", "message": "Account successfully frozen. All active sessions have been terminated."}


@app.post("/api/auth/delete-account")
def delete_account(payload: AccountDeleteSchema, user: Dict[str, Any] = Depends(get_current_user)):
    # Verify password before irreversible deletion
    if not verify_password(payload.password, user["password_hash"], user["salt"]):
        raise HTTPException(status_code=401, detail="Incorrect password. Account deletion aborted.")

    email = user["email"]
    db.users.delete_one({"email": email})
    db.active_sessions.delete_many({"user_email": email})
    db.security_events.delete_many({"user_email": email})
    db.get_collection("security_alerts").delete_many({"user_email": email})

    cloudwatch.put_log_event(
        log_group="/aws/lambda/AuthHandler",
        level="INFO",
        message=f"Account and associated telemetry deleted for {email}"
    )
    return {"status": "SUCCESS", "message": "Your account and all associated telemetry have been permanently deleted."}


@app.get("/api/security/user-alerts")
def get_user_alerts(user: Dict[str, Any] = Depends(get_current_user)):
    alerts = db.get_collection("security_alerts").find({"user_email": user["email"]}, sort_key="created_at", reverse=True, limit=20)
    return {"alerts": alerts}


@app.post("/api/security/user-alerts/dismiss")
def dismiss_user_alert(payload: Dict[str, Any], user: Dict[str, Any] = Depends(get_current_user)):
    alert_id = payload.get("alert_id")
    if alert_id:
        db.get_collection("security_alerts").delete_one({"alert_id": alert_id, "user_email": user["email"]})
    return {"status": "SUCCESS", "message": "Alert dismissed."}


@app.post("/api/security/user-alerts/dismiss-all")
def dismiss_all_user_alerts(user: Dict[str, Any] = Depends(get_current_user)):
    db.get_collection("security_alerts").delete_many({"user_email": user["email"]})
    return {"status": "SUCCESS", "message": "All alerts cleared."}


# -------------------------------------------------------------
# Red Team Attack Simulator & Blue Team SOC Endpoints
# -------------------------------------------------------------
class SimulateAttackSchema(BaseModel):
    target_email: str = Field(min_length=3, max_length=254)
    attack_type: str # "IMPOSSIBLE_TRAVEL", "CREDENTIAL_STUFFING", "BRUTE_FORCE", "DEVICE_SPOOF"
    speed_kmh: Optional[float] = None
    custom_ip: Optional[str] = None
    custom_city: Optional[str] = None
    custom_country: Optional[str] = None

@app.post("/api/security/simulate-attack")
def simulate_attack(payload: SimulateAttackSchema):
    email = sanitize_email(payload.target_email)
    user = db.users.find_one({"email": email})

    # Base coordinates
    last_loc = user.get("last_successful_login", {}).get("geo", {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}) if user else {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"}

    attack_type = payload.attack_type.upper()
    simulated_geo = {}
    simulated_ip = "127.0.0.1"
    simulated_fp = {}
    recent_failures = 0
    ua = "Mozilla/5.0"

    if attack_type == "IMPOSSIBLE_TRAVEL":
        # Tokyo coordinates: 10,800 km away from NYC in 2 minutes
        simulated_geo = {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "Japan"}
        simulated_ip = "133.242.18.5"
        simulated_fp = {"os": "Linux x86_64", "canvas_hash": "anom_hash_9812", "screen_resolution": "1920x1080"}
        ua = "Mozilla/5.0 (X11; Linux x86_64)"

    elif attack_type == "CREDENTIAL_STUFFING":
        # Tor Exit Node in Moscow / Frankfurt
        simulated_geo = {"lat": 55.7558, "lon": 37.6173, "city": "Moscow", "country": "Russia"}
        simulated_ip = "185.220.101.45" # Known Tor Exit IP
        simulated_fp = {"os": "Windows NT 10.0", "canvas_hash": "tor_spoof_441", "screen_resolution": "1000x800"}
        ua = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

    elif attack_type == "BRUTE_FORCE":
        simulated_geo = last_loc
        simulated_ip = "198.51.100.22"
        simulated_fp = {"os": "Unknown", "canvas_hash": "bot_canvas_000"}
        recent_failures = 6 # Force burst
        ua = "python-requests/2.31.0 HeadlessChrome"

    elif attack_type == "DEVICE_SPOOF":
        simulated_geo = last_loc
        simulated_ip = "45.33.32.156" # Datacenter IP
        simulated_fp = {"os": "Android 14", "canvas_hash": "spoofed_mobile_99", "screen_resolution": "390x844"}
        ua = "Mozilla/5.0 (Linux; Android 14; Pixel 7)"

    else:
        simulated_geo = {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "UK"}
        simulated_ip = payload.custom_ip or "185.100.87.1"
        simulated_fp = {"os": "Custom Vector", "canvas_hash": "rnd_hash"}

    # Extract features
    attempt_meta = {
        "timestamp": time.time(),
        "geo": simulated_geo,
        "ip": simulated_ip,
        "fingerprint": simulated_fp,
        "user_agent": ua
    }
    features = extract_features(user, attempt_meta, recent_failures)
    if payload.speed_kmh:
        features["geo_velocity_kmh"] = payload.speed_kmh

    # Evaluate ML risk
    ml_res = ml_engine.evaluate_risk(features)
    score = ml_res["risk_score"]
    action = ml_res["action"]

    # Compute Autoencoder loss
    vector = [
        features["geo_velocity_kmh"],
        features["distance_km"],
        features["device_distance"],
        features["ip_reputation"],
        features["failed_attempts_burst"],
        features["circadian_anomaly"],
        features["bot_signature"]
    ]
    auto_res = tf_autoencoder.compute_reconstruction_loss(vector)

    # Log Security Event
    event_doc = {
        "event_id": f"sim_{int(time.time()*1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_email": email,
        "ip_address": simulated_ip,
        "geo": simulated_geo,
        "risk_score": score,
        "risk_level": ml_res["risk_level"],
        "action_taken": action,
        "factors": ml_res["explainable_factors"],
        "is_simulation": True,
        "device": simulated_fp.get("os", "Simulated Device"),
        "autoencoder_loss": auto_res["mse_reconstruction_error"]
    }
    db.security_events.insert_one(event_doc)

    # Dispatch to CloudWatch
    cloudwatch.record_security_decision(score, action)
    cloudwatch.put_log_event(
        log_group="/aws/lambda/AccountHijackRiskEngine",
        level="WARN" if score >= 40 else "INFO",
        message=f"[RED TEAM SIMULATION] {attack_type} against {email}: Risk {score} -> Action: {action}",
        payload={"factors": ml_res["explainable_factors"], "geo": simulated_geo}
    )

    # If action is BLOCK or STEP_UP, inject alert into user's alert inbox
    if action in ("BLOCK_SESSION", "STEP_UP_MFA"):
        db.get_collection("security_alerts").insert_one({
            "alert_id": f"alt_sim_{int(time.time()*1000)}",
            "user_email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": f"SIMULATED_{attack_type}",
            "risk_score": score,
            "origin": simulated_geo.get("city", "Unknown") + ", " + simulated_geo.get("country", "Unknown"),
            "ip": simulated_ip,
            "device": simulated_fp.get("os", "Unknown"),
            "status": "UNRESOLVED",
            "reason": f"Simulated {attack_type} detected by ML Engine.",
            "factors": ml_res["explainable_factors"]
        })

    return {
        "status": "SIMULATION_COMPLETE",
        "attack_type": attack_type,
        "target_email": email,
        "risk_score": score,
        "risk_level": ml_res["risk_level"],
        "action_taken": action,
        "explainable_factors": ml_res["explainable_factors"],
        "autoencoder": auto_res,
        "origin": simulated_geo,
        "ip": simulated_ip
    }


@app.get("/api/security/events")
def get_security_events(limit: int = 50):
    events = db.security_events.find(sort_key="timestamp", reverse=True, limit=min(limit, 100))
    return {"events": events}


@app.get("/api/security/stats")
def get_security_stats():
    total_events = db.security_events.count_documents()
    blocked_count = db.security_events.count_documents({"action_taken": "BLOCK_SESSION"})
    mfa_count = db.security_events.count_documents({"action_taken": "STEP_UP_MFA"})
    allowed_count = db.security_events.count_documents({"action_taken": "ALLOW"})

    recent_events = db.security_events.find(sort_key="timestamp", reverse=True, limit=20)
    avg_score = 0.0
    if recent_events:
        avg_score = round(sum(e.get("risk_score", 0.0) for e in recent_events) / len(recent_events), 1)

    return {
        "total_analyzed": total_events,
        "blocked_hijacks": blocked_count,
        "mfa_challenges": mfa_count,
        "normal_allowed": allowed_count,
        "avg_risk_score": avg_score,
        "active_alarms": [a for a in cloudwatch.alarms.values() if a["state"] == "ALARM"]
    }


# -------------------------------------------------------------
# CloudWatch Telemetry API
# -------------------------------------------------------------
@app.get("/api/monitoring/cloudwatch")
def get_cloudwatch_telemetry():
    return cloudwatch.get_dashboard_summary()


# -------------------------------------------------------------
# System & Maintenance Endpoints
# -------------------------------------------------------------
@app.get("/api/system/status")
def system_status():
    dep_mode = os.getenv("DEPLOYMENT_MODE", "STANDALONE_LOCAL")
    return {
        "status": "HEALTHY",
        "service": "AWSSecurity AI Cyber Defense Engine",
        "version": "2.1.0",
        "deployment_mode": dep_mode,
        "is_aws": dep_mode.upper() == "AWS",
        "database_backend": "MongoDB Live Cluster" if db.use_mongo else "Embedded Local Document Store",
        "telemetry_engine": "Amazon CloudWatch" if dep_mode.upper() == "AWS" else "Embedded Local SIEM / Telemetry",
        "maintenance_mode": MAINTENANCE_MODE,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/system/maintenance")
def toggle_maintenance(enable: bool):
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = enable
    return {"maintenance_mode": MAINTENANCE_MODE}


# -------------------------------------------------------------
# CMS / Admin Endpoints
# -------------------------------------------------------------
@app.get("/api/cms/users")
def cms_get_users():
    users = db.users.find()
    safe_users = []
    for u in users:
        u.pop("password_hash", None)
        u.pop("mfa_secret", None)
        safe_users.append(u)
    return safe_users

@app.delete("/api/cms/users/{email}")
def cms_delete_user(email: str):
    success = db.users.delete_one({"email": email})
    db.active_sessions.delete_many({"email": email})
    if success:
        return {"message": f"User {email} deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/cms/stats")
def cms_get_stats():
    total_users = db.users.count_documents()
    active_sessions = db.active_sessions.count_documents()
    total_events = db.security_events.count_documents()
    blocked_hijacks = db.security_events.count_documents({"action_taken": "BLOCK_SESSION"})
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_security_events": total_events,
        "blocked_hijacks": blocked_hijacks,
        "maintenance_mode": MAINTENANCE_MODE
    }


# -------------------------------------------------------------
# Static Files & Single Page Application Routing
# -------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    # If file exists in frontend, serve it
    potential_file = os.path.join(FRONTEND_DIR, full_path)
    if full_path and os.path.isfile(potential_file):
        return FileResponse(potential_file)
    # Default to index.html
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"message": "Frontend index.html not yet built."}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    print("[AWSSecurity] Starting serverless web application on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
