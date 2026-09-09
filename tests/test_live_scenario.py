"""
Live 2-Browser Attack & Real-Time Alert Verification Test
Simulates Browser 1 (Legitimate User) and Browser 2 (Attacker) interactions.
"""
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi.testclient import TestClient
from backend.app import app
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter

client = TestClient(app)

def run_two_browser_verification():
    print("\n=======================================================")
    print("[TEST] RUNNING 2-BROWSER REAL-TIME ALERT VERIFICATION TEST")
    print("=======================================================")

    email = "demo@awssecurity.io"
    password = "AWSSecurity#2026"

    # Reset account state to ACTIVE and clear limiter
    rate_limiter.clear_all()
    db.users.update_one({"email": email}, {"$set": {"status": "ACTIVE", "mfa_pending": None}})
    db.get_collection("security_alerts").delete_many({"user_email": email})
    db.active_sessions.delete_many({"user_email": email})

    # STEP 1: BROWSER 1 (Legitimate User in Chrome) logs in
    print("\n[Step 1] Browser 1 (Chrome): Legitimate user logs in with valid credentials...")
    login_resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "chrome_uuid_legit_001",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_trusted_demo"
        }
    })
    assert login_resp.status_code == 200, f"Expected 200, got {login_resp.status_code}: {login_resp.text}"
    res_data = login_resp.json()
    print(f"  -> Login status: {res_data.get('status')}, Risk Score: {res_data.get('risk_score')}")
    if res_data.get("status") == "MFA_REQUIRED":
        mfa_resp = client.post("/api/auth/verify-mfa", json={
            "email": email,
            "code": res_data["demo_mfa_code"]
        })
        assert mfa_resp.status_code == 200
        token1 = mfa_resp.json()["token"]
    else:
        token1 = res_data["token"]
    print(f"  -> Browser 1 authenticated successfully! Session token: {token1[:15]}...")

    headers1 = {"Authorization": f"Bearer {token1}"}

    # Browser 1 checks alerts inbox (should be empty initially)
    alerts_resp = client.get("/api/security/user-alerts", headers=headers1)
    assert alerts_resp.status_code == 200
    initial_alerts = alerts_resp.json()["alerts"]
    print(f"  -> Browser 1 initial alert count: {len(initial_alerts)}")

    # STEP 2: BROWSER 2 (Attacker in Edge) attempts wrong password
    print("\n[Step 2] Browser 2 (Edge): Attacker enters WRONG password...")
    attacker_resp1 = client.post("/api/auth/login", json={
        "email": email,
        "password": "WrongPassword123!",
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Edge",
            "browser_id": "edge_uuid_attacker_999",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_diff_edge"
        }
    })
    assert attacker_resp1.status_code == 401, f"Expected 401, got {attacker_resp1.status_code}"
    print("  -> Attacker was rejected with 401 Unauthorized (Anti-enumeration error message).")

    # STEP 3: BROWSER 1 (Legitimate User) polls alerts
    print("\n[Step 3] Browser 1 (Chrome): Polling /api/security/user-alerts...")
    alerts_resp2 = client.get("/api/security/user-alerts", headers=headers1)
    assert alerts_resp2.status_code == 200
    alerts2 = alerts_resp2.json()["alerts"]
    print(f"  -> Browser 1 detected {len(alerts2)} alert(s)!")
    assert len(alerts2) >= 1, "Alert was not recorded in database!"
    latest_alert = alerts2[0]
    print(f"  -> Alert Type: {latest_alert.get('type')}")
    print(f"  -> Reason: {latest_alert.get('reason')}")
    print(f"  -> Device: {latest_alert.get('device')}")
    assert "SUSPICIOUS_FAILED_LOGIN" in latest_alert["type"]

    # STEP 4: BROWSER 2 attempts 2nd wrong password
    print("\n[Step 4] Browser 2 (Edge): Attacker enters 2nd WRONG password...")
    attacker_resp2 = client.post("/api/auth/login", json={
        "email": email,
        "password": "AnotherWrongPass999!",
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Edge",
            "browser_id": "edge_uuid_attacker_999",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_diff_edge"
        }
    })
    assert attacker_resp2.status_code == 401

    # STEP 5: BROWSER 1 polls alerts again
    print("\n[Step 5] Browser 1 (Chrome): Polling /api/security/user-alerts after 2nd failure...")
    alerts_resp3 = client.get("/api/security/user-alerts", headers=headers1)
    assert alerts_resp3.status_code == 200
    alerts3 = alerts_resp3.json()["alerts"]
    print(f"  -> Alert count now: {len(alerts3)}")
    assert len(alerts3) >= 2
    escalated_alert = alerts3[0]
    print(f"  -> Escalated Alert Type: {escalated_alert.get('type')}")
    print(f"  -> Escalated Reason: {escalated_alert.get('reason')}")
    assert "REPEATED_FAILED_LOGINS" in escalated_alert["type"]

    # STEP 6: BROWSER 2 launches Red Team Impossible Travel Scenario
    print("\n[Step 6] Browser 2: Simulating Impossible Travel from Tokyo (8,500 km/h)...")
    sim_resp = client.post("/api/security/simulate-attack", json={
        "target_email": email,
        "attack_type": "IMPOSSIBLE_TRAVEL"
    })
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    print(f"  -> Simulation result: Risk Score {sim_data['risk_score']}/100, Action: {sim_data['action_taken']}")
    assert sim_data["action_taken"] == "BLOCK_SESSION"

    # STEP 7: BROWSER 1 receives the Impossible Travel Alert
    print("\n[Step 7] Browser 1 (Chrome): Polling /api/security/user-alerts for Tokyo vector...")
    alerts_resp4 = client.get("/api/security/user-alerts", headers=headers1)
    alerts4 = alerts_resp4.json()["alerts"]
    print(f"  -> Total alerts in Browser 1 inbox: {len(alerts4)}")
    tokyo_alert = next((a for a in alerts4 if "IMPOSSIBLE_TRAVEL" in a.get("type", "")), None)
    assert tokyo_alert is not None, "Tokyo Impossible Travel alert not found!"
    print(f"  -> Found Tokyo Alert: Type={tokyo_alert['type']}, Origin={tokyo_alert['origin']}, Risk={tokyo_alert['risk_score']}")

    # STEP 7B: PRIMARY PORTAL PRESERVATION (Terminate Other Sessions)
    print("\n[Step 7B] Primary Portal Protection: Terminate all other sessions without logging out Browser 1...")
    # Seed a secondary attacker session
    sess2_token = "mock_attacker_remote_token_777"
    db.active_sessions.insert_one({
        "session_id": "sess_attacker_999",
        "session_token": sess2_token,
        "user_email": email,
        "ip_address": "198.51.100.44",
        "geo": {"city": "Berlin", "country": "DE"},
        "device": "Linux Firefox",
        "created_at": "2026-09-09T10:00:00+00:00",
        "expires_at": "2026-09-10T10:00:00+00:00",
        "status": "ACTIVE"
    })

    # Browser 1 inspects sessions
    sess_resp = client.get("/api/auth/sessions", headers=headers1)
    assert sess_resp.status_code == 200
    sessions_list = sess_resp.json()["sessions"]
    print(f"  -> Active sessions before kill-others: {len(sessions_list)}")
    assert len(sessions_list) >= 2
    primary_sess = next((s for s in sessions_list if s.get("is_current")), None)
    assert primary_sess is not None, "Primary session is_current flag missing!"
    print(f"  -> Identified primary portal session: {primary_sess['session_id']} (is_current={primary_sess['is_current']})")

    # Browser 1 executes kill-others
    kill_others_resp = client.post("/api/auth/sessions/kill-others", headers=headers1)
    assert kill_others_resp.status_code == 200
    print(f"  -> Kill others response: {kill_others_resp.json()['message']}")

    # Verify Browser 1 is STILL LOGGED IN (Primary Portal is NOT logged out!)
    primary_check = client.get("/api/auth/me", headers=headers1)
    assert primary_check.status_code == 200, f"Primary portal was unexpectedly logged out! Got {primary_check.status_code}"
    print("  -> Browser 1 (Primary Portal) is STILL ACTIVE and authenticated! (200 OK)")

    # Verify attacker remote session was terminated
    attacker_check = client.get("/api/auth/me", headers={"Authorization": f"Bearer {sess2_token}"})
    assert attacker_check.status_code == 401, f"Attacker session was not revoked! Got {attacker_check.status_code}"
    print("  -> Attacker remote session was successfully REVOKED! (401 Unauthorized)")

    # STEP 8: BROWSER 1 activates Emergency Kill Switch
    print("\n[Step 8] Browser 1: Clicking 'Freeze Account' kill switch...")
    freeze_resp = client.post("/api/auth/lock-account", headers=headers1)
    assert freeze_resp.status_code == 200
    print(f"  -> Account freeze response: {freeze_resp.json()}")

    # STEP 9: Verify subsequent access from both browsers is 403 Forbidden
    print("\n[Step 9] Verifying both browsers are immediately blocked...")
    check1 = client.get("/api/auth/me", headers=headers1)
    assert check1.status_code in (401, 403), f"Expected 401 or 403, got {check1.status_code}"
    print("  -> Browser 1 request revoked (Session deleted / Account frozen)")

    check2 = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert check2.status_code in (401, 403)
    print("  -> Browser 2 login attempt is rejected")

    # Reset account state back to ACTIVE for developer use
    db.users.update_one({"email": email}, {"$set": {"status": "ACTIVE"}})
    print("\n[SUCCESS] ALL 2-BROWSER REAL-TIME SCENARIOS VERIFIED 100% WORKING!")
    print("=======================================================\n")

if __name__ == "__main__":
    run_two_browser_verification()
