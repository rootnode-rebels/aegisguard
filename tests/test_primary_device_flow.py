"""
Primary vs Secondary Device Flow & Portal Preservation Verification Test
Tests:
1. First login prompt for primary device designation.
2. Designation of primary device.
3. Secondary device login with same credentials (tagged as SECONDARY, alert generated).
4. Secondary device restricted from killing primary session (403 Forbidden).
5. Primary portal terminates secondary session while remaining logged in.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi.testclient import TestClient
from backend.app import app
from database.db_manager import db
from backend.security.rate_limiter import rate_limiter

client = TestClient(app)

def test_primary_device_full_flow():
    print("\n=======================================================")
    print("[TEST] PRIMARY VS SECONDARY DEVICE WORKFLOW VERIFICATION")
    print("=======================================================")

    test_email = "test_device_tier@awssecurity.io"
    test_password = "SecurePassword#2026"

    # 1. Clean up & register fresh user
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})
    rate_limiter.clear_all()

    reg_resp = client.post("/api/auth/register", json={
        "email": test_email,
        "full_name": "Device Tester",
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_primary_001",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary"
        }
    })
    assert reg_resp.status_code == 201, f"Registration failed: {reg_resp.text}"
    print("[Step 1] User registered successfully.")

    # 2. First login from Browser 1 (Chrome)
    login1_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_primary_001",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary"
        }
    })
    assert login1_resp.status_code == 200, f"Login 1 failed: {login1_resp.text}"
    data1 = login1_resp.json()
    token1 = data1["token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    print(f"[Step 2] Browser 1 login -> prompt_primary_device: {data1.get('prompt_primary_device')}")
    assert data1.get("prompt_primary_device") is True, "First login should prompt for primary device!"

    # 3. Designate Browser 1 as Primary Device
    set_prim_resp = client.post("/api/auth/devices/set-primary", headers=headers1, json={
        "is_primary": True,
        "device_label": "Primary Security Portal (Chrome on Windows)"
    })
    assert set_prim_resp.status_code == 200, f"Set primary failed: {set_prim_resp.text}"
    print(f"[Step 3] Designated Browser 1 as primary device: {set_prim_resp.json()['message']}")

    # Verify user profile reflects primary device
    me1 = client.get("/api/auth/me", headers=headers1).json()
    assert me1.get("primary_device") is not None
    assert me1.get("device_tier") == "PRIMARY"
    assert me1.get("is_primary_device") is True
    print(f"  -> Profile verified: device_tier={me1['device_tier']}, is_primary_device={me1['is_primary_device']}")

    # 4. Same machine, same browser (Chrome Incognito / diff profile with identical canvas_hash) -> Must be Secondary Device!
    print("\n[Step 4] Logging into Browser 2 (Same PC, Chrome Incognito with same canvas_hash)...")
    login2_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password,
        "geo": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"},
        "fingerprint": {
            "browser": "Chrome",
            "browser_id": "browser_chrome_incognito_002",
            "os": "Windows NT 10.0",
            "screen_resolution": "1920x1080",
            "canvas_hash": "canvas_hash_chrome_primary" # Identical canvas on same physical PC!
        }
    })
    assert login2_resp.status_code == 200, f"Login 2 failed: {login2_resp.text}"
    data2 = login2_resp.json()
    token2 = data2["token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    print(f"  -> Browser 2 prompt_primary_device: {data2.get('prompt_primary_device')}")
    print(f"  -> Browser 2 device_tier: {data2.get('device_tier')}")
    print(f"  -> Browser 2 is_primary_device: {data2.get('is_primary_device')}")
    assert data2.get("prompt_primary_device") is False, "Browser 2 should not prompt for primary device"
    assert data2.get("device_tier") == "SECONDARY", "Browser 2 should be tagged as SECONDARY device"
    assert data2.get("is_primary_device") is False

    # 5. Check that Browser 1 received an instant alert about the secondary device login
    alerts_b1 = client.get("/api/security/user-alerts", headers=headers1).json()["alerts"]
    print(f"[Step 5] Browser 1 alerts received: {len(alerts_b1)}")
    assert len(alerts_b1) >= 1, "Alert for secondary device login was not created!"
    sec_alert = next((a for a in alerts_b1 if a.get("type") == "SECONDARY_DEVICE_LOGIN"), None)
    assert sec_alert is not None, "SECONDARY_DEVICE_LOGIN alert missing!"
    print(f"  -> Alert found: {sec_alert['reason']}")

    # 6. Secondary Device (Browser 2) attempts to terminate Primary Session -> Must be 403 Forbidden!
    sessions_b2 = client.get("/api/auth/sessions", headers=headers2).json()["sessions"]
    print(f"\n[Step 6] Browser 2 views active sessions: {len(sessions_b2)} total")
    primary_sess = next((s for s in sessions_b2 if s.get("device_tier") == "PRIMARY"), None)
    assert primary_sess is not None, "Primary session not visible in sessions list"

    print(f"  -> Browser 2 attempting to kill Primary Session ({primary_sess['session_id']})...")
    kill_attempt = client.post("/api/auth/sessions/kill", headers=headers2, json={
        "session_id": primary_sess["session_id"]
    })
    print(f"  -> Response Status Code: {kill_attempt.status_code}")
    assert kill_attempt.status_code == 403, f"Expected 403 Forbidden, got {kill_attempt.status_code}: {kill_attempt.text}"
    print(f"  -> Correctly blocked by policy: {kill_attempt.json().get('detail')}")

    # 7. Primary Device (Browser 1) terminates other sessions
    print("\n[Step 7] Browser 1 terminates other sessions...")
    kill_others = client.post("/api/auth/sessions/kill-others", headers=headers1)
    assert kill_others.status_code == 200
    print(f"  -> Terminate others result: {kill_others.json()['message']}")

    # 8. Verify Primary Portal is STILL LOGGED IN (Preserved!)
    check_b1 = client.get("/api/auth/me", headers=headers1)
    assert check_b1.status_code == 200, f"Primary portal was unexpectedly logged out! Got {check_b1.status_code}"
    print("  -> Browser 1 (Primary Portal) is STILL ACTIVE (HTTP 200 OK)!")

    # 9. Verify Secondary Device is REVOKED
    check_b2 = client.get("/api/auth/me", headers=headers2)
    assert check_b2.status_code == 401, f"Secondary session was not revoked! Got {check_b2.status_code}"
    print("  -> Browser 2 (Secondary Device) was successfully revoked (HTTP 401 Unauthorized)!")

    # Clean up test user
    db.users.delete_one({"email": test_email})
    db.active_sessions.delete_many({"user_email": test_email})
    db.get_collection("security_alerts").delete_many({"user_email": test_email})

    print("\n[SUCCESS] PRIMARY VS SECONDARY DEVICE WORKFLOW VERIFIED 100% WORKING!")
    print("=======================================================\n")

if __name__ == "__main__":
    test_primary_device_full_flow()
