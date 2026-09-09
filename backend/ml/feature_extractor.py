"""
Behavioral Feature Extractor for Account Hijacking Risk Assessment.
Calculates geo-velocity, device trust distance, IP reputation, and behavioral anomalies.
"""
import math
import time
from typing import Dict, Any, Tuple, Optional

# Known high-risk IP indicators (Tor nodes, public VPN/Proxy subnets, Datacenter ranges)
KNOWN_TOR_IPS = {"185.220.101.", "198.98.56.", "162.247.74.", "51.15.43.", "185.100.87."}
KNOWN_VPN_DATACENTER_IPS = {"45.33.", "104.244.", "198.51.100.", "203.0.113.", "192.88.99.", "133.242."}

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two geographic coordinates using the Haversine formula."""
    R = 6371.0 # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2.0) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return R * c

def calculate_geo_velocity(current_geo: Dict[str, float], last_geo: Optional[Dict[str, float]], 
                           current_ts: float, last_ts: Optional[float]) -> Tuple[float, float]:
    """
    Calculates distance (km) and speed (km/h) between consecutive logins.
    Returns (distance_km, speed_kmh).
    """
    if not last_geo or not last_ts:
        return 0.0, 0.0

    lat1, lon1 = last_geo.get("lat", 0.0), last_geo.get("lon", 0.0)
    lat2, lon2 = current_geo.get("lat", 0.0), current_geo.get("lon", 0.0)

    distance = haversine_distance_km(lat1, lon1, lat2, lon2)
    time_delta_hours = max((current_ts - last_ts) / 3600.0, 0.00027) # min 1 second

    velocity = distance / time_delta_hours
    return round(distance, 2), round(velocity, 2)

def calculate_device_distance(current_fingerprint: Dict[str, Any], trusted_devices: list) -> float:
    """
    Calculates behavioral device distance (0.0 = identical trusted device, 1.0 = completely unknown device).
    """
    if not trusted_devices:
        return 0.5 # First device, neutral baseline

    best_match_score = 0.0
    curr_canvas = current_fingerprint.get("canvas_hash", "")
    curr_os = current_fingerprint.get("os", "")
    curr_browser = current_fingerprint.get("browser", "")
    curr_browser_id = current_fingerprint.get("browser_id", "")
    curr_screen = current_fingerprint.get("screen_resolution", "")
    curr_platform = current_fingerprint.get("platform", "")

    for dev in trusted_devices:
        matches = 0
        total = 0

        # Canvas hash (Hardware GPU rendering profile)
        if curr_canvas and dev.get("canvas_hash"):
            total += 2
            if curr_canvas == dev.get("canvas_hash"):
                matches += 2

        # OS matching
        if curr_os and dev.get("os"):
            total += 1
            if curr_os == dev.get("os"):
                matches += 1

        # Screen resolution
        if curr_screen and dev.get("screen_resolution"):
            total += 1
            if curr_screen == dev.get("screen_resolution"):
                matches += 1

        # Platform
        if curr_platform and dev.get("platform"):
            total += 1
            if curr_platform == dev.get("platform"):
                matches += 1

        # Browser affinity
        if curr_browser_id and dev.get("browser_id"):
            total += 2
            if curr_browser_id == dev.get("browser_id"):
                matches += 2
        elif curr_browser and dev.get("browser"):
            total += 1
            if curr_browser == dev.get("browser"):
                matches += 1

        if total > 0:
            score = matches / total
            if score > best_match_score:
                best_match_score = score

    return round(1.0 - best_match_score, 2)

def evaluate_ip_reputation(ip: str) -> float:
    """
    Returns risk score from 0.0 (clean residential) to 1.0 (confirmed Tor/malicious proxy).
    """
    if not ip or ip in ("127.0.0.1", "localhost", "::1"):
        return 0.0
    for prefix in KNOWN_TOR_IPS:
        if ip.startswith(prefix):
            return 1.0 # Confirmed Tor Exit Node
    for prefix in KNOWN_VPN_DATACENTER_IPS:
        if ip.startswith(prefix):
            return 0.75 # Data center / Commercial VPN
    return 0.05 # Standard residential / mobile ASN

def evaluate_user_agent_bot_score(user_agent: str) -> float:
    """Detects headless browsers and automated script crawlers."""
    ua = (user_agent or "").lower()
    if not ua:
        return 0.8
    bot_signatures = ["headlesschrome", "puppeteer", "selenium", "phantomjs", "curl/", "python-requests", "postman"]
    for sig in bot_signatures:
        if sig in ua:
            return 1.0
    return 0.0

def extract_features(
    user_data: Optional[Dict[str, Any]],
    current_attempt: Dict[str, Any],
    recent_failure_count: int
) -> Dict[str, Any]:
    """
    Extracts the full 6-dimensional feature vector for Machine Learning inference.
    """
    current_ts = current_attempt.get("timestamp", time.time())
    current_geo = current_attempt.get("geo", {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "US"})
    current_fp = current_attempt.get("fingerprint", {})
    current_ip = current_attempt.get("ip", "127.0.0.1")
    current_ua = current_attempt.get("user_agent", "")

    # Retrieve last known location & timestamp
    last_login = None
    trusted_devices = []
    if user_data:
        trusted_devices = user_data.get("trusted_devices", [])
        last_login = user_data.get("last_successful_login")

    last_geo = last_login.get("geo") if last_login else None
    last_ts = last_login.get("timestamp") if last_login else None

    distance_km, geo_velocity = calculate_geo_velocity(current_geo, last_geo, current_ts, last_ts)
    device_distance = calculate_device_distance(current_fp, trusted_devices)
    ip_rep_score = evaluate_ip_reputation(current_ip)
    bot_score = evaluate_user_agent_bot_score(current_ua)

    # Circadian anomaly: deviation from 09:00 - 23:00 local time
    hour = time.gmtime(current_ts).tm_hour
    circadian_risk = 0.6 if (hour < 5 or hour > 23) else 0.1

    return {
        "geo_velocity_kmh": geo_velocity,
        "distance_km": distance_km,
        "device_distance": device_distance,
        "ip_reputation": ip_rep_score,
        "failed_attempts_burst": recent_failure_count,
        "circadian_anomaly": circadian_risk,
        "bot_signature": bot_score,
        "is_known_device": 1 if device_distance == 0.0 else 0
    }
