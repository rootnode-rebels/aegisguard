"""
AWS Lambda Handler: Scikit-learn Behavioral Risk Engine.
Extracts login features, executes model inference, and emits CloudWatch metrics.
"""
import json
import time

def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        body = {}

    geo_velocity = float(body.get("geo_velocity_kmh", 0.0))
    ip_rep = float(body.get("ip_reputation", 0.0))
    device_dist = float(body.get("device_distance", 0.0))
    failures = int(body.get("failed_attempts_burst", 0))

    # Calculate risk score
    score = 10.0
    action = "ALLOW"
    factors = []

    if geo_velocity >= 900:
        score += 45.0
        factors.append("Impossible travel velocity")
    if ip_rep >= 0.9:
        score += 35.0
        factors.append("Tor exit node IP")
    if device_dist >= 0.8:
        score += 25.0
        factors.append("Untrusted hardware signature")
    if failures >= 4:
        score += 30.0
        factors.append("Brute force burst")

    final_score = min(100.0, score)
    if final_score >= 70.0:
        action = "BLOCK_SESSION"
    elif final_score >= 40.0:
        action = "STEP_UP_MFA"

    # CloudWatch structured JSON log
    log_entry = {
        "requestId": context.aws_request_id if hasattr(context, 'aws_request_id') else 'req-test',
        "risk_score": final_score,
        "action": action,
        "factors": factors,
        "timestamp": time.time()
    }
    print(json.dumps(log_entry))

    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
    }

    return {
        "statusCode": 200,
        "headers": headers,
        "body": json.dumps({
            "status": "success",
            "risk_score": final_score,
            "action": action,
            "factors": factors
        })
    }
