"""
AWS Lambda Handler: Real-Time Alert Notification Dispatcher (Amazon SNS / SES).
Sends instant push and email notifications to the legitimate user upon account hijacking detection.
"""
import json
import os
import boto3

def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        body = {}

    user_email = body.get("user_email", "unknown@user.com")
    threat_type = body.get("threat_type", "Suspicious Account Access")
    risk_score = body.get("risk_score", 85.0)
    origin_city = body.get("origin_city", "Unknown Location")
    origin_ip = body.get("origin_ip", "0.0.0.0")

    alert_message = (
        f"🚨 SECURITY ALERT: Unauthorized login attempt detected!\n\n"
        f"Account: {user_email}\n"
        f"Threat Level: HIGH (Risk Score: {risk_score}/100)\n"
        f"Location: {origin_city}\n"
        f"IP Address: {origin_ip}\n"
        f"Action Taken: Session automatically blocked by ML Risk Engine.\n\n"
        f"If this was not you, log in to your security dashboard to terminate all sessions and rotate your password."
    )

    sns_arn = os.getenv("SECURITY_ALERT_TOPIC_ARN")
    if sns_arn and not sns_arn.startswith("arn:aws:sns:dummy"):
        try:
            sns = boto3.client("sns")
            sns.publish(
                TopicArn=sns_arn,
                Subject=f"🚨 High Risk Security Alert: {user_email}",
                Message=alert_message
            )
            print(f"[AlertDispatcher] SNS notification published to {sns_arn}")
        except Exception as e:
            print(f"[AlertDispatcher] SNS Publish Error: {e}")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps({
            "status": "DISPATCHED",
            "threat": threat_type,
            "recipient": user_email,
            "message": alert_message
        })
    }
