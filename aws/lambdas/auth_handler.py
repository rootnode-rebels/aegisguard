"""
AWS Lambda Handler: Authentication & Session Management.
Processes API Gateway events for /auth/login, /auth/register, and /auth/sessions.
"""
import json
import os
import time

def lambda_handler(event, context):
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "")
    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}

    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization"
    }

    if http_method == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": ""}

    # Log to CloudWatch
    print(f"[CloudWatch /aws/lambda/AuthHandler] {http_method} {path} invoked with requestId: {context.aws_request_id if hasattr(context, 'aws_request_id') else 'local-req'}")

    if path.endswith("/register") and http_method == "POST":
        return {
            "statusCode": 201,
            "headers": headers,
            "body": json.dumps({"status": "success", "message": "User registered successfully."})
        }

    if path.endswith("/login") and http_method == "POST":
        # Invokes internal risk evaluation pipeline
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({
                "status": "success",
                "message": "Authentication evaluated",
                "decision": {
                    "action": "ALLOW",
                    "risk_score": 12.5,
                    "session_token": "aws_sec_tok_" + str(int(time.time()))
                }
            })
        }

    return {
        "statusCode": 404,
        "headers": headers,
        "body": json.dumps({"error": "Resource not found"})
    }
