"""
AWS CloudWatch Monitoring & Telemetry Service.
Emulates Amazon CloudWatch Metrics, Log Groups, and Metric Alarms for serverless security tracking.
"""
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database.db_manager import db

class CloudWatchService:
    def __init__(self):
        self.lock = threading.Lock()
        self.metrics = {
            "Invocations": 0,
            "HighRiskDetections": 0,
            "BlockedHijacks": 0,
            "StepUpMFAChallenges": 0,
            "NormalLogins": 0,
            "TotalExecutionLatencyMs": 0.0,
            "RiskScoreSum": 0.0,
            "RiskEvaluations": 0
        }
        self.metric_timeseries: List[Dict[str, Any]] = []
        self.alarms = {
            "HighRiskRateAlarm": {
                "name": "HighRiskRateAlarm",
                "metric": "HighRiskDetections",
                "threshold": 3,
                "period_minutes": 5,
                "state": "OK", # "OK" or "ALARM"
                "reason": "Threshold not breached.",
                "updated_at": datetime.now(timezone.utc).isoformat()
            },
            "BruteForceBurstAlarm": {
                "name": "BruteForceBurstAlarm",
                "metric": "BlockedHijacks",
                "threshold": 4,
                "period_minutes": 5,
                "state": "OK",
                "reason": "Threshold not breached.",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }

    def record_invocation(self, function_name: str, latency_ms: float, status_code: int = 200):
        with self.lock:
            self.metrics["Invocations"] += 1
            self.metrics["TotalExecutionLatencyMs"] += latency_ms

    def record_security_decision(self, risk_score: float, action: str):
        now = time.time()
        with self.lock:
            self.metrics["RiskEvaluations"] += 1
            self.metrics["RiskScoreSum"] += risk_score

            if action == "BLOCK_SESSION":
                self.metrics["BlockedHijacks"] += 1
                self.metrics["HighRiskDetections"] += 1
            elif action == "STEP_UP_MFA":
                self.metrics["StepUpMFAChallenges"] += 1
            else:
                self.metrics["NormalLogins"] += 1

            # Append time series point
            self.metric_timeseries.append({
                "timestamp": now,
                "risk_score": risk_score,
                "action": action
            })

            # Trim history to last 500 events
            if len(self.metric_timeseries) > 500:
                self.metric_timeseries = self.metric_timeseries[-500:]

            self._evaluate_alarms()

    def _evaluate_alarms(self):
        now = time.time()
        five_mins_ago = now - 300
        recent = [p for p in self.metric_timeseries if p["timestamp"] >= five_mins_ago]

        high_risk_count = sum(1 for p in recent if p["action"] == "BLOCK_SESSION")
        alarm_high = self.alarms["HighRiskRateAlarm"]
        if high_risk_count >= alarm_high["threshold"]:
            alarm_high["state"] = "ALARM"
            alarm_high["reason"] = f"CRITICAL: {high_risk_count} high-risk attacks detected in last 5 minutes (threshold >= {alarm_high['threshold']})."
            alarm_high["updated_at"] = datetime.now(timezone.utc).isoformat()
        else:
            alarm_high["state"] = "OK"
            alarm_high["reason"] = f"Within normal bounds ({high_risk_count}/{alarm_high['threshold']} in 5 min)."

        blocked_count = sum(1 for p in recent if p["action"] == "BLOCK_SESSION")
        alarm_brute = self.alarms["BruteForceBurstAlarm"]
        if blocked_count >= alarm_brute["threshold"]:
            alarm_brute["state"] = "ALARM"
            alarm_brute["reason"] = f"ALARM: {blocked_count} sessions blocked automatically in last 5 minutes."
            alarm_brute["updated_at"] = datetime.now(timezone.utc).isoformat()
        else:
            alarm_brute["state"] = "OK"
            alarm_brute["reason"] = f"Normal operation ({blocked_count}/{alarm_brute['threshold']} blocked in 5 min)."

    def put_log_event(self, log_group: str, level: str, message: str, payload: Optional[Dict[str, Any]] = None):
        """Dispatches structured log entry to the CloudWatch log stream."""
        entry = {
            "log_group": log_group,
            "level": level.upper(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "payload": payload or {}
        }
        db.cloudwatch_logs.insert_one(entry)
        return entry

    def get_dashboard_summary(self) -> Dict[str, Any]:
        with self.lock:
            eval_count = max(1, self.metrics["RiskEvaluations"])
            inv_count = max(1, self.metrics["Invocations"])
            avg_risk = round(self.metrics["RiskScoreSum"] / eval_count, 1) if self.metrics["RiskEvaluations"] > 0 else 0.0
            avg_latency = round(self.metrics["TotalExecutionLatencyMs"] / inv_count, 2)

            # Get recent 30 CloudWatch logs
            recent_logs = db.cloudwatch_logs.find(sort_key="timestamp", reverse=True, limit=30)

            return {
                "metrics": {
                    "Invocations": self.metrics["Invocations"],
                    "HighRiskDetections": self.metrics["HighRiskDetections"],
                    "BlockedHijacks": self.metrics["BlockedHijacks"],
                    "StepUpMFAChallenges": self.metrics["StepUpMFAChallenges"],
                    "NormalLogins": self.metrics["NormalLogins"],
                    "AvgRiskScore": avg_risk,
                    "AvgExecutionLatencyMs": avg_latency
                },
                "alarms": list(self.alarms.values()),
                "recent_logs": recent_logs,
                "timeseries": self.metric_timeseries[-50:]
            }

cloudwatch = CloudWatchService()
