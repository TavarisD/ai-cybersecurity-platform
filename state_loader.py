import json
import os
from alert_system import alerts, trim_alerts
from metrics_store import metrics, trim_metrics
from live_processing import attacker_stats
from alert_system import alerts


EVENTS_FILE = "events.jsonl"


def restore_state(live_logs, max_logs=100):
    live_logs.clear()
    metrics["events"].clear()
    metrics["threat_scores"].clear()
    attacker_stats.clear()
    alerts.clear()

    if not os.path.exists(EVENTS_FILE):
        return

    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            live_logs.append(entry)

            timestamp = entry.get("timestamp")
            threat_score = entry.get("threat_score", 0)

            if timestamp:
                try:
                    display_time = timestamp.split("T")[-1][:8]
                except Exception:
                    display_time = str(timestamp)[:8]
                metrics["events"].append(display_time)
            else:
                metrics["events"].append("unknown")

            metrics["threat_scores"].append(threat_score)

            ip = entry.get("ip")
            history = entry.get("attacker_history")

            if ip and isinstance(history, dict):
                attacker_stats[ip] = {
                    "total_events": history.get("total_events", 0),
                    "failed_login_count": history.get("failed_login_count", 0),
                    "sql_injection_count": history.get("sql_injection_count", 0),
                }

            severity = entry.get("severity", "").upper()
            if severity == "HIGH":
                alerts.append({
                    "message": f"[Restored] High threat from {ip or 'unknown'}",
                    "severity": "high"
                })
            elif severity == "MEDIUM":
                alerts.append({
                    "message": f"[Restored] Suspicious activity from {ip or 'unknown'}",
                    "severity": "medium"
                })

    if len(live_logs) > max_logs:
        del live_logs[:-max_logs]

    trim_metrics()
    trim_alerts()