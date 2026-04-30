import json
import asyncio
from datetime import datetime
from pyexpat import features

from feature_extraction import extract_features
from anomaly_detector import detect_anomaly
from ai_analyzer import analyzer_with_ai
from blacklist_store import add_to_blacklist, is_blacklisted, get_blacklist
from metrics_store import log_event
from alert_system import create_alert

attacker_stats = {}

def save_event(entry):
    record = entry.copy()
    record["timestamp"] = datetime.utcnow().isoformat()

    with open("events.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def update_attacker_stats(features):
    ip = features.get("ip")

    if not ip:
        return None

    if ip not in attacker_stats:
        attacker_stats[ip] = {
            "total_events": 0,
            "failed_login_count": 0,
            "sql_injection_count": 0
        }

    attacker_stats[ip]["total_events"] += 1

    if features.get("failed_login"):
        attacker_stats[ip]["failed_login_count"] += 1

    if features.get("sql_injection"):
        attacker_stats[ip]["sql_injection_count"] += 1

    return attacker_stats[ip]

def process_live_log(log_line, live_logs, max_logs, main_loop, broadcast_callback):
    features = extract_features(log_line)
    from feature_extraction import detect_attack_type
    attack_type = detect_attack_type(features)
    anomaly = detect_anomaly(features)
    ai_result = analyzer_with_ai(log_line)
    attacker_info = update_attacker_stats(features)

    reasons = []

    if features.get("failed_login"):
        reasons.append("Repeated failed login attempts detected")

    if features.get("sql_injection"):
        reasons.append("SQL injection behavior detected")

    if anomaly == "anomaly":
        reasons.append("Unusual or anomalous activity detected")

    attacker_info = attacker_info or {}

    if attacker_info.get("total_events", 0) >= 3:
        reasons.append("This IP has a history of repeated activity")

    if attacker_info.get("failed_login_count", 0) >= 3:
        reasons.append("Multiple failed login attempts from this IP")

    if attacker_info.get("sql_injection_count", 0) >= 1:
        reasons.append("Previous SQL injection attempts from this IP")

# Correlation explanations
    if features.get("failed_login") and anomaly == "anomaly":
        reasons.append("Failed logins combined with anomalous behavior indicate a coordinated attack")

    if features.get("sql_injection") and anomaly == "anomaly":
        reasons.append("SQL injection combined with anomalous activity increases threat level")

    if features.get("failed_login") and features.get("sql_injection"):
        reasons.append("Multiple attack types detected from the same source")

    threat_score = 0
    ip = features.get("ip")

    history = get_blacklist()
    history_count = history.get(ip, 0) if ip else 0

    if features.get("failed_login"):
        threat_score += 35

    if features.get("sql_injection"):
        threat_score += 70

    if anomaly == "anomaly":
        threat_score += 20

    if features.get("failed_login") and anomaly == "anomaly":
        threat_score += 10

    if features.get("sql_injection") and anomaly == "anomaly":
        threat_score += 15

    if features.get("failed_login") and features.get("sql_injection"):
        threat_score += 20

    threat_score += history_count * 5
    threat_score = min(threat_score, 100)

    log_event(threat_score)

    if threat_score >= 85:
        create_alert(f"{attack_type.replace('_', ' ').title()} from {ip}", "high")
    elif threat_score >= 60:
        create_alert(f"{attack_type.replace('_', ' ').title()} from {ip}", "medium")

    if threat_score >= 80:
        severity = "HIGH"
    elif threat_score >= 45:
        severity = "MEDIUM"
    else:
        severity = "LOW"

        priority = "low"

    priority = "low"

    if features.get("sql_injection") and anomaly == "anomaly":
        priority = "critical"
    elif threat_score >= 85:
        priority = "high"
    elif threat_score >= 50:
        priority = "medium"

    if ip and severity == "HIGH":
        add_to_blacklist(ip)

    entry = {
    "log": log_line,
    "features": features,
    "anomaly": anomaly,
    "threat_score": threat_score,
    "severity": severity,
    "priority": priority,
    "ai_analysis": ai_result + " | " + " | ".join(reasons) if reasons else ai_result,
    "ip": ip,
    "attacker_history": attacker_info,
    "is_blacklisted": is_blacklisted(ip) if ip else False,
    "timestamp": datetime.utcnow().isoformat(),
    "attack_type": attack_type,
}

    live_logs.append(entry)
    save_event(entry)

    if len(live_logs) > max_logs:
        live_logs.pop(0)

    if main_loop is not None:
        asyncio.run_coroutine_threadsafe(
            broadcast_callback(entry),
            main_loop
        )

    return entry