from datetime import datetime


def classify_attack(log_text: str):
    log_lower = log_text.lower()

    if "failed login" in log_lower:
        return "Brute Force Attempt"

    if "sql injection" in log_lower:
        return "SQL Injection Attempt"

    if "xss" in log_lower:
        return "Cross-Site Scripting Attempt"

    if "port scan" in log_lower:
        return "Port Scanning Activity"

    if "malware" in log_lower:
        return "Possible Malware Activity"

    if "ddos" in log_lower:
        return "DDoS Activity"

    return "Unknown Threat Activity"


def determine_incident_severity(threat_score: int):
    if threat_score >= 90:
        return "CRITICAL"

    if threat_score >= 70:
        return "HIGH"

    if threat_score >= 40:
        return "MEDIUM"

    return "LOW"


def generate_ai_incident_summary(
    source: str,
    log_text: str,
    threat_score: int
):
    attack_type = classify_attack(log_text)

    severity = determine_incident_severity(threat_score)

    timestamp = datetime.utcnow().isoformat()

    summary = f"""
AI SOC Incident Summary

Source:
{source}

Attack Classification:
{attack_type}

Severity:
{severity}

Threat Score:
{threat_score}

AI Analysis:
Suspicious activity was detected from source '{source}'.
The observed behavior matches patterns associated with:
{attack_type}.

Recommended Analyst Action:
Review recent logs from this source.
Investigate related authentication activity, IP behavior,
and correlated incident spikes.

Generated:
{timestamp}
"""

    return {
        "attack_type": attack_type,
        "severity": severity,
        "summary": summary,
        "generated_at": timestamp
    }