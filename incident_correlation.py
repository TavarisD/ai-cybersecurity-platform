from collections import defaultdict
from datetime import datetime


attack_history = defaultdict(list)


def record_incident(
    ip: str,
    attack_type: str,
    severity: str
):
    incident = {
        "attack_type": attack_type,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat()
    }

    attack_history[ip].append(incident)

    return incident


def get_incident_history(ip: str):
    return attack_history.get(ip, [])


def detect_attack_campaign(ip: str):
    history = get_incident_history(ip)

    if len(history) >= 10:
        return {
            "campaign_detected": True,
            "campaign_type": "Sustained Attack Campaign",
            "incident_count": len(history)
        }

    return {
        "campaign_detected": False,
        "campaign_type": None,
        "incident_count": len(history)
    }


def detect_mixed_attack_behavior(ip: str):
    history = get_incident_history(ip)

    attack_types = set()

    for incident in history:
        attack_types.add(incident["attack_type"])

    if len(attack_types) >= 3:
        return {
            "mixed_attack_detected": True,
            "attack_types": list(attack_types)
        }

    return {
        "mixed_attack_detected": False,
        "attack_types": list(attack_types)
    }


def generate_correlation_summary(ip: str):
    history = get_incident_history(ip)

    campaign = detect_attack_campaign(ip)

    mixed_behavior = detect_mixed_attack_behavior(ip)

    return {
        "ip": ip,
        "total_incidents": len(history),
        "campaign_analysis": campaign,
        "mixed_attack_behavior": mixed_behavior,
        "recent_activity": history[-5:]
    }
