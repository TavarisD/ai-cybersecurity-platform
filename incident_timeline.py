from datetime import datetime

incident_timelines = {}


def update_incident_timeline(ip_address, attack_type):
    history = incident_timelines.get(ip_address, [])

    history.append({
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": attack_type
    })

    incident_timelines[ip_address] = history

    return analyze_timeline(ip_address)


def analyze_timeline(ip_address):
    history = incident_timelines.get(ip_address, [])

    total_events = len(history)

    unique_attacks = len(
        set(item["attack_type"] for item in history)
    )

    escalation_level = "low"

    if total_events >= 5:
        escalation_level = "medium"

    if total_events >= 10:
        escalation_level = "high"

    if total_events >= 20:
        escalation_level = "critical"

    return {
        "total_events": total_events,
        "unique_attack_types": unique_attacks,
        "escalation_level": escalation_level
    }