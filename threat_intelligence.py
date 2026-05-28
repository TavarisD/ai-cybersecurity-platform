from datetime import datetime


def classify_threat_actor(threat_score: int, attack_type: str):
    if threat_score >= 85:
        sophistication = "advanced"
    elif threat_score >= 60:
        sophistication = "intermediate"
    else:
        sophistication = "basic"

    if attack_type == "sql_injection" and threat_score >= 70:
        sophistication = "advanced"

    return sophistication


def determine_incident_urgency(threat_score: int):
    if threat_score >= 85:
        return "immediate"

    if threat_score >= 60:
        return "high"

    if threat_score >= 35:
        return "medium"

    return "low"


def recommended_response_actions(
    attack_type: str,
    threat_score: int
):
    actions = []

    if attack_type == "sql_injection":
        actions.append("Block malicious IP")
        actions.append("Inspect database activity")
        actions.append("Review WAF protections")

    if attack_type == "failed_login":
        actions.append("Monitor authentication system")
        actions.append("Enable account lockout protections")

    if threat_score >= 70:
        actions.append("Escalate to SOC analyst")

    if threat_score >= 85:
        actions.append("Initiate incident response procedure")

    return actions


def build_threat_intelligence(
    source: str,
    attack_type: str,
    threat_score: int
):
    sophistication = classify_threat_actor(
        threat_score,
        attack_type
    )

    urgency = determine_incident_urgency(threat_score)

    actions = recommended_response_actions(
        attack_type,
        threat_score
    )

    return {
        "source": source,
        "threat_actor_sophistication": sophistication,
        "incident_urgency": urgency,
        "recommended_actions": actions,
        "generated_at": datetime.utcnow().isoformat()
    }