def generate_executive_summary(
    actor_confidence,
    risk_classification,
    escalation_prediction,
    hunting_recommendations
):
    confidence = actor_confidence.get("actor_confidence", 0)

    threat_level = "LOW"
    recommended_action = "Continue monitoring"

    if confidence >= 60:
        threat_level = "MEDIUM"
        recommended_action = "Review recent activity"

    if confidence >= 80:
        threat_level = "HIGH"
        recommended_action = (
            "Investigate source and review containment options"
        )

    if confidence >= 90:
        threat_level = "CRITICAL"
        recommended_action = (
            "Immediate investigation and containment recommended"
        )

    executive_assessment = (
        actor_confidence.get(
            "analyst_assessment",
            "Limited evidence"
        )
    )

    return {
        "executive_assessment": executive_assessment,
        "threat_level": threat_level,
        "recommended_action": recommended_action,
        "analyst_confidence": confidence
    }
