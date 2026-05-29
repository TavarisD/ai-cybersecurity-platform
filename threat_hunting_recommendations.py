def generate_hunting_recommendations(
    behavior_profile,
    campaign_attribution,
    escalation_prediction
):
    recommendation = "Continue monitoring"
    priority = "low"
    confidence = 50

    if escalation_prediction.get("escalation_likely"):
        recommendation = (
            "Search for additional activity from this indicator "
            "across authentication, firewall, and application logs"
        )
        priority = "high"
        confidence = 85

    if campaign_attribution.get("campaign_detected"):
        recommendation = (
            "Investigate related indicators and identify campaign spread"
        )
        priority = "critical"
        confidence = 90

    if (
        behavior_profile.get("repeat_offender")
        and behavior_profile.get("aggression_level") == "high"
    ):
        recommendation = (
            "Perform immediate threat hunt and containment review"
        )
        priority = "critical"
        confidence = 95

    return {
        "hunt_recommendation": recommendation,
        "priority": priority,
        "confidence": confidence
    }