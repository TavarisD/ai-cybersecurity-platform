def calculate_actor_confidence(
    behavior_profile,
    risk_classification,
    campaign_attribution,
    escalation_prediction
):
    confidence = 0

    confidence += behavior_profile.get("confidence", 0) * 0.30

    confidence += (
        risk_classification.get("risk_score", 0) * 0.30
    )

    confidence += (
        campaign_attribution.get(
            "campaign_confidence",
            0
        ) * 0.20
    )

    confidence += (
        escalation_prediction.get(
            "prediction_confidence",
            0
        ) * 0.20
    )

    confidence = round(min(confidence, 100))

    confidence_level = "Low"
    analyst_assessment = "Limited evidence"

    if confidence >= 60:
        confidence_level = "Moderate"
        analyst_assessment = "Suspicious activity likely"

    if confidence >= 80:
        confidence_level = "High"
        analyst_assessment = "Likely malicious actor"

    if confidence >= 90:
        confidence_level = "Very High"
        analyst_assessment = (
            "Likely coordinated malicious actor"
        )

    return {
        "actor_confidence": confidence,
        "confidence_level": confidence_level,
        "analyst_assessment": analyst_assessment
    }
