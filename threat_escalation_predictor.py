def predict_escalation(
    behavior_profile,
    risk_classification,
    campaign_attribution
):
    escalation_likely = False
    escalation_stage = "stable"
    confidence = 0

    if risk_classification.get("risk_score", 0) >= 70:
        escalation_likely = True
        escalation_stage = "credential_attack"
        confidence = 70

    if campaign_attribution.get("campaign_detected"):
        escalation_likely = True
        escalation_stage = "exploitation_attempt"
        confidence = max(confidence, 85)

    if (
        behavior_profile.get("persistence_level") == "high"
        and behavior_profile.get("aggression_level") == "high"
    ):
        escalation_likely = True
        escalation_stage = "active_compromise"
        confidence = 95

    return {
        "escalation_likely": escalation_likely,
        "predicted_stage": escalation_stage,
        "prediction_confidence": confidence
    }
