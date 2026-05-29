def generate_threat_narrative(
    risk_classification,
    campaign_attribution,
    escalation_prediction,
    threat_reputation
):
    narrative = (
        f"Threat actor classified as "
        f"{risk_classification.get('risk_classification', 'Unknown')} "
        f"with reputation level "
        f"{threat_reputation.get('reputation_level', 'low')}. "
        f"Campaign attribution indicates "
        f"{campaign_attribution.get('campaign_name', 'Unknown Activity')}. "
        f"Escalation prediction is "
        f"{escalation_prediction.get('predicted_stage', 'stable')}."
    )

    return {
        "narrative": narrative,
        "generated": True
    }