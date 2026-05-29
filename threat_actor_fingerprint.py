def generate_threat_fingerprint(
    indicator,
    behavior_profile,
    campaign_attribution,
    risk_classification
):
    fingerprint_id = f"fp_{indicator.replace('.', '_')}"

    aggression = behavior_profile.get(
        "aggression_level",
        "low"
    )

    repeat_offender = behavior_profile.get(
        "repeat_offender",
        False
    )

    attack_pattern = campaign_attribution.get(
        "campaign_name",
        "unknown_activity"
    )

    return {
        "fingerprint_id": fingerprint_id,
        "repeat_offender": repeat_offender,
        "attack_pattern": attack_pattern,
        "aggression_level": aggression,
        "risk_classification": risk_classification.get(
            "risk_classification",
            "low_risk"
        )
    }