def attribute_campaign(
    indicator,
    attack_type,
    correlation_data,
    timeline_result
):
    total_incidents = correlation_data.get(
        "total_incidents",
        0
    )

    unique_attacks = timeline_result.get(
        "unique_attack_types",
        0
    )

    campaign_name = "Unknown Activity"
    campaign_confidence = 0
    campaign_detected = False

    if total_incidents >= 5:
        campaign_detected = True
        campaign_name = "Persistent Recon Campaign"
        campaign_confidence = 70

    if unique_attacks >= 3:
        campaign_detected = True
        campaign_name = "Multi-Vector Attack Campaign"
        campaign_confidence = 85

    if (
        total_incidents >= 10
        and unique_attacks >= 3
    ):
        campaign_detected = True
        campaign_name = "Advanced Coordinated Campaign"
        campaign_confidence = 95

    return {
        "campaign_detected": campaign_detected,
        "campaign_name": campaign_name,
        "campaign_confidence": campaign_confidence,
        "indicator": indicator,
        "latest_attack_type": attack_type
    }