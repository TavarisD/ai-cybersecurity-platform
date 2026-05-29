def profile_attacker_behavior(timeline_data, correlation_data, threat_score):
    total_events = timeline_data.get("total_events", 0)
    unique_attack_types = timeline_data.get("unique_attack_types", 0)
    escalation_level = timeline_data.get("escalation_level", "low")

    campaign_detected = (
        correlation_data
        .get("campaign_analysis", {})
        .get("campaign_detected", False)
    )

    mixed_attack_detected = (
        correlation_data
        .get("mixed_attack_behavior", {})
        .get("mixed_attack_detected", False)
    )

    behavior_type = "opportunistic_probe"
    persistence_level = "low"
    aggression_level = "low"
    confidence = 50
    repeat_offender = False

    if total_events >= 5:
        persistence_level = "medium"
        repeat_offender = True
        confidence += 15

    if total_events >= 10:
        persistence_level = "high"
        confidence += 15

    if threat_score >= 60:
        aggression_level = "medium"
        confidence += 10

    if threat_score >= 85:
        aggression_level = "high"
        confidence += 10

    if campaign_detected:
        behavior_type = "campaign_activity"
        confidence += 10

    if mixed_attack_detected or unique_attack_types >= 2:
        behavior_type = "multi_vector_attack"
        aggression_level = "high"
        confidence += 15

    if total_events >= 5 and unique_attack_types == 1:
        behavior_type = "persistent_single_vector_attack"

    if escalation_level in ["high", "critical"]:
        confidence += 10

    confidence = min(confidence, 100)

    return {
        "behavior_type": behavior_type,
        "persistence_level": persistence_level,
        "aggression_level": aggression_level,
        "repeat_offender": repeat_offender,
        "confidence": confidence
    }