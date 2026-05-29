def classify_threat_actor(behavior_profile, threat_score):
    behavior_type = behavior_profile.get("behavior_type", "")
    confidence = behavior_profile.get("confidence", 0)
    aggression = behavior_profile.get("aggression_level", "low")
    persistence = behavior_profile.get("persistence_level", "low")

    risk_classification = "Low Risk"
    analyst_priority = "Low"
    risk_score = threat_score

    if threat_score >= 60:
        risk_classification = "Elevated Threat"
        analyst_priority = "Medium"

    if threat_score >= 80:
        risk_classification = "High Risk Actor"
        analyst_priority = "High"

    if (
        aggression == "high"
        and persistence == "high"
        and confidence >= 80
    ):
        risk_classification = "Advanced Persistent Threat"
        analyst_priority = "Critical"
        risk_score = max(risk_score, 95)

    if behavior_type == "multi_vector_attack":
        risk_score += 5

    risk_score = min(risk_score, 100)

    return {
        "risk_classification": risk_classification,
        "risk_score": risk_score,
        "analyst_priority": analyst_priority
    }