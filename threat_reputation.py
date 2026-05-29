def calculate_threat_reputation(
    threat_cluster,
    fingerprint,
    actor_confidence
):
    score = 0

    if threat_cluster.get("cluster_active"):
        score += 40

    if fingerprint.get("repeat_offender"):
        score += 30

    score += min(
        actor_confidence.get("actor_confidence", 0),
        30
    )

    reputation = "low"

    if score >= 80:
        reputation = "critical"
    elif score >= 60:
        reputation = "high"
    elif score >= 30:
        reputation = "medium"

    return {
        "reputation_score": score,
        "reputation_level": reputation
    }
