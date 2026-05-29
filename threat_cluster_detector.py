def detect_threat_cluster(
    fingerprint,
    campaign_attribution,
    correlation_data
):
    cluster_name = campaign_attribution.get(
        "campaign_name",
        "unknown_cluster"
    )

    cluster_score = (
        correlation_data.get("total_incidents", 0) * 10
    )

    cluster_confidence = min(cluster_score, 100)

    return {
        "cluster_name": cluster_name,
        "cluster_confidence": cluster_confidence,
        "related_incidents": correlation_data.get(
            "total_incidents",
            0
        ),
        "cluster_active": cluster_confidence >= 50
    }
