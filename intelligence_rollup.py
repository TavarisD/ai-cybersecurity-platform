def build_intelligence_rollup(
    risk_classification,
    threat_reputation,
    threat_narrative,
    mitre_mapping,
    threat_cluster,
    ioc_enrichment
):
    return {
        "overall_risk": (
            risk_classification.get(
                "risk_classification",
                "low_risk"
            )
        ),

        "reputation_level": (
            threat_reputation.get(
                "reputation_level",
                "low"
            )
        ),

        "cluster_name": (
            threat_cluster.get(
                "cluster_name",
                "unknown_cluster"
            )
        ),

        "mitre_technique": (
            mitre_mapping.get(
                "mitre_technique_name",
                "Unknown Technique"
            )
        ),

        "ioc_count": (
            ioc_enrichment.get(
                "ioc_count",
                0
            )
        ),

        "executive_narrative": (
            threat_narrative.get(
                "narrative",
                "No narrative available"
            )
        )
    }