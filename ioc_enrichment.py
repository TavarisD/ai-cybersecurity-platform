def enrich_iocs(ioc_data):
    enriched = []

    for ioc in ioc_data.get("iocs", []):
        risk_level = "low"

        if ioc["indicator_type"] == "ip_address":
            risk_level = "medium"

        enriched.append({
            "indicator_value": ioc["indicator_value"],
            "indicator_type": ioc["indicator_type"],
            "threat_category": (
                "network_indicator"
                if ioc["indicator_type"] == "ip_address"
                else "generic_indicator"
            ),
            "confidence": 85,
            "risk_level": risk_level
        })

    return {
        "ioc_count": len(enriched),
        "enriched_iocs": enriched
    }
