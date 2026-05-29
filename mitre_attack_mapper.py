def map_to_mitre_attack(attack_type, behavior_profile, risk_classification):
    technique_id = "T0000"
    technique_name = "Unknown Technique"
    tactic = "Unknown"
    severity = "low"

    if attack_type == "failed_login":
        technique_id = "T1110"
        technique_name = "Brute Force"
        tactic = "Credential Access"
        severity = "medium"

    if attack_type == "sql_injection":
        technique_id = "T1190"
        technique_name = "Exploit Public-Facing Application"
        tactic = "Initial Access"
        severity = "high"

    if behavior_profile.get("behavior_type") == "multi_vector_attack":
        technique_id = "T1595"
        technique_name = "Active Scanning"
        tactic = "Reconnaissance"
        severity = "high"

    if risk_classification.get("analyst_priority") == "Critical":
        severity = "critical"

    return {
        "mitre_technique_id": technique_id,
        "mitre_technique_name": technique_name,
        "mitre_tactic": tactic,
        "mitre_severity": severity
    }
