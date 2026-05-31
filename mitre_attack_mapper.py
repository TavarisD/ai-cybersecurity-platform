def map_to_mitre_attack(attack_type, behavior_profile=None, risk_classification=None):
    attack = (attack_type or "").lower().strip()

    if "phishing" in attack:
        return {
            "mitre_technique_id": "T1566",
            "mitre_technique_name": "Phishing",
            "mitre_tactic": "Initial Access",
            "mitre_severity": "high"
        }

    if "brute" in attack or "failed login" in attack or "credential" in attack:
        return {
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "mitre_severity": "high"
        }

    if "sql" in attack or "injection" in attack:
        return {
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "mitre_tactic": "Initial Access",
            "mitre_severity": "critical"
        }

    if "malware" in attack:
        return {
            "mitre_technique_id": "T1204",
            "mitre_technique_name": "User Execution",
            "mitre_tactic": "Execution",
            "mitre_severity": "high"
        }

    return {
        "mitre_technique_id": "T0000",
        "mitre_technique_name": "Unknown Technique",
        "mitre_tactic": "Unknown",
        "mitre_severity": "low"
    }