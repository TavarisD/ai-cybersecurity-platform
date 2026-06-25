def map_to_mitre_attack(attack_type, behavior_profile=None, risk_classification=None):
    attack = (attack_type or "").lower().strip()

    if "phishing" in attack:
        return {
            "mitre_technique_id": "T1566",
            "mitre_technique_name": "Phishing",
            "mitre_tactic": "Initial Access",
            "mitre_severity": "high"
        }

    if (
        "brute" in attack
        or "failed login" in attack
        or "failed_login" in attack
        or "credential" in attack
    ):
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

    if "ransomware" in attack:
        return {
            "mitre_technique_id": "T1486",
            "mitre_technique_name": "Data Encrypted for Impact",
            "mitre_tactic": "Impact",
            "mitre_severity": "critical"
        }

    if "powershell" in attack:
        return {
            "mitre_technique_id": "T1059.001",
            "mitre_technique_name": "PowerShell",
            "mitre_tactic": "Execution",
            "mitre_severity": "high"
        }

    if "ssh" in attack:
        return {
            "mitre_technique_id": "T1021.004",
            "mitre_technique_name": "SSH",
            "mitre_tactic": "Lateral Movement",
            "mitre_severity": "medium"
        }
    
    return {
        "mitre_technique_id": "T0000",
        "mitre_technique_name": "Unknown Technique",
        "mitre_tactic": "Unknown",
        "mitre_severity": "low"
    }