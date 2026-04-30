import re

def extract_features(log):
    text = log.lower()

    features = {
        "ip": None,
        "failed_login": 0,
        "sql_injection": 0
    }

    ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", log)
    if ip_match:
        features["ip"] = ip_match.group()

    failed_patterns = [
        "failed login",
        "login failed",
        "authentication failed",
        "invalid password",
        "invalid credentials",
        "unsuccessful login"
    ]

    if any(p in text for p in failed_patterns):
        features["failed_login"] = 1

    sql_patterns = [
        "select ",
        "union select",
        "drop table",
        "insert into",
        "delete from",
        "--",
        "' or '1'='1",
        "sql injection",
        "sql injection attempt",
        "injection attempt detected"
    ]

    if any(p in text for p in sql_patterns):
        features["sql_injection"] = 1

    return features

def detect_attack_type(features):
    if features.get("failed_login"):
        return "failed_login"
    elif features.get("sql_injection"):
        return "sql_injection"
    elif features.get("multiple_failed_logins"):
        return "brute_force"
    return "normal"