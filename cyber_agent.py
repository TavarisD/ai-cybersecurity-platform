from ai_engine import AnomalyDetector, extract_features
from ai_explainer import explain_log


def detect_known_attack(log: str) -> tuple[bool, str]:
    text = log.lower()

    if "sql injection" in text or "' or 1=1" in text or "union select" in text:
        return True, "sql_injection"

    if "multiple failed login" in text or "multiple failed login attempts" in text:
        return True, "brute_force"

    if "failed login" in text and "from" in text:
        return True, "failed_login"

    return False, "unknown"


def analyze_security_logs(logs):
    features = extract_features(logs)

    detector = AnomalyDetector()
    detector.fit(features)

    predictions = detector.predict(features)

    results = []

    for log, pred in zip(logs, predictions):
        ml_anomaly = bool(pred == -1)

        rule_anomaly, attack_type = detect_known_attack(log)

        is_anomaly = ml_anomaly or rule_anomaly

        explanation = explain_log(log, is_anomaly)

        results.append({
            "log": log,
            "anomaly": is_anomaly,
            "attack_type": attack_type,
            "analysis": explanation
        })

    return results


def analyze_security_log(log_text: str):
    results = analyze_security_logs([log_text])
    return results[0]