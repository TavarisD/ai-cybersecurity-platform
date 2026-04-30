from datetime import datetime

MAX_METRIC_POINTS = 200

metrics = {
    "events": [],
    "threat_scores": []
}

def trim_metrics():
    if len(metrics["events"]) > MAX_METRIC_POINTS:
        metrics["events"] = metrics["events"][-MAX_METRIC_POINTS:]

    if len(metrics["threat_scores"]) > MAX_METRIC_POINTS:
        metrics["threat_scores"] = metrics["threat_scores"][-MAX_METRIC_POINTS:]


def log_event(threat_score):
    metrics["events"].append(datetime.now().strftime("%H:%M:%S"))
    metrics["threat_scores"].append(threat_score)
    trim_metrics()

def get_metrics():
    return metrics