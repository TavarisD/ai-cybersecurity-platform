MAX_ALERTS = 100

alerts = []


def trim_alerts():
    if len(alerts) > MAX_ALERTS:
        del alerts[:-MAX_ALERTS]


def add_alert(message, severity="medium"):
    alerts.append({
        "message": message,
        "severity": severity
    })
    trim_alerts()


def create_alert(message, severity="medium"):
    add_alert(message, severity)


def get_alerts():
    return alerts