import os
import resend


def send_security_alert_email(
    source: str,
    escalation_level: str,
    spike_detected: bool,
    timestamp: str | None = None
):
    resend_api_key = os.getenv("RESEND_API_KEY")
    alert_from = os.getenv("ALERT_FROM_EMAIL", "onboarding@resend.dev")
    alert_to = os.getenv("ALERT_TO_EMAIL")

    if not resend_api_key or not alert_to:
        print("EMAIL SEND SKIPPED: missing Resend environment variables")
        return {
            "sent": False,
            "reason": "missing_resend_environment_variables"
        }

    resend.api_key = resend_api_key

    subject = f"Cybersecurity Alert: {escalation_level.upper()} escalation from {source}"

    body = f"""
Cybersecurity AI Alert

Source: {source}
Escalation Level: {escalation_level}
Spike Detected: {spike_detected}
Timestamp: {timestamp or "unknown"}

Recommended Action:
Review this source in the SOC dashboard and investigate recent activity.
"""

    try:
        response = resend.Emails.send({
            "from": alert_from,
            "to": [alert_to],
            "subject": subject,
            "text": body
        })

        print("RESEND EMAIL ALERT SENT:", response)

        return {
            "sent": True,
            "reason": "email_sent",
            "provider": "resend",
            "response": response
        }

    except Exception as e:
        print("RESEND EMAIL SEND FAILED:", str(e))

        return {
            "sent": False,
            "reason": str(e),
            "provider": "resend"
        }