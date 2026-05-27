import os
import smtplib
from email.message import EmailMessage


def send_security_alert_email(
    source: str,
    escalation_level: str,
    spike_detected: bool,
    timestamp: str | None = None
):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    alert_from = os.getenv("ALERT_FROM_EMAIL")
    alert_to = os.getenv("ALERT_TO_EMAIL")

    if not all([
        smtp_host,
        smtp_username,
        smtp_password,
        alert_from,
        alert_to
    ]):
        print("EMAIL SEND SKIPPED: missing SMTP environment variables")
        return {
            "sent": False,
            "reason": "missing_smtp_environment_variables"
        }

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

    message = EmailMessage()
    message["From"] = alert_from
    message["To"] = alert_to
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)

        print("EMAIL ALERT SENT:", subject)

        return {
            "sent": True,
            "reason": "email_sent"
        }

    except Exception as e:
        print("EMAIL SEND FAILED:", str(e))

        return {
            "sent": False,
            "reason": str(e)
        }