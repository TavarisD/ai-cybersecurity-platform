def generate_welcome_email(user_email: str):
    return {
        "subject": "Welcome to AI Cybersecurity Platform",
        "body": f"""
Hello,

Welcome to AI Cybersecurity Platform.

Getting started:

1. Login to your dashboard
2. Reveal or copy your API key
3. Open API Documentation
4. Send your first test log
5. Monitor activity in your dashboard

Useful Pages:

Dashboard:
/dashboard

API Documentation:
/api-docs-page

Customer Onboarding:
/onboarding

Usage Analytics:
/usage-analytics-page

Thank you for joining.

AI Cybersecurity Platform
"""
    }