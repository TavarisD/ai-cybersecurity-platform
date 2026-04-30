import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def explain_log(log, is_anomaly):
    client = get_openai_client()

    if client is None:
        return f"No OpenAI API key provided (fallback mode). Log: {log}. Anomaly detected: {is_anomaly}"

    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=f"Explain this security log in plain English. Log: {log}. Anomaly detected: {is_anomaly}"
        )
        return response.output_text
    except Exception as e:
        return f"AI explanation unavailable: {str(e)}"