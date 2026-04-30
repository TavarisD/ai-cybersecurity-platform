import os
from openai import OpenAI

def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def analyzer_with_ai(log):
    client = get_openai_client()

    if client is None:
        return "No OpenAI API key provided (fallback mode)"

    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=f"Analyze this security log: {log}"
        )
        return response.output_text
    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"