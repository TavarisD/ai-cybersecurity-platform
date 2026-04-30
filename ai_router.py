import os
from dotenv import load_dotenv
from openai import OpenAI
import anthropic

load_dotenv()

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
claude_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def ask_chatgpt(prompt):
    response = openai_client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content if response.choices else "No response"

def ask_claude(prompt):
    response = claude_client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text

def ai_router(task):
    if "analyze" in task.lower() or "deep" in task.lower():
        return ask_claude(task)
    return ask_chatgpt(task)