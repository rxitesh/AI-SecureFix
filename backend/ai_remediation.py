import time
from google import genai

client = genai.Client()


def clean_markdown_fences(code: str) -> str:
    """Strip markdown code block fences if the LLM includes them."""
    cleaned = code.strip()
    if cleaned.startswith("```python"):
        cleaned = cleaned[len("```python"):].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[len("```"):].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()
    return cleaned

def is_retryable_error(error: Exception) -> bool:
    """Identify temporary availability, network drop, and rate-limit errors."""
    if isinstance(error, (ConnectionError, TimeoutError)):
        return True

    error_str = str(error).upper()
    retryable_keywords = [
        "503",
        "UNAVAILABLE",
        "429",
        "RESOURCE_EXHAUSTED",
        "HIGH DEMAND",
        "RATE LIMIT",
        "TIMEOUT",
        "DEADLINE_EXCEEDED",
        "DISCONNECTED",
        "CONNECTION",
        "RESET BY PEER",
        "REMOTE",
    ]
    return any(keyword in error_str for keyword in retryable_keywords)

def ai_remediate_code(code: str, max_retries: int = 3, initial_delay: float = 2.0):
    prompt = f"""
You are a secure Python code remediation assistant.

Analyze the Python code below and fix its security vulnerabilities.

Requirements:
1. Preserve the original functionality as much as possible.
2. Fix security vulnerabilities using secure coding practices.
3. Do not add unnecessary features.
4. Return ONLY the corrected Python code.
5. Do not use Markdown code fences.
6. Do not include explanations before or after the code.

Python code:

{code}
"""

    last_error = None
    delay = initial_delay

    for attempt in range(1, max_retries + 1):
        try:
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt
            )

            raw_text = response.text or ""
            fixed_code = clean_markdown_fences(raw_text)

            return {
                "success": True,
                "method": "AI-Based",
                "model": "gemini-3.6-flash",
                "attempts": attempt,
                "original_code": code,
                "fixed_code": fixed_code
            }

        except Exception as error:
            last_error = error
            # If it's a temporary error and we have attempts left, wait and retry
            if attempt < max_retries and is_retryable_error(error):
                time.sleep(delay)
                delay *= 2  # Exponential backoff: 2s -> 4s -> 8s
                continue
            break

    return {
        "success": False,
        "method": "AI-Based",
        "attempts": attempt,
        "error": str(last_error)
    }