from google import genai


client = genai.Client()


def ai_remediate_code(code: str):
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

    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt
        )

        fixed_code = response.text.strip()

        return {
            "success": True,
            "method": "AI-Based",
            "model": "gemini-3.8-flash",
            "original_code": code,
            "fixed_code": fixed_code
        }

    except Exception as error:
        return {
            "success": False,
            "method": "AI-Based",
            "error": str(error)
        }