from pathlib import Path
from fastapi import FastAPI
from backend.scanner import scan_file
from backend.remediation import remediate_file
from backend.verifier import verify_remediation
from pydantic import BaseModel
from backend.dynamic_remediation import remediate_code
from backend.dynamic_verifier import verify_dynamic_code
from backend.ai_remediation import ai_remediate_code
from backend.ai_verifier import verify_ai_code

app = FastAPI(
    title="AI SecureFix API",
    description="Security Analysis and Automated Remediation of AI-Generated Code and AI Agents",
    version="1.0.0"
)

class CodeRequest(BaseModel):
    code: str

@app.get("/")
def home():
    return {
        "project": "AI SecureFix",
        "status": "running",
        "message": "Security analysis backend is ready"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/scan")
def scan():
    return scan_file("samples/vulnerable.py")

@app.post("/remediate")
def remediate():
    return remediate_file("samples/vulnerable.py")

@app.get("/verify")
def verify():
    return verify_remediation()

@app.post("/scan-code")
def scan_code(request: CodeRequest):
    temp_directory = Path("temp")
    temp_directory.mkdir(exist_ok=True)

    temp_file = temp_directory / "submitted_code.py"

    temp_file.write_text(
        request.code,
        encoding="utf-8"
    )

    return scan_file("temp/submitted_code.py")

@app.post("/remediate-code")
def remediate_submitted_code(request: CodeRequest):
    return remediate_code(request.code)

@app.post("/verify-code")
def verify_submitted_code(request: CodeRequest):
    return verify_dynamic_code(request.code)

@app.post("/ai-remediate-code")
def ai_remediate_submitted_code(request: CodeRequest):
    return ai_remediate_code(request.code)

@app.post("/ai-verify-code")
def ai_verify_submitted_code(request: CodeRequest):
    return verify_ai_code(request.code)