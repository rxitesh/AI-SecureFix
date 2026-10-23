from pathlib import Path
from fastapi import FastAPI
from backend.scanner import scan_file
from backend.remediation import remediate_file
from backend.verifier import verify_remediation
from pydantic import BaseModel

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