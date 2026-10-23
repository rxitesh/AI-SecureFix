import json
import subprocess
from pathlib import Path


def normalize_severity(rule_id, severity):
    rule_id = rule_id or ""

    if "sqlalchemy-execute-raw-query" in rule_id:
        return "HIGH"

    if rule_id == "custom-command-injection":
        return "HIGH"

    if rule_id == "custom-hardcoded-password":
        return "HIGH"

    if "md5-used-as-password" in rule_id:
        return "MEDIUM"

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW"
    }

    return severity_map.get(severity, "LOW")


def get_vulnerability_name(rule_id):
    rule_id = rule_id or ""

    if "sqlalchemy-execute-raw-query" in rule_id:
        return "SQL Injection"

    if "md5-used-as-password" in rule_id:
        return "Weak Password Hashing"

    if rule_id == "custom-command-injection":
        return "Command Injection"

    if rule_id == "custom-hardcoded-password":
        return "Hardcoded Password"

    return "Security Vulnerability"


def custom_scan(file_path: Path):
    vulnerabilities = []

    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return vulnerabilities

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        if "os.system(" in line:
            vulnerabilities.append({
                "rule_id": "custom-command-injection",
                "severity": "ERROR",
                "message": "Possible command injection detected through os.system().",
                "file": str(file_path),
                "line": line_number,
                "cwe": ["CWE-78"],
                "source": "Custom Analyzer"
            })

        if "admin123" in line or "password123" in line:
            vulnerabilities.append({
                "rule_id": "custom-hardcoded-password",
                "severity": "WARNING",
                "message": "Possible hardcoded password detected.",
                "file": str(file_path),
                "line": line_number,
                "cwe": ["CWE-798"],
                "source": "Custom Analyzer"
            })

    return vulnerabilities


def calculate_security_score(vulnerabilities):
    penalties = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2
    }

    score = 100

    for vulnerability in vulnerabilities:
        severity = vulnerability["severity"]
        score -= penalties.get(severity, 0)

    return max(score, 0)


def calculate_risk_level(score):
    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def scan_file(file_path: str):
    project_root = Path(__file__).resolve().parent.parent
    target = project_root / file_path

    if not target.exists():
        return {
            "success": False,
            "error": "File not found"
        }

    command = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        str(target),
        "--json",
        "--quiet"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        data = json.loads(result.stdout)

        vulnerabilities = []

        for finding in data.get("results", []):
            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})

            rule_id = finding.get("check_id")
            original_severity = extra.get("severity")

            vulnerabilities.append({
                "rule_id": rule_id,
                "type": get_vulnerability_name(rule_id),
                "severity": normalize_severity(
                    rule_id,
                    original_severity
                ),
                "message": extra.get("message"),
                "file": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "cwe": metadata.get("cwe", []),
                "source": "Semgrep"
            })

        custom_findings = custom_scan(target)

        for finding in custom_findings:
            finding["type"] = get_vulnerability_name(
                finding["rule_id"]
            )

            finding["severity"] = normalize_severity(
                finding["rule_id"],
                finding["severity"]
            )

            vulnerabilities.append(finding)

        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for vulnerability in vulnerabilities:
            severity = vulnerability["severity"].lower()

            if severity in summary:
                summary[severity] += 1

        security_score = calculate_security_score(vulnerabilities)
        risk_level = calculate_risk_level(security_score)

        return {
            "success": True,
            "total_findings": len(vulnerabilities),
            "security_score": security_score,
            "risk_level": risk_level,
            "summary": summary,
            "vulnerabilities": vulnerabilities
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Security scan timed out"
        }

    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Could not parse Semgrep output"
        }