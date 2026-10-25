from pathlib import Path

from backend.scanner import scan_file
from backend.dynamic_remediation import remediate_code


def verify_dynamic_code(code: str):
    temp_directory = Path("temp")
    temp_directory.mkdir(exist_ok=True)

    original_file = temp_directory / "verify_original.py"
    fixed_file = temp_directory / "verify_fixed.py"

    try:
        # Save original submitted code
        original_file.write_text(
            code,
            encoding="utf-8"
        )

        # Scan original code
        before = scan_file("temp/verify_original.py")

        if not before.get("success"):
            return {
                "success": False,
                "error": "Could not scan original submitted code."
            }

        # Remediate submitted code
        remediation = remediate_code(code)

        if not remediation.get("success"):
            return {
                "success": False,
                "error": "Could not remediate submitted code."
            }

        fixed_code = remediation["fixed_code"]

        # Save remediated code
        fixed_file.write_text(
            fixed_code,
            encoding="utf-8"
        )

        # Scan remediated code
        after = scan_file("temp/verify_fixed.py")

        if not after.get("success"):
            return {
                "success": False,
                "error": "Could not scan remediated code."
            }

        # Compare before and after
        before_count = before["total_findings"]
        after_count = after["total_findings"]

        before_score = before["security_score"]
        after_score = after["security_score"]

        removed_count = before_count - after_count
        score_improvement = after_score - before_score

        # Calculate remediation rate
        if before_count > 0:
            remediation_rate = (
                removed_count / before_count
            ) * 100
        else:
            remediation_rate = 100

        # Determine verification status
        if before_count == 0:
            status = "NO_VULNERABILITIES"
            verified = True

        elif after_count == 0:
            status = "FULLY_REMEDIATED"
            verified = True

        elif after_count < before_count:
            status = "PARTIALLY_REMEDIATED"
            verified = False

        elif after_count == before_count:
            status = "FAILED"
            verified = False

        else:
            status = "REGRESSION"
            verified = False

        return {
            "success": True,
            "verified": verified,
            "status": status,

            "before": {
                "total_findings": before_count,
                "security_score": before_score,
                "risk_level": before["risk_level"],
                "summary": before["summary"]
            },

            "after": {
                "total_findings": after_count,
                "security_score": after_score,
                "risk_level": after["risk_level"],
                "summary": after["summary"]
            },

            "fixes_applied": remediation["fixes_applied"],
            "removed_vulnerabilities": removed_count,
            "score_improvement": score_improvement,
            "remediation_rate": round(remediation_rate, 2),

            "fixed_code": fixed_code
        }

    except Exception as error:
        return {
            "success": False,
            "error": str(error)
        }