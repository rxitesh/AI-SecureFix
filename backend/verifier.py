from backend.scanner import scan_file


def verify_remediation():
    original_file = "samples/vulnerable.py"
    fixed_file = "remediated/fixed_vulnerable.py"

    before = scan_file(original_file)
    after = scan_file(fixed_file)

    if not before.get("success"):
        return {
            "success": False,
            "error": "Could not scan original file"
        }

    if not after.get("success"):
        return {
            "success": False,
            "error": "Could not scan remediated file"
        }

    before_count = before["total_findings"]
    after_count = after["total_findings"]

    before_score = before["security_score"]
    after_score = after["security_score"]

    removed_count = before_count - after_count
    score_improvement = after_score - before_score

    if before_count > 0:
        remediation_rate = (
            removed_count / before_count
        ) * 100
    else:
        remediation_rate = 100

    verified = (
        after_count < before_count
        and after_score > before_score
    )

    return {
        "success": True,
        "verified": verified,

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

        "removed_vulnerabilities": removed_count,
        "score_improvement": score_improvement,
        "remediation_rate": round(remediation_rate, 2)
    }