import re


def remediate_code(code: str):
    fixed_code = code
    fixes = []

    # 1. Fix Command Injection
    command_pattern = r'os\.system\((.+)\)'

    if re.search(command_pattern, fixed_code):
        if "import subprocess" not in fixed_code:
            fixed_code = "import subprocess\n" + fixed_code

        fixed_code = re.sub(
            command_pattern,
            r"subprocess.run(\1, shell=False)",
            fixed_code
        )

        fixes.append({
            "type": "Command Injection",
            "cwe": "CWE-78",
            "method": "Rule-Based",
            "description": "Replaced os.system() with subprocess.run() without shell execution."
        })

    # 2. Fix Hardcoded Password
    password_pattern = (
        r'(\b\w*password\w*\s*=\s*)'
        r'["\'][^"\']+["\']'
    )

    if re.search(
        password_pattern,
        fixed_code,
        flags=re.IGNORECASE
    ):
        if "import os" not in fixed_code:
            fixed_code = "import os\n" + fixed_code

        fixed_code = re.sub(
            password_pattern,
            r'\1os.getenv("APP_PASSWORD")',
            fixed_code,
            flags=re.IGNORECASE
        )

        fixes.append({
            "type": "Hardcoded Password",
            "cwe": "CWE-798",
            "method": "Rule-Based",
            "description": "Replaced hardcoded password with an environment variable."
        })

    return {
        "success": True,
        "fixes_applied": len(fixes),
        "fixes": fixes,
        "original_code": code,
        "fixed_code": fixed_code
    }