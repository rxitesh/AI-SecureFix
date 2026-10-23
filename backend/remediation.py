from pathlib import Path


def remediate_file(file_path: str):
    project_root = Path(__file__).resolve().parent.parent
    target = project_root / file_path

    if not target.exists():
        return {
            "success": False,
            "error": "File not found"
        }

    try:
        original_code = target.read_text(encoding="utf-8")
        fixed_code = original_code
        fixes_applied = []

        # 1. Fix SQL Injection
        old_sql = '''
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
'''

        new_sql = '''
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
'''

        if old_sql in fixed_code:
            fixed_code = fixed_code.replace(old_sql, new_sql)

            fixes_applied.append({
                "type": "SQL Injection",
                "cwe": "CWE-89",
                "fix": "Replaced SQL string concatenation with a parameterized query."
            })

        # 2. Fix Command Injection
        old_command = '''
    os.system("ping " + host)
'''

        new_command = '''
    import subprocess
    subprocess.run(["ping", host], check=True)
'''

        if old_command in fixed_code:
            fixed_code = fixed_code.replace(
                old_command,
                new_command
            )

            fixes_applied.append({
                "type": "Command Injection",
                "cwe": "CWE-78",
                "fix": "Replaced os.system() with subprocess.run() using an argument list."
            })

        # 3. Fix Hardcoded Password
        old_password = '''
    stored_password = "admin123"
'''

        new_password = '''
    stored_password = os.getenv("APP_PASSWORD")
'''

        if old_password in fixed_code:
            fixed_code = fixed_code.replace(
                old_password,
                new_password
            )

            fixes_applied.append({
                "type": "Hardcoded Password",
                "cwe": "CWE-798",
                "fix": "Moved the hardcoded password to an environment variable."
            })

        # 4. Fix Weak MD5 Password Hashing
        old_hash = "    return hashlib.md5(password.encode()).hexdigest()"

        new_hash = """    salt = os.urandom(16)
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1
    ).hex()"""

        if old_hash in fixed_code:
            fixed_code = fixed_code.replace(
                old_hash,
                new_hash
            )

            fixes_applied.append({
                "type": "Weak Password Hashing",
                "cwe": "CWE-327",
                "fix": "Replaced MD5 with scrypt password hashing."
            })

        # Create directory for remediated files
        output_directory = project_root / "remediated"
        output_directory.mkdir(exist_ok=True)

        output_file = output_directory / "fixed_vulnerable.py"

        output_file.write_text(
            fixed_code,
            encoding="utf-8"
        )

        return {
            "success": True,
            "fixes_applied": len(fixes_applied),
            "fixes": fixes_applied,
            "original_code": original_code,
            "fixed_code": fixed_code,
            "output_file": str(output_file)
        }

    except Exception as error:
        return {
            "success": False,
            "error": str(error)
        }