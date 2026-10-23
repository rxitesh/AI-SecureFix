import os
import hashlib
import sqlite3


def login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    stored_password = os.getenv("APP_PASSWORD")

    if password == stored_password:
        return "Login successful"

    return "Login failed"


def ping_server(host):
    import subprocess
    subprocess.run(["ping", host], check=True)


def hash_password(password):
    salt = os.urandom(16)
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1
    ).hex()