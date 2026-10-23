import os
import hashlib
import sqlite3


def login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    stored_password = "admin123"

    if password == stored_password:
        return "Login successful"

    return "Login failed"


def ping_server(host):
    os.system("ping " + host)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()