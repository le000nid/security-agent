"""Arsenal SAST fixture: string-built SQL and executescript of input (CWE-89)."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/legacy-login")
def legacy_login():
    name = request.args.get("name", "")
    password = request.args.get("password", "")
    query = f"SELECT name, role FROM users WHERE name='{name}' AND pass='{password}'"
    return {"row": sqlite3.connect("app.db").execute(query).fetchone()}


@app.route("/batch")
def batch_tool():
    script = request.args.get("script", "")
    conn = sqlite3.connect("app.db")
    conn.executescript(script)
    return {"status": "executed"}
