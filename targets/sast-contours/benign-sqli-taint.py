"""Educational fixture: parameter binding keeps SQL text constant."""

from flask import request


def safe_lookup(cursor):
    return cursor.execute(
        "SELECT * FROM users WHERE name = ?", (request.args.get("name"),)
    )
