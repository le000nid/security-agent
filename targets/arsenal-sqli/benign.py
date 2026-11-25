"""Arsenal SAST fixture: parameterized statements and allowlisted identifiers."""

import sqlite3

_SORT_QUERIES = {
    "name": "SELECT name, role FROM users ORDER BY name",
    "role": "SELECT name, role FROM users ORDER BY role",
}


def login(conn: sqlite3.Connection, name: str, password: str) -> dict:
    row = conn.execute(
        "SELECT name, role FROM users WHERE name = ? AND pass = ?", (name, password)
    ).fetchone()
    return {"row": row}


def ordered_users(conn: sqlite3.Connection, sort_key: str) -> list[tuple]:
    query = _SORT_QUERIES.get(sort_key)
    if query is None:
        raise ValueError("sort column not allowed")
    return conn.execute(query).fetchall()
