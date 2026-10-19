"""Educational fixture: Flask input controls SQL text."""

from flask import request


def unsafe_lookup(cursor):
    name = request.args.get("name")
    sql = "SELECT * FROM users WHERE name = '%s'" % name
    return cursor.execute(sql)
