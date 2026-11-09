"""The same untrusted values remain safe when passed as bound parameters."""


def percent_execute(incoming, cursor):
    supplied = incoming.args.get("name")
    alias = supplied
    # ok: python-sql-tainted-execute
    return cursor.execute("SELECT * FROM users WHERE name = %s", (alias,))


def format_execute(request, cursor):
    supplied = request.GET.get("email")
    # ok: python-sql-tainted-execute
    return cursor.execute("SELECT * FROM users WHERE email = %s", (supplied,))


def form_executemany(incoming, cursor):
    supplied = incoming.form["name"]
    # ok: python-sql-tainted-execute
    return cursor.executemany(
        "UPDATE users SET active = 1 WHERE name = %s", [(supplied,)]
    )


def manager_raw(incoming, User):
    supplied = incoming.POST.get("name")
    alias = supplied
    # ok: python-django-raw-sqli-taint
    return User._default_manager.raw("SELECT * FROM users WHERE name = %s", [alias])
