"""HTTP aliases, Django getters and multiple SQL construction styles."""


def percent_execute(incoming, cursor):
    supplied = incoming.args.get("name")
    alias = supplied
    sql = "SELECT * FROM users WHERE name = '%s'" % alias
    # ruleid: python-sql-tainted-execute
    return cursor.execute(sql)


def format_execute(request, cursor):
    supplied = request.GET.get("email")
    sql = "SELECT * FROM users WHERE email = '{}'".format(supplied)
    # ruleid: python-sql-tainted-execute
    return cursor.execute(sql)


def form_executemany(incoming, cursor):
    supplied = incoming.form["name"]
    sql = f"UPDATE users SET active = 1 WHERE name = '{supplied}'"
    # ruleid: python-sql-tainted-execute
    return cursor.executemany(sql, [()])


def manager_raw(incoming, User):
    supplied = incoming.POST.get("name")
    alias = supplied
    sql = f"SELECT * FROM users WHERE name = '{alias}'"
    # ruleid: python-django-raw-sqli-taint
    return User._default_manager.raw(sql)
