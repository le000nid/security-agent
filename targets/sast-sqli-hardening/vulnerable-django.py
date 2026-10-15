"""Unsafe Django raw SQL examples."""


def unsafe_raw_get(request, User):
    name = request.GET.get("name")

    sql = f"SELECT * FROM users WHERE name = '{name}'"

    return User.objects.raw(sql)


def unsafe_raw_post(request, User):
    user_id = request.POST["id"]

    sql = "SELECT * FROM users WHERE id = " + user_id

    return User.objects.raw(sql)