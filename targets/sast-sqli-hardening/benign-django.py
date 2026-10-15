"""Safe Django query examples."""


def safe_raw(request, User):
    name = request.GET.get("name")

    return User.objects.raw(
        "SELECT * FROM users WHERE name = %s",
        [name],
    )


def safe_orm(request, User):
    user_id = request.POST["id"]

    return User.objects.filter(id=user_id)