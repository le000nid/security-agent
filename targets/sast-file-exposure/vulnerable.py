from flask import request, send_file


def download():
    name = request.args.get("name")
    return send_file("uploads/" + name)
