from flask import request, send_from_directory


def download():
    return send_from_directory("uploads", request.args["name"])
