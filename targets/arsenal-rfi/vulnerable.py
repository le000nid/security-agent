"""Arsenal SAST fixture: outbound fetch of a request-controlled URL (CWE-918)."""

from urllib.request import urlopen

from flask import Flask, request

app = Flask(__name__)


@app.route("/title")
def title():
    url = request.args.get("url", "")
    with urlopen(url, timeout=5) as response:
        return response.read(2048).decode("utf-8", "replace")
