"""Intentionally insecure educational fixtures; never use as application code."""

import pickle
import subprocess

import requests
from flask import Flask

app = Flask(__name__)
api_key = "training-secret-value"


def examples(serialized_data: bytes) -> None:
    subprocess.run("echo training", shell=True)
    pickle.loads(serialized_data)
    requests.get("https://localhost", verify=False)


if __name__ == "__main__":
    app.run(debug=True)
