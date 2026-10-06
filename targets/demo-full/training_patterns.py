"""Intentionally vulnerable educational fixture. Never use as production code.

These examples are source-only. They are NEVER imported by the HTTP server.
"""

import pickle
import subprocess


def training_secret():
    api_key = "training-only-not-a-real-secret"
    return api_key


def unsafe_command(command):
    return subprocess.run(command, shell=True)


def unsafe_deserialization(data):
    return pickle.loads(data)


def debug_example(app):
    app.run(debug=True)
