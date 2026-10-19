"""SAST-only teaching examples. This module is never imported by the HTTP fixture."""

import requests
from flask import request


def vulnerable_fetch():
    target = request.args.get("url")
    return requests.get(target, timeout=2).text


def safe_fetch():
    return requests.get("http://127.0.0.1:3000/healthz", timeout=2).text
