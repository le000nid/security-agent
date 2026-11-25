"""Arsenal SAST fixture: concatenated open() and archive member writes (CWE-22/23)."""

import os
import tarfile
import zipfile

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("file", "")
    with open(BASE_DIR + name, "r") as handle:
        return handle.read()


@app.route("/unpack")
def unpack():
    member = request.args.get("member", "")
    with zipfile.ZipFile(BASE_DIR + "/bundle.zip") as bundle:
        data = bundle.read(member)
    with open(os.path.join(BASE_DIR, member), "wb") as out:
        out.write(data)
    return {"written": len(data)}


@app.route("/extract")
def extract():
    bundle = request.args.get("bundle", "evil.tar")
    with tarfile.open(os.path.join(BASE_DIR, bundle)) as tf:
        tf.extractall("/srv/inbox")
    return {"status": "extracted"}
