"""Arsenal SAST fixture: containment-proven reads and allowlisted extraction."""

import zipfile
from pathlib import Path

from app.http_guard import contained_path

BASE_DIR = Path("/srv/files")


def download(raw_name: str) -> str:
    path = contained_path(BASE_DIR, raw_name)
    return path.read_text(encoding="utf-8")


def unpack_member(bundle_path: Path, member: str) -> None:
    if ".." in Path(member).parts:
        raise ValueError("parent segment in archive member")
    with zipfile.ZipFile(bundle_path) as bundle:
        payload = bundle.read(member)
    target = contained_path(BASE_DIR, "unpacked", member)
    target.write_bytes(payload)
