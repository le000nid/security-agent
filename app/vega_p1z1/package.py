"""Build the standalone submission, excluding project code and runtime data."""

import json
import stat
import tempfile
import zipfile
from pathlib import Path

FILES = ("run.sh", "agent.json", "agent.py", "strategy.md")


def build_archive(destination: Path) -> Path:
    root = Path(__file__).resolve().parent
    contents = {name: (root / name).read_bytes() for name in FILES}
    manifest = json.loads(contents["agent.json"])
    if manifest.get("entrypoint") != "run.sh":
        raise ValueError("Invalid P1Z1 entrypoint")
    if b"\r" in contents["run.sh"] or not contents["strategy.md"].strip():
        raise ValueError("Invalid P1Z1 submission files")
    compile(contents["agent.py"], "agent.py", "exec")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=".p1z1-", suffix=".zip", delete=False
        ) as stream:
            temporary = Path(stream.name)
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            for name in FILES:
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                mode = 0o755 if name == "run.sh" else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, contents[name])
        with zipfile.ZipFile(temporary) as archive:
            if tuple(archive.namelist()) != FILES or archive.testzip() is not None:
                raise ValueError("Invalid P1Z1 ZIP")
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
