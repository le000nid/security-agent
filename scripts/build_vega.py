#!/usr/bin/env python3
"""Build the isolated, secret-free VEGA adapter archive."""

from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

REQUIRED = ("run.sh", "agent.json", "agent.py", "strategy.md")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "vega"
OUTPUT = PROJECT_ROOT / "dist" / "security-agent-vega.zip"


def build(output: Path = OUTPUT) -> Path:
    sources = {name: SOURCE_DIR / name for name in REQUIRED}
    missing = [name for name, path in sources.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing VEGA files: " + ", ".join(missing))

    with sources["agent.json"].open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise ValueError("vega/agent.json must contain a JSON object")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in REQUIRED:
            data = sources[name].read_bytes()
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            mode = 0o755 if name == "run.sh" else 0o644
            entry.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(entry, data)

    with zipfile.ZipFile(output) as archive:
        if tuple(archive.namelist()) != REQUIRED:
            raise RuntimeError("Unexpected VEGA archive contents")
    return output


if __name__ == "__main__":
    print(build())
