#!/usr/bin/env python3
"""Build the isolated, secret-free VEGA adapter archives.

Three profiles ship from the same contract (exactly four root files):

- ``vega``  — bounded evidence agent (``vega/``)  -> dist/security-agent-vega.zip
- ``p3z2``  — P3Z2 LFI filter-bypass agent (``vega_p3z2/``)
              -> dist/security-agent-p3z2.zip
- ``p3z3``  — P3Z3 check-before-assembly bypass agent (``vega_p3z3/``)
              -> dist/security-agent-p3z3.zip
"""

from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

REQUIRED = ("run.sh", "agent.json", "agent.py", "strategy.md")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "vega"
OUTPUT = PROJECT_ROOT / "dist" / "security-agent-vega.zip"
P3Z2_SOURCE_DIR = PROJECT_ROOT / "vega_p3z2"
P3Z2_OUTPUT = PROJECT_ROOT / "dist" / "security-agent-p3z2.zip"
P3Z3_SOURCE_DIR = PROJECT_ROOT / "vega_p3z3"
P3Z3_OUTPUT = PROJECT_ROOT / "dist" / "security-agent-p3z3.zip"


def build(output: Path = OUTPUT, source_dir: Path = SOURCE_DIR) -> Path:
    sources = {name: source_dir / name for name in REQUIRED}
    missing = [name for name, path in sources.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            f"Missing VEGA files in {source_dir.name}: " + ", ".join(missing)
        )

    with sources["agent.json"].open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise ValueError(f"{source_dir.name}/agent.json must contain a JSON object")

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


def build_p3z2(output: Path = P3Z2_OUTPUT) -> Path:
    return build(output, P3Z2_SOURCE_DIR)


def build_p3z3(output: Path = P3Z3_OUTPUT) -> Path:
    return build(output, P3Z3_SOURCE_DIR)


def build_all() -> list[Path]:
    return [build(), build_p3z2(), build_p3z3()]


if __name__ == "__main__":
    for artifact in build_all():
        print(artifact)
