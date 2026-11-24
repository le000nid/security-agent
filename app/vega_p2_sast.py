"""Offline SAST handoff for the two VEGA file-disclosure tasks."""

import argparse
import json
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

from app.resources import config_directory
from app.semgrep import parse_semgrep_json, run_semgrep
from app.validation import validate_source_path

TASKS = ("p2z1", "p2z2")
PROFILE_RULES = config_directory() / "semgrep-vega-p2.yaml"
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".php"}
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"}
WEB_DIRS = {"public", "static", "www", "wwwroot", "htdocs"}
OLD_DIRS = {"archive", "backup", "backups", "old", "previous"}
BACKUP_SUFFIXES = (".bak", ".backup", ".old", ".orig", ".save", "~")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".7z")
ARCHIVE_HINT = re.compile(
    r"(?:^|[._-])(?:backup|old|previous|site|www|dump)(?:[._-]|$)"
)
MAX_ENTRIES = 5000
MAX_CODE_FILES = 256
MAX_FILE_BYTES = 900_000
MAX_CODE_BYTES = 16 * 1024 * 1024


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _raise_walk_error(error: OSError) -> None:
    raise error


def _files(root: Path) -> Iterator[Path]:
    seen = 0
    for directory, dirs, files in os.walk(root, onerror=_raise_walk_error):
        current = Path(directory)
        seen += len(dirs) + len(files)
        if seen > MAX_ENTRIES:
            raise ValueError("Local input exceeds the SAST inventory limit")
        dirs[:] = sorted(
            name
            for name in dirs
            if name.casefold() not in SKIP_DIRS
            and not _is_link((current / name).lstat())
        )
        for name in sorted(files):
            path = current / name
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and not _is_link(info):
                yield path


def _backup_reason(path: Path) -> str | None:
    name = path.name.casefold()
    if name.endswith(BACKUP_SUFFIXES):
        return "backup_suffix"
    if name.endswith(ARCHIVE_SUFFIXES) and ARCHIVE_HINT.search(name):
        return "backup_archive_name"
    if any(part.casefold() in OLD_DIRS for part in path.parts[:-1]) and (
        path.suffix.casefold() in CODE_SUFFIXES | {".html", ".json", ".sql", ".ini"}
        or name == ".env"
    ):
        return "old_copy_directory"
    return None


def _inspect_backups(root: Path) -> dict:
    inspected = 0
    candidates = []
    for path in _files(root):
        relative = path.relative_to(root)
        if relative.as_posix() == "instruction.md":
            continue
        inspected += 1
        reason = _backup_reason(relative)
        if reason:
            candidates.append(
                {
                    "path": relative.as_posix(),
                    "reason": reason,
                    "under_web_named_directory": any(
                        part.casefold() in WEB_DIRS for part in relative.parts[:-1]
                    ),
                    "http_verified": False,
                }
            )
    return {
        "status": "completed" if inspected else "no_source",
        "inspected_files": inspected,
        "backup_candidates": sorted(candidates, key=lambda item: item["path"]),
    }


def _stage_sources(root: Path, staged: Path) -> set[str]:
    total = 0
    paths = set()
    for path in _files(root):
        if path.suffix.casefold() not in CODE_SUFFIXES:
            continue
        with path.open("rb") as stream:
            content = stream.read(MAX_FILE_BYTES + 1)
        total += len(content)
        if (
            len(paths) >= MAX_CODE_FILES
            or len(content) > MAX_FILE_BYTES
            or total > MAX_CODE_BYTES
        ):
            raise ValueError("Local input exceeds the SAST source size limit")
        relative = path.relative_to(root)
        destination = staged / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        paths.add(relative.as_posix())
    return paths


def _scan_traversal(root: Path) -> dict:
    with TemporaryDirectory(prefix="vega-p2-sast-") as directory:
        staged = Path(directory) / "source"
        staged.mkdir()
        expected = _stage_sources(root, staged)
        if not expected:
            return {"status": "no_source", "scanned_files": 0, "findings": []}
        raw = staged.parent / "semgrep.json"
        run_semgrep(staged, raw, extra_rules=PROFILE_RULES, timeout=180)
        findings = parse_semgrep_json(raw)
        payload = json.loads(raw.read_text(encoding="utf-8-sig"))

        def relative(name: str) -> str:
            return Path(name).relative_to(staged).as_posix()

        scanned = {relative(name) for name in payload["paths"]["scanned"]}
        if scanned != expected:
            raise ValueError("Semgrep did not cover all selected source files")
        hints = []
        for finding in findings:
            if finding.category not in {"path-traversal", "local-file-inclusion"}:
                continue
            path, line = finding.location.rsplit(":", 1)
            hints.append(
                {
                    "path": relative(path),
                    "line": int(line),
                    "rule": finding.title,
                    "category": finding.category,
                    "http_verified": False,
                }
            )
        return {
            "status": "completed",
            "scanned_files": len(scanned),
            "findings": sorted(hints, key=lambda h: (h["path"], h["line"], h["rule"])),
        }


def inspect(task: str, source: Path | None) -> dict:
    """Return local hints; the caller owns all live VEGA actions."""
    if task not in TASKS:
        raise ValueError(f"Unsupported task: {task}")
    stages = {
        "http_discovery": {"status": "not_implemented", "owner": "DAST"},
        "secret_extraction": {"status": "not_implemented", "owner": "VEGA runtime"},
        "flag_write": {"status": "not_implemented", "owner": "VEGA runtime"},
    }
    result = {"task": task, "scope": "sast_only", "stages": stages}
    if source is None:
        return {**result, "sast": {"status": "no_source"}}
    root = validate_source_path(str(source))
    if not root.is_dir():
        raise ValueError("VEGA SAST source must be a local directory")
    result["sast"] = _scan_traversal(root) if task == "p2z1" else _inspect_backups(root)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", choices=TASKS)
    parser.add_argument("--source", type=Path, help="Local sources or deployment tree")
    args = parser.parse_args()
    source = args.source
    if source is None and (task_dir := os.environ.get("VEGA_TASK_DIR")):
        materials = Path(task_dir) / "materials"
        if materials.is_dir():
            source = materials
    try:
        report = inspect(args.task, source)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"SAST failed: {exc}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
