"""Local rules only; no autofix, registry, or build execution."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from app.models import Finding
from app.resources import config_directory
from app.scanner_env import scanner_environment
from app.validation import validate_source_path

RULES = config_directory() / "semgrep.yaml"


def _evidence(extra: dict) -> str:
    """Prefer a short matched line; fall back to the scanner's rule message."""

    lines = extra.get("lines")
    if isinstance(lines, str):
        snippet = " ".join(lines.split()).strip()
        if snippet and snippet.casefold() != "requires login":
            return snippet[:500]
    message = extra.get("message")
    return str(message).strip()[:500] if message else "Semgrep rule matched"


def run_semgrep(source: Path, output: Path) -> None:
    source = validate_source_path(str(source))
    executable = shutil.which("semgrep")
    if not executable:
        raise ValueError("semgrep was not found on PATH; use the agent Docker image")
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("w", encoding="utf-8") as raw,
        TemporaryDirectory(prefix="semgrep-lab-") as home,
    ):
        try:
            result = subprocess.run(
                [
                    executable,
                    "scan",
                    "--config",
                    str(RULES),
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--strict",
                    "--disable-nosem",
                    str(source),
                ],
                stdout=raw,
                stderr=subprocess.PIPE,
                text=True,
                timeout=900,
                check=False,
                env=scanner_environment(home),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Semgrep execution failed") from exc
    if result.returncode != 0:
        raise ValueError(f"Semgrep failed (exit {result.returncode}); inspect logs/")


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field in Semgrep output")
        result[key] = value
    return result


def _scanned_paths(payload: dict) -> set[str]:
    if not isinstance(payload.get("errors"), list):
        raise ValueError("Invalid Semgrep JSON: expected errors array")
    if payload["errors"]:
        raise ValueError("Semgrep reported scan errors; inspect logs/raw_semgrep.json")
    paths = payload.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("Invalid Semgrep JSON: expected scanned paths array")
    scanned = paths["scanned"]
    if not scanned:
        raise ValueError(
            "Semgrep scanned no source files; check source and scan filters"
        )
    if any(not isinstance(item, str) or not item or "\x00" in item for item in scanned):
        raise ValueError("Invalid Semgrep scanned path")
    if "skipped_rules" in payload and payload["skipped_rules"] != []:
        raise ValueError("Semgrep skipped configured rules; inspect raw output")
    return set(scanned)


def _finding_identity(record, scanned: set[str]) -> tuple[str, str, int, int]:
    if not isinstance(record, dict):
        raise ValueError("Invalid Semgrep finding object")
    rule = record.get("check_id")
    source = record.get("path")
    start = record.get("start")
    if not isinstance(rule, str) or not rule.strip() or not rule.rsplit(".", 1)[-1]:
        raise ValueError("Invalid Semgrep rule ID")
    if not isinstance(source, str) or source not in scanned:
        raise ValueError("Semgrep finding refers to a file not scanned")
    if not isinstance(start, dict):
        raise ValueError("Invalid Semgrep finding position")
    line, column = start.get("line"), start.get("col", 0)
    if type(line) is not int or line < 1:
        raise ValueError("Invalid Semgrep finding line")
    if type(column) is not int or column < (1 if "col" in start else 0):
        raise ValueError("Invalid Semgrep finding column")
    return rule.rsplit(".", 1)[-1], source, line, column


def parse_semgrep_json(path: Path) -> list[Finding]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_json_object
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid Semgrep JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Invalid Semgrep JSON: expected results array")
    scanned = _scanned_paths(payload)
    findings = []
    for index, record in enumerate(payload["results"]):
        try:
            rule_id, source, line, column = _finding_identity(record, scanned)
            extra = record["extra"]
            metadata = extra.get("metadata")
            if metadata is None:
                metadata = {}
            if not isinstance(metadata, dict):
                raise ValueError("Invalid Semgrep finding metadata")
            severity = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}.get(
                extra["severity"], extra["severity"].lower()
            )
            location = f"{source}:{line}"
            identity = f"{rule_id}:{location}:{column}"
            findings.append(
                Finding(
                    id="semgrep:" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                    title=rule_id,
                    source="SAST",
                    tool="semgrep",
                    severity=severity,
                    confidence=metadata.get("confidence", "unknown").lower(),
                    category=metadata.get("category", "uncategorized"),
                    location=location,
                    evidence=_evidence(extra),
                    description=extra["message"],
                    recommendation=metadata.get(
                        "recommendation", "Review the indicated code and rule guidance."
                    ),
                    raw_output_ref=f"{path.as_posix()}#/results/{index}",
                )
            )
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise ValueError(f"Malformed Semgrep result {index}") from exc
    return findings
