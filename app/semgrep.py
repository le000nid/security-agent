"""Local rules only; no autofix, registry, or build execution."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from app.models import Finding
from app.scanner_env import scanner_environment
from app.validation import validate_source_path

RULES = Path(__file__).resolve().parent.parent / "config/semgrep.yaml"


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


def parse_semgrep_json(path: Path) -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Invalid Semgrep JSON: expected results array")
    if payload.get("errors"):
        raise ValueError("Semgrep reported scan errors; inspect logs/raw_semgrep.json")
    findings = []
    for index, record in enumerate(payload["results"]):
        try:
            extra = record["extra"]
            metadata = extra.get("metadata") or {}
            rule_id = str(record["check_id"]).rsplit(".", 1)[-1]
            severity = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}.get(
                extra["severity"], extra["severity"].lower()
            )
            location = f"{record['path']}:{record['start']['line']}"
            identity = f"{rule_id}:{location}:{record['start'].get('col', 0)}"
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
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"Malformed Semgrep result {index}") from exc
    return findings
