"""Parsing and persistence for Nuclei output."""

import hashlib
import json
from pathlib import Path
from typing import Any

from app.models import Finding, finding_sort_key


class NucleiParseError(ValueError):
    """Raised when a Nuclei JSONL line is invalid."""


def _as_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def parse_nuclei_jsonl(path: Path) -> list[Finding]:
    """Normalize Nuclei JSONL records into Finding models."""

    findings: list[Finding] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NucleiParseError(
                    f"Invalid JSON in {path} at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(record, dict):
                raise NucleiParseError(
                    f"Expected a JSON object in {path} at line {line_number}"
                )

            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            findings.append(
                Finding(
                    id="nuclei:" + hashlib.sha256(line.encode()).hexdigest()[:20],
                    title=str(
                        info.get("name") or record.get("name") or "Unnamed finding"
                    ),
                    source="DAST",
                    tool="nuclei",
                    severity=str(
                        info.get("severity") or record.get("severity") or "unknown"
                    ).lower(),
                    location=str(
                        record.get("matched-at")
                        or record.get("matched_at")
                        or record.get("host")
                        or ""
                    ),
                    evidence=str(
                        record.get("matcher-name") or record.get("template-id") or ""
                    ),
                    description=info.get("description")
                    or record.get("description")
                    or "",
                    category=", ".join(_as_tags(info.get("tags"))) or "uncategorized",
                    recommendation=info.get("remediation")
                    or "Review the HTTP configuration.",
                    raw_output_ref=f"{path.as_posix()}#L{line_number}",
                )
            )
    return findings


def save_findings(findings: list[Finding], path: Path) -> None:
    """Write normalized findings as formatted JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        finding.model_dump(mode="json")
        for finding in sorted(findings, key=finding_sort_key)
    ]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
