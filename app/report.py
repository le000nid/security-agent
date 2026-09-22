"""Markdown report generation."""

import json
import re
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from app.models import SEVERITY_ORDER, Finding, finding_sort_key


def _inline(value: str) -> str:
    value = escape(value).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_[\]{}()|])", r"\\\1", value)


def generate_markdown_report(
    findings: list[Finding], target_url: str, output_path: Path
) -> None:
    """Create a compact, human-readable report."""

    ordered_findings = sorted(findings, key=finding_sort_key)
    counts = Counter(finding.severity for finding in ordered_findings)
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Security Scan Report",
        "",
        f"- Scope: {_inline(target_url)}",
        f"- Generated (UTC): `{generated_at}`",
        f"- Findings: **{len(findings)}**",
        "",
        "## Severity summary",
        "",
    ]
    if counts:
        lines.extend(
            f"- {severity}: {counts[severity]}"
            for severity in SEVERITY_ORDER
            if counts[severity]
        )
    else:
        lines.append("No findings were reported by the selected scanners.")

    lines.extend(["", "## Findings", ""])
    if ordered_findings:
        lines.extend(
            [
                "| Severity | Title | Source / Tool | Location |",
                "| --- | --- | --- | --- |",
            ]
        )
        for finding in ordered_findings:
            lines.append(
                "| "
                + " | ".join(
                    _inline(value)
                    for value in (
                        finding.severity,
                        finding.title,
                        f"{finding.source} / {finding.tool}",
                        finding.location,
                    )
                )
                + " |"
            )
    else:
        lines.append("No findings to display.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    for finding in ordered_findings:
        category_lines = [f"- Scanner category: {_inline(finding.category)}"]
        if finding.normalized_category is not None:
            category_lines.append(
                f"- Normalized category: {_inline(finding.normalized_category)}"
            )
        lines.extend(
            [
                "",
                f"### [{_inline(finding.severity.upper())}] {_inline(finding.title)}",
                "",
                f"- Source / tool: {_inline(finding.source)} / {_inline(finding.tool)}",
                *category_lines,
                f"- Confidence: {_inline(finding.confidence)}",
                f"- Location: {_inline(finding.location)}",
                f"- Raw reference: {_inline(finding.raw_output_ref)}",
                "",
                "Description: " + _inline(finding.description),
                "",
                "Recommendation: " + _inline(finding.recommendation),
            ]
        )
        if finding.evidence:
            lines.extend(["", "Evidence: " + _inline(finding.evidence)])
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def save_summary(
    findings,
    mode,
    target,
    source,
    rationales,
    path: Path,
    *,
    llm_status="disabled",
    llm=None,
    llm_usage=None,
    llm_error=None,
) -> None:
    severity_counts = Counter(f.severity for f in findings)
    source_counts = Counter(f.source for f in findings)
    payload = {
        "version": "0.2.2",
        "mode": mode,
        "status": "completed",
        "target_url": target,
        "source_path": str(source) if source else None,
        "total": len(findings),
        "by_source": {name: source_counts[name] for name in sorted(source_counts)},
        "by_severity": {
            severity: severity_counts[severity]
            for severity in SEVERITY_ORDER
            if severity_counts[severity]
        },
        "llm_rationales": {
            finding_id: rationales[finding_id] for finding_id in sorted(rationales)
        },
        "llm_status": llm_status,
        "llm": llm,
        "llm_usage": (
            llm_usage.model_dump()
            if hasattr(llm_usage, "model_dump")
            else llm_usage
            or {
                "requests": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }
        ),
    }
    if llm_error:
        payload["llm_error"] = llm_error
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
