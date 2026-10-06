import json
from pathlib import Path

from app.llm import LLMUsage
from app.models import Finding
from app.report import generate_markdown_report, save_summary


def test_generate_markdown_report(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    finding = Finding(
        id="headers",
        title="Missing header",
        source="DAST",
        tool="nuclei",
        raw_output_ref="logs/raw_nuclei.jsonl#L1",
        severity="info",
        location="http://localhost:3000",
    )

    generate_markdown_report([finding], "http://localhost:3000", output)

    report = output.read_text(encoding="utf-8")
    assert "# Security Scan Report" in report
    assert "Missing header" in report
    assert "Findings: **1**" in report
    for value in (
        "Severity",
        "Source / tool",
        "Scanner category",
        "Confidence",
        "Location",
        "Description",
        "Recommendation",
        "Raw reference",
    ):
        assert value in report


def test_report_displays_normalized_category_only_when_available(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.md"
    enriched = Finding(
        id="cors",
        title="Wildcard CORS",
        source="DAST",
        tool="nuclei",
        category="misconfig",
        normalized_category="cors",
        raw_output_ref="logs/raw_nuclei.jsonl#L1",
    )
    scanner_only = Finding(
        id="headers",
        title="Missing header",
        source="DAST",
        tool="nuclei",
        category="headers",
        raw_output_ref="logs/raw_nuclei.jsonl#L2",
    )

    generate_markdown_report([enriched, scanner_only], "http://localhost:3000", output)

    report = output.read_text(encoding="utf-8")
    assert "Scanner category: misconfig" in report
    assert "Normalized category: cors" in report
    assert scanner_only.normalized_category is None


def test_canonical_severity_order_in_report_and_summary(tmp_path: Path) -> None:
    severities = ["unknown", "info", "low", "medium", "high", "critical"]
    findings = [
        Finding(
            id=severity,
            title=severity,
            source="DAST",
            tool="nuclei",
            severity=severity,
            raw_output_ref=f"logs/raw_nuclei.jsonl#{severity}",
        )
        for severity in severities
    ]
    report_path = tmp_path / "report.md"
    summary_path = tmp_path / "summary.json"
    generate_markdown_report(findings, "http://localhost:3000", report_path)
    save_summary(findings, "dast", "http://localhost:3000", None, {}, summary_path)

    report = report_path.read_text(encoding="utf-8")
    positions = [report.index(f"- {severity}: 1") for severity in reversed(severities)]
    assert positions == sorted(positions)
    table_positions = [
        report.index(f"| {severity} | {severity} |")
        for severity in reversed(severities)
    ]
    assert table_positions == sorted(table_positions)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert list(summary["by_severity"]) == list(reversed(severities))
    assert summary["version"] == "0.4.1"
    assert summary["llm"] is None
    assert summary["llm_usage"] == {
        "requests": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }


def test_summary_contains_non_sensitive_llm_metadata_and_usage(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    usage = LLMUsage(
        requests=2, prompt_tokens=100, completion_tokens=20, total_tokens=120
    )
    metadata = {
        "provider": "openai_compatible",
        "base_url": "https://deepcode.ci.nsu.ru/api",
        "model": "deepseek-ai/DeepSeek-V4-Flash-0731",
        "model_available": True,
    }
    save_summary(
        [],
        "dast",
        "http://localhost:3000",
        None,
        {},
        summary_path,
        llm_status="completed",
        llm=metadata,
        llm_usage=usage,
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["llm"] == metadata
    assert summary["llm_usage"] == usage.model_dump()
    assert "api_key" not in json.dumps(summary).lower()
