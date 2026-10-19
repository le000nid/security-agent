import copy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from benchmark.verify_nosqli_run import verify


def completed_run():
    findings = []
    for source, title, count in [
        ("SAST", "javascript-nosqli-scalar-operator", 1),
        ("SAST", "javascript-nosqli-untrusted-filter", 2),
        ("DAST", "MongoDB scalar operator injection", 1),
        ("DAST", "MongoDB untrusted filter injection", 1),
        ("DAST", "MongoDB server scope overwrite", 1),
    ]:
        findings.extend(
            {
                "source": source,
                "title": title,
                "evidence": "baseline=one; changed=two; control=[]",
                "raw_output_ref": "logs/scanner.json",
            }
            for _ in range(count)
        )
    summary = {
        "benchmark_id": "nosqli-mongo-full",
        "mode": "full",
        "status": "completed",
        "same_application": True,
        "benchmark_evaluation": {
            "expected_count": 5,
            "detected_expected_count": 5,
            "missed_findings": [],
            "unexpected_findings": [],
        },
        "llm_usage": {"total": {"requests": 0}},
    }
    return summary, findings


def test_acceptance_counts_instances_not_only_unique_rule_types():
    summary, findings = completed_run()
    repository = Mock()
    repository.latest.return_value = "run-id"
    repository.summary.return_value = summary
    repository.findings.return_value = findings
    assert verify(repository)["sast"] == 3
    repository.findings.return_value = findings[:1] + findings[2:]
    with pytest.raises(ValueError, match="six scenario findings"):
        verify(repository)


def test_expected_sast_categories_match_semgrep_metadata():
    root = Path(__file__).resolve().parents[2]
    baseline = json.loads(
        (root / "config/expected/nosqli-mongo-full.json").read_text(encoding="utf-8")
    )
    categories = {item["category"] for item in baseline if item["tool"] == "semgrep"}
    assert categories == {"nosql-injection"}


@pytest.mark.parametrize("failure", ["failed", "missing-type", "llm", "evidence"])
def test_incomplete_runs_cannot_be_reported_as_passed(failure):
    summary, findings = completed_run()
    summary, findings = copy.deepcopy(summary), copy.deepcopy(findings)
    if failure == "failed":
        summary["status"] = "failed"
    elif failure == "missing-type":
        summary["benchmark_evaluation"]["detected_expected_count"] = 4
    elif failure == "llm":
        summary["llm_usage"]["total"]["requests"] = 1
    else:
        findings[-1]["evidence"] = "template-id only"
    repository = Mock()
    repository.summary.return_value = summary
    repository.findings.return_value = findings
    with pytest.raises(ValueError):
        verify(repository)
