import json
from pathlib import Path

import yaml

from app.semgrep import RULES, parse_semgrep_json
from benchmark.evaluator import evaluate

ROOT = Path(__file__).resolve().parent.parent


def test_semgrep_rules_are_curated_local_rules() -> None:
    config = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    rules = config["rules"]
    assert 6 <= len(rules) <= 10
    assert len({rule["id"] for rule in rules}) == len(rules)
    for rule in rules:
        assert rule["languages"]
        assert rule["metadata"]["category"]
        assert rule["metadata"]["confidence"] in {"LOW", "MEDIUM", "HIGH"}
        assert rule["metadata"]["recommendation"]


def test_expected_semgrep_results_normalize_for_sample_target(tmp_path: Path) -> None:
    expected = json.loads(
        (ROOT / "benchmark/expected_findings.json").read_text(encoding="utf-8")
    )
    results = []
    for index, item in enumerate(expected, start=1):
        results.append(
            {
                "check_id": item["title"],
                "path": "targets/sample-app/app.py",
                "start": {"line": index, "col": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "Educational fixture",
                    "lines": "short evidence",
                    "metadata": {
                        "category": item["category"],
                        "confidence": "HIGH",
                    },
                },
            }
        )
    raw = tmp_path / "raw_semgrep.json"
    raw.write_text(json.dumps({"results": results, "errors": []}), encoding="utf-8")
    findings = parse_semgrep_json(raw)
    assert {finding.title for finding in findings} == {
        item["title"] for item in expected
    }


def test_benchmark_evaluator_reports_missed_and_unexpected() -> None:
    expected = [
        {"tool": "semgrep", "title": "a", "source": "SAST", "category": "one"},
        {"tool": "semgrep", "title": "b", "source": "SAST", "category": "two"},
    ]
    actual = [
        expected[0],
        {"tool": "semgrep", "title": "c", "source": "SAST", "category": "three"},
        {"tool": "nuclei", "title": "d", "source": "DAST", "category": "headers"},
    ]
    result = evaluate(actual, expected)
    assert result["expected_count"] == 2
    assert result["detected_expected_count"] == 1
    assert [item["title"] for item in result["missed_findings"]] == ["b"]
    assert [item["title"] for item in result["unexpected_findings"]] == ["c"]
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5


def test_compose_agent_is_non_published_and_mounts_targets() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    agent = compose["services"]["agent"]
    assert "ports" not in agent
    assert "./targets:/targets:ro" in agent["volumes"]
    assert agent["image"] == "${AGENT_IMAGE:-ai-security-agent:0.4.1}"
