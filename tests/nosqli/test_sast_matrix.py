"""Acceptance verifier regressions. Real scanner acceptance runs in the Docker script."""

import copy
import json
from collections import Counter
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from pydantic import ValidationError

from app.benchmarks import BenchmarkRegistry
from app.config import Settings
from app.repository import RunRepository
from app.semgrep import parse_semgrep_json
from app.service import RunRequest, RunService
from benchmark.verify_nosqli_sast import MARKER
from benchmark.verify_nosqli_sast_matrix import (
    Case,
    validate_inventory,
    verify,
    verify_run,
)

ROOT = Path("targets/nosqli-variants")
INVENTORY = Path("config/nosqli-sast-cases.json")


def synthetic_payload(source: Path) -> dict:
    """Represent annotated locations to test the verifier, not scanner detection."""
    results = []
    scanned = sorted(p for p in source.rglob("*") if p.suffix in {".js", ".ts"})
    for file in scanned:
        for index, line in enumerate(file.read_text().splitlines()):
            marker = MARKER.fullmatch(line)
            if marker and marker[1] == "ruleid":
                results.append(
                    {
                        "path": str(file.resolve()),
                        "check_id": "config." + marker[2],
                        "start": {"line": index + 2, "col": 3},
                        "extra": {
                            "severity": "WARNING",
                            "message": "Review untrusted NoSQL query data.",
                            "metadata": {
                                "category": "injection",
                                "confidence": "MEDIUM",
                            },
                        },
                    }
                )
    return {
        "results": results,
        "errors": [],
        "paths": {"scanned": [str(f.resolve()) for f in scanned]},
    }


def inventory():
    return json.loads(INVENTORY.read_text())


def test_complete_inventory_and_reviewed_locations():
    data = inventory()
    result = verify(synthetic_payload(ROOT), ROOT, data)
    assert result["cases"] == 80
    assert result["findings"] == result["dangerous_cases"] == result["safe_cases"] == 40
    assert result["scanned_files"] == 8
    assert result["by_language"] == {".js": 40, ".ts": 40}
    assert len(result["by_rule"]) == 4
    assert all(
        counts == {"dangerous": 10, "safe": 10, "findings": 10}
        for counts in result["by_rule"].values()
    )


@pytest.mark.parametrize(
    "failure",
    [
        "missed",
        "safe-hit",
        "duplicate",
        "wrong-rule",
        "wrong-line",
        "unscanned-ts",
        "parse-error",
        "unexpected-file",
    ],
)
def test_imprecise_or_incomplete_results_fail(failure):
    payload = synthetic_payload(ROOT)
    if failure == "missed":
        payload["results"].pop()
    elif failure == "duplicate":
        payload["results"].append(copy.deepcopy(payload["results"][0]))
    elif failure == "wrong-rule":
        payload["results"][0]["check_id"] = "config.javascript-nosqli-wrong-rule"
    elif failure == "wrong-line":
        payload["results"][0]["start"]["line"] += 1
    elif failure == "unscanned-ts":
        payload["paths"]["scanned"] = [
            p for p in payload["paths"]["scanned"] if not p.endswith(".ts")
        ]
    elif failure == "parse-error":
        payload["errors"] = [{"message": "partial scan"}]
    elif failure == "unexpected-file":
        payload["paths"]["scanned"].append("outside.js")
    else:
        file = ROOT / "javascript/where.js"
        lines = file.read_text().splitlines()
        line = next(i + 2 for i, text in enumerate(lines) if "// ok:" in text)
        payload["results"].append(
            {
                **copy.deepcopy(payload["results"][0]),
                "path": str(file.resolve()),
                "start": {"line": line},
            }
        )
    with pytest.raises(ValueError):
        verify(payload, ROOT, inventory())


@pytest.mark.parametrize(
    "failure",
    [
        "empty",
        "duplicate-id",
        "duplicate-function",
        "missing-case",
        "wrong-function",
        "wrong-rule",
        "wrong-verdict",
        "unsafe-path",
    ],
)
def test_inventory_changes_cannot_hide_missing_coverage(failure):
    data = inventory()
    if failure == "empty":
        data = []
    elif failure == "duplicate-id":
        data[1]["id"] = data[0]["id"]
    elif failure == "duplicate-function":
        data.append(copy.deepcopy(data[0]))
    elif failure == "missing-case":
        data.pop()
    elif failure == "wrong-function":
        data[0]["function"] = "absent"
    elif failure == "wrong-rule":
        data[0]["rule"] = "javascript-nosqli-absent"
    elif failure == "wrong-verdict":
        data[0]["expected"] = False
    else:
        data[0]["file"] = "../outside.js"
    with pytest.raises(ValueError):
        validate_inventory(ROOT, data)


@pytest.mark.parametrize(
    "change",
    [
        {"expected": "false"},
        {"file": "/tmp/where.js"},
        {"file": "javascript//where.js"},
        {"file": "javascript/where.ts"},
        {"function": "a();"},
    ],
)
def test_strict_case_schema(change):
    with pytest.raises(ValidationError):
        Case.model_validate({**inventory()[0], **change})


def test_annotations_cannot_disappear(tmp_path):
    source = tmp_path / "corpus"
    (source / "javascript").mkdir(parents=True)
    (source / "javascript/a.js").write_text(
        "export function example(req, collection) {\n  return collection.find(req.body.filter);\n}\n"
    )
    data = [
        {
            "id": "example",
            "file": "javascript/a.js",
            "function": "example",
            "rule": "javascript-nosqli-untrusted-filter",
            "expected": True,
        }
    ]
    with pytest.raises(ValueError, match="annotation"):
        validate_inventory(source, data)


def test_non_nosqli_rules_are_preserved():
    rules = yaml.safe_load(Path("config/semgrep.yaml").read_text())["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert {
        "python-debug-enabled",
        "javascript-eval-usage",
        "javascript-obvious-hardcoded-secret",
    } <= set(ids)
    assert {c["rule"] for c in inventory()} <= set(ids)
    assert BenchmarkRegistry.load().get("nosqli-sast-matrix").resolve_mode() == "sast"


def test_service_preserves_exact_locations_in_common_reports(tmp_path, monkeypatch):
    payload = synthetic_payload(ROOT)
    monkeypatch.setattr(
        "app.service.Settings.from_env", lambda: Settings(llm_brief_enabled=False)
    )
    monkeypatch.setattr(
        "app.agent.tools.run_semgrep",
        lambda source, output: output.write_text(json.dumps(payload)),
    )
    no_llm = Mock(side_effect=AssertionError("No provider calls"))
    service = RunService(tmp_path / "runs", client_factory=no_llm)
    result = service.run(
        RunRequest(benchmark_id="nosqli-sast-matrix", mode="sast", llm_enabled=False)
    )
    checked = verify_run(tmp_path / "runs")
    assert checked["findings"] == 40 and checked["llm_requests"] == 0
    repo = RunRepository(tmp_path / "runs")
    findings = repo.json(result.run_id, "findings.json")
    assert Counter(f["title"] for f in findings) == {
        rule: 10 for rule in checked["by_rule"]
    }
    no_llm.assert_not_called()
    path = tmp_path / "runs" / result.run_id / "reports/findings.json"
    path.write_text(json.dumps(findings[:-1]))
    with pytest.raises(ValueError, match="lost or duplicated"):
        verify_run(tmp_path / "runs")


def test_normalization_keeps_rule_metadata_and_locations(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(synthetic_payload(ROOT)))
    findings = parse_semgrep_json(raw)
    assert len(findings) == 40
    assert all(
        f.source == "SAST"
        and f.tool == "semgrep"
        and f.category == "injection"
        and f.confidence == "medium"
        for f in findings
    )
