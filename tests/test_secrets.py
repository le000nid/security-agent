"""Reject incomplete secret scans, false positives and incorrect locations."""

import copy
import json
import shutil

import pytest

from app.benchmarks import BenchmarkRegistry
from app.semgrep import parse_semgrep_json
from benchmark import verify_secrets as checker


@pytest.fixture
def report():
    prefix = "/targets/sast-secrets/"
    return {
        "errors": [],
        "paths": {"scanned": [prefix + name for name in sorted(checker.FILES)]},
        "results": [
            {
                "path": prefix + name,
                "check_id": "config." + rule,
                "start": {"line": line, "col": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "Synthetic candidate, requires review",
                    "metadata": {"category": "secrets", "confidence": "MEDIUM"},
                },
            }
            for name, rule, line in checker.expectations().elements()
        ],
    }


def test_exact_report_and_production_normalization(report, tmp_path):
    assert checker.verify(report) == {
        "files": 16,
        "candidate_cases": 12,
        "clean_files": 8,
        "findings": 12,
    }
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(report), encoding="utf-8")
    findings = parse_semgrep_json(raw)
    assert len(findings) == 12
    assert all(f.category == "secrets" and f.confidence == "medium" for f in findings)
    assert all(f.location.rsplit(":", 1)[1].isdigit() for f in findings)
    assert len({f.id for f in findings}) == len(findings)


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_finding",
        "duplicate_finding",
        "false_positive",
        "wrong_rule",
        "wrong_line",
        "missing_file",
        "duplicate_file",
        "scan_error",
        "missing_errors",
        "skipped_rules",
        "wrong_results_type",
    ],
)
def test_regressions_are_rejected(report, scenario):
    payload = copy.deepcopy(report)
    if scenario == "missing_finding":
        payload["results"].pop()
    elif scenario == "duplicate_finding":
        payload["results"].append(copy.deepcopy(payload["results"][0]))
    elif scenario == "false_positive":
        item = copy.deepcopy(payload["results"][0])
        item["path"] = item["path"].replace("vulnerable-", "benign-")
        payload["results"].append(item)
    elif scenario == "wrong_rule":
        payload["results"][0]["check_id"] = "config.unrelated-rule"
    elif scenario == "wrong_line":
        payload["results"][0]["start"]["line"] += 1
    elif scenario == "missing_file":
        payload["paths"]["scanned"].pop()
    elif scenario == "duplicate_file":
        payload["paths"]["scanned"].append(payload["paths"]["scanned"][0])
    elif scenario == "scan_error":
        payload["errors"] = [{"message": "injected timeout"}]
    elif scenario == "missing_errors":
        payload.pop("errors")
    elif scenario == "skipped_rules":
        payload["skipped_rules"] = [{"rule_id": checker.TEXT}]
    else:
        payload["results"] = None
    with pytest.raises((ValueError, TypeError)):
        checker.verify(payload)


def test_missing_clean_fixture_is_rejected(tmp_path):
    fixtures = tmp_path / "sast-secrets"
    shutil.copytree(checker.FIXTURES, fixtures)
    (fixtures / "benign-notes.txt").unlink()
    with pytest.raises(ValueError, match="inventory mismatch"):
        checker.expectations(fixtures)


def test_registry_exposes_source_only_benchmark():
    benchmark = BenchmarkRegistry.load().get("sast-secrets")
    assert benchmark.resolve_mode() == "sast"
    assert benchmark.ui_metadata()["baseline_count"] == 4
    assert benchmark.target_url is None
    assert benchmark.docker_service is None


def test_cli_accepts_bom(report, monkeypatch, tmp_path, capsys):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(report), encoding="utf-8-sig")
    monkeypatch.setattr("sys.argv", ["verify_secrets", str(raw)])
    checker.main()
    assert "Secret candidates passed" in capsys.readouterr().out


def test_cli_rejects_broken_json(monkeypatch, tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["verify_secrets", str(raw)])
    with pytest.raises(SystemExit) as error:
        checker.main()
    assert error.value.code == 1
