"""The acceptance checker must reject incomplete scans and false positives."""

import copy
import json
from collections import Counter

import pytest

from benchmark import verify_sqli_variants as checker


@pytest.fixture
def report():
    expected, _ = checker.expectations()
    prefix = "/targets/sast-sqli-variants/"
    return {
        "errors": [],
        "paths": {"scanned": [prefix + name for name in sorted(checker.FILES)]},
        "results": [
            {
                "path": prefix + name,
                "check_id": "config." + rule,
                "start": {"line": line},
            }
            for name, rule, line in expected.elements()
        ],
    }


def test_variant_inventory_has_fourteen_dangerous_and_safe_cases():
    expected, safe = checker.expectations()
    assert expected.total() == safe.total() == 14
    assert {name for name, _, _ in expected} == {
        name for name in checker.FILES if name.startswith("vulnerable-")
    }
    assert Counter(rule for _, rule, _ in expected.elements()) == Counter(
        rule for _, rule, _ in safe.elements()
    )


def test_complete_report_is_accepted(report):
    assert checker.verify(report) == {
        "files": 8,
        "dangerous_cases": 14,
        "safe_cases": 14,
        "findings": 14,
    }


def test_scanned_documentation_does_not_replace_source_fixtures(report):
    report["paths"]["scanned"].append("/targets/sast-sqli-variants/README.md")
    assert checker.verify(report)["findings"] == 14
    report["paths"]["scanned"].pop(0)
    with pytest.raises(ValueError, match="Not all expected fixtures"):
        checker.verify(report)


def test_finding_in_documentation_is_not_silently_ignored(report):
    report["paths"]["scanned"].append("/targets/sast-sqli-variants/README.md")
    item = copy.deepcopy(report["results"][0])
    item["path"] = "/targets/sast-sqli-variants/README.md"
    report["results"].append(item)
    with pytest.raises(ValueError, match="Unexpected scan path"):
        checker.verify(report)


def test_duplicate_documentation_scan_is_rejected(report):
    report["paths"]["scanned"].extend(["/targets/sast-sqli-variants/README.md"] * 2)
    with pytest.raises(ValueError, match="Not all expected fixtures"):
        checker.verify(report)


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
    elif scenario == "wrong_results_type":
        payload["results"] = None
    with pytest.raises((ValueError, TypeError)):
        checker.verify(payload)


def test_cli_accepts_utf8_bom(report, monkeypatch, tmp_path, capsys):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(report), encoding="utf-8-sig")
    monkeypatch.setattr("sys.argv", ["verify_sqli_variants", str(raw)])
    checker.main()
    assert "SQLi variants passed" in capsys.readouterr().out


def test_cli_rejects_broken_json(monkeypatch, tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["verify_sqli_variants", str(raw)])
    with pytest.raises(SystemExit) as error:
        checker.main()
    assert error.value.code == 1
