"""LFI coverage and rejection checks for the real-scan acceptance verifier."""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from benchmark import verify_lfi_variants as checker


@pytest.fixture
def report():
    expected, _ = checker.expectations()
    prefix = "/targets/sast-lfi-variants/"
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


def test_lfi_inventory_and_rule_category():
    expected, safe = checker.expectations()
    assert expected.total() == safe.total() == 14
    assert len(checker.FILES) == 10
    assert Counter(rule for _, rule, _ in expected.elements()) == {
        "php-local-file-inclusion": 14
    }
    config = Path(__file__).resolve().parents[1] / "config/semgrep.yaml"
    rules = yaml.safe_load(config.read_text(encoding="utf-8"))["rules"]
    rule = next(rule for rule in rules if rule["id"] == "php-local-file-inclusion")
    assert rule["metadata"]["category"] == "local-file-inclusion"


def test_complete_lfi_report_is_accepted(report):
    assert checker.verify(report) == {
        "files": 10,
        "dangerous_cases": 14,
        "safe_cases": 14,
        "findings": 14,
    }


@pytest.mark.parametrize(
    "scenario", ["miss", "safe_mapping", "scan_error", "missing_file", "rfi_rule"]
)
def test_lfi_regressions_are_rejected(report, scenario):
    if scenario == "miss":
        report["results"].pop()
    elif scenario == "safe_mapping":
        report["results"][0]["path"] = "/targets/sast-lfi-variants/benign-mappings.php"
    elif scenario == "scan_error":
        report["errors"] = [{"message": "injected timeout"}]
    elif scenario == "missing_file":
        report["paths"]["scanned"].pop()
    elif scenario == "rfi_rule":
        report["results"][0]["check_id"] = "config.php-remote-file-inclusion"
    with pytest.raises(ValueError):
        checker.verify(report)


def test_lfi_cli_reads_bom(report, monkeypatch, tmp_path, capsys):
    raw = tmp_path / "lfi.json"
    raw.write_text(json.dumps(report), encoding="utf-8-sig")
    monkeypatch.setattr("sys.argv", ["verify_lfi_variants", str(raw)])
    checker.main()
    assert "LFI variants passed" in capsys.readouterr().out
