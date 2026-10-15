"""Tests for SQLi taint-analysis rules and fixtures."""

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

RULE_IDS = {
    "javascript-sql-tainted-query",
    "python-sql-tainted-execute",
    "php-sql-tainted-query",
}


def test_new_sqli_taint_rules() -> None:
    path = ROOT / "config/semgrep.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    rules = {rule["id"]: rule for rule in data["rules"]}

    assert RULE_IDS <= set(rules)

    for rule_id in RULE_IDS:
        rule = rules[rule_id]

        assert rule["mode"] == "taint"
        assert rule["metadata"]["category"] == "sql-injection"
        assert rule["pattern-sources"]
        assert rule["pattern-sinks"]

        assert rule["pattern-sinks"][0]["patterns"][1] == {
            "focus-metavariable": "$SQL"
        }


def test_sqli_taint_fixtures() -> None:
    path = ROOT / "config/expected/sast-contours.json"
    expected = json.loads(path.read_text(encoding="utf-8"))

    titles = {item["title"] for item in expected}

    assert len(expected) == 6
    assert len(titles) == 6
    assert RULE_IDS <= titles

    for extension in ("js", "py", "php"):
        for prefix in ("vulnerable", "benign"):
            fixture = (
                ROOT
                / "targets"
                / "sast-contours"
                / f"{prefix}-sqli-taint.{extension}"
            )

            assert fixture.is_file()