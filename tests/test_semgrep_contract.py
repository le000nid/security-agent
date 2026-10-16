"""Reject incomplete or contradictory scanner output before reporting success."""

import copy
import json

import pytest

from app.semgrep import parse_semgrep_json


@pytest.fixture
def payload():
    return {
        "results": [
            {
                "check_id": "config.php-local-file-inclusion",
                "path": "source.php",
                "start": {"line": 3, "col": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "HTTP input reaches inclusion",
                    "metadata": {
                        "category": "local-file-inclusion",
                        "confidence": "HIGH",
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["source.php"]},
        "skipped_rules": [],
    }


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_errors",
        "null_errors",
        "wrong_errors_type",
        "missing_paths",
        "null_paths",
        "empty_scan",
        "wrong_scanned_type",
        "bad_scanned_entry",
        "skipped_rule",
    ],
)
def test_incomplete_scan_cannot_be_reported_clean(tmp_path, payload, scenario):
    payload["results"] = []
    if scenario == "missing_errors":
        payload.pop("errors")
    elif scenario == "null_errors":
        payload["errors"] = None
    elif scenario == "wrong_errors_type":
        payload["errors"] = {}
    elif scenario == "missing_paths":
        payload.pop("paths")
    elif scenario == "null_paths":
        payload["paths"] = None
    elif scenario == "empty_scan":
        payload["paths"]["scanned"] = []
    elif scenario == "wrong_scanned_type":
        payload["paths"]["scanned"] = "source.php"
    elif scenario == "bad_scanned_entry":
        payload["paths"]["scanned"] = [None]
    elif scenario == "skipped_rule":
        payload["skipped_rules"] = [{"rule_id": "php-local-file-inclusion"}]
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        parse_semgrep_json(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("check_id", None),
        ("check_id", ""),
        ("path", None),
        ("path", "not-scanned.php"),
        ("start", {"line": 0, "col": 1}),
        ("start", {"line": -1, "col": 1}),
        ("start", {"line": True, "col": 1}),
        ("start", {"line": 3, "col": False}),
    ],
)
def test_invalid_finding_identity_is_rejected(tmp_path, payload, field, value):
    payload["results"][0][field] = value
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        parse_semgrep_json(raw)


@pytest.mark.parametrize("field", ["results", "errors"])
def test_duplicate_top_level_fields_are_rejected(tmp_path, payload, field):
    text = json.dumps(payload)
    duplicate = text[:-1] + f', "{field}": []' + "}"
    raw = tmp_path / "raw.json"
    raw.write_text(duplicate, encoding="utf-8")
    with pytest.raises(ValueError):
        parse_semgrep_json(raw)


def test_valid_clean_scan_requires_scanned_files(tmp_path, payload):
    payload["results"] = []
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(payload), encoding="utf-8")
    assert parse_semgrep_json(raw) == []


def test_valid_unicode_path_and_bom_are_accepted(tmp_path, payload):
    payload = copy.deepcopy(payload)
    payload["paths"]["scanned"] = ["учебный файл.php"]
    payload["results"][0]["path"] = "учебный файл.php"
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8-sig")
    result = parse_semgrep_json(raw)
    assert result[0].location == "учебный файл.php:3"
