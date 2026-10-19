"""Verify a real Semgrep scan of the SQLi hardening fixtures."""

import argparse
import json
from collections import Counter
from pathlib import Path

EXPECTED = Counter(
    {
        ("vulnerable-django.py", "python-django-raw-sqli-taint", 9): 1,
        ("vulnerable-django.py", "python-django-raw-sqli-taint", 17): 1,
        ("vulnerable-knex.js", "javascript-knex-sqli-taint", 6): 1,
        ("vulnerable-knex.js", "javascript-knex-sqli-taint", 15): 1,
        ("vulnerable-prepare.php", "php-prepare-sqli-taint", 9): 1,
        ("vulnerable-prepare.php", "php-prepare-sqli-taint", 18): 1,
    }
)
FILES = {
    "benign-django.py",
    "vulnerable-django.py",
    "benign-knex.js",
    "vulnerable-knex.js",
    "benign-prepare.php",
    "vulnerable-prepare.php",
}


def fixture_name(value):
    path = Path(value.replace("\\", "/"))
    if path.parent.name != "sast-sqli-hardening" or path.name not in FILES:
        raise ValueError(f"Unexpected scan path: {value}")
    return path.name


def verify(payload):
    if not isinstance(payload, dict):
        raise TypeError("Expected a Semgrep JSON object")
    if payload.get("errors") != []:
        raise ValueError(f"Scan errors: {payload.get('errors')}")
    scanned = {fixture_name(p) for p in payload["paths"]["scanned"]}
    if scanned != FILES:
        raise ValueError(f"Missing scanned fixtures: {sorted(FILES - scanned)}")
    if not isinstance(payload.get("results"), list):
        raise TypeError("Expected a results array")
    actual = Counter(
        (
            fixture_name(item["path"]),
            item["check_id"].rsplit(".", 1)[-1],
            item["start"]["line"],
        )
        for item in payload["results"]
    )
    if actual != EXPECTED:
        raise ValueError(
            f"Missing findings: {list((EXPECTED - actual).elements())}; "
            f"unexpected findings: {list((actual - EXPECTED).elements())}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        verify(json.loads(args.report.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"SQLi hardening FAILED: {exc}\n")
    print("SQLi hardening passed: 6 exact findings, all 6 files scanned")


if __name__ == "__main__":
    main()
