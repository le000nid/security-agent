"""Exact acceptance checks for synthetic secret candidates, not CTF solving."""

import argparse
import json
from collections import Counter
from pathlib import Path

from benchmark.annotated_scan import fixture_name

FIXTURES = Path(__file__).resolve().parents[1] / "targets/sast-secrets"
PYTHON = "python-obvious-hardcoded-secret"
JAVASCRIPT = "javascript-obvious-hardcoded-secret"
TEXT = "generic-labeled-secret-candidate"
PEM = "generic-pem-private-key-candidate"
# Independently specified file/rule/line expectations, including clean controls.
CASES = {
    "vulnerable-source.py": [(PYTHON, 2), (PYTHON, 3)],
    "vulnerable-source.js": [(JAVASCRIPT, 2), (JAVASCRIPT, 3)],
    "vulnerable-source.ts": [(JAVASCRIPT, 2)],
    "vulnerable-notes.txt": [(TEXT, 2), (TEXT, 3)],
    "vulnerable-settings.json": [(TEXT, 2), (TEXT, 3)],
    "vulnerable-settings.yaml": [(TEXT, 2)],
    "vulnerable-settings.ini": [(TEXT, 2)],
    "vulnerable-key.pem": [(PEM, 1)],
    "benign-source.py": [],
    "benign-source.js": [],
    "benign-source.ts": [],
    "benign-notes.txt": [],
    "benign-settings.json": [],
    "benign-settings.yaml": [],
    "benign-settings.ini": [],
    "benign-key.pem": [],
}
FILES = set(CASES)


def expectations(fixtures=FIXTURES):
    present = {path.name for path in fixtures.iterdir() if path.is_file()}
    if present != FILES:
        raise ValueError(f"Fixture inventory mismatch: {sorted(present ^ FILES)}")
    expected = Counter()
    for name, entries in CASES.items():
        lines = (fixtures / name).read_text(encoding="utf-8").splitlines()
        for rule, line in entries:
            if line > len(lines) or not lines[line - 1].strip():
                raise ValueError(f"Missing fixture content: {name}:{line}")
            expected[(name, rule, line)] += 1
    return expected


def verify(payload, fixtures=FIXTURES):
    expected = expectations(fixtures)
    if not isinstance(payload, dict) or payload.get("errors") != []:
        raise ValueError("Missing errors array or Semgrep reported scan errors")
    if payload.get("skipped_rules", []) != []:
        raise ValueError("Semgrep skipped configured rules")
    scanned = payload["paths"]["scanned"]
    if not isinstance(scanned, list):
        raise TypeError("Expected a scanned paths array")
    if Counter(fixture_name(path, fixtures, FILES) for path in scanned) != Counter(
        FILES
    ):
        raise ValueError("Not all expected fixtures were scanned exactly once")
    if not isinstance(payload.get("results"), list):
        raise TypeError("Expected a results array")
    actual = Counter()
    for item in payload["results"]:
        line = item["start"]["line"]
        if type(line) is not int or line < 1:
            raise ValueError("Invalid finding line")
        actual[
            (
                fixture_name(item["path"], fixtures, FILES),
                item["check_id"].rsplit(".", 1)[-1],
                line,
            )
        ] += 1
    if actual != expected:
        raise ValueError(
            f"Missing: {list((expected - actual).elements())}; "
            f"unexpected: {list((actual - expected).elements())}"
        )
    return {
        "files": len(FILES),
        "candidate_cases": expected.total(),
        "clean_files": sum(not entries for entries in CASES.values()),
        "findings": actual.total(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.report.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"Secret candidates FAILED: {exc}\n")
    print("Secret candidates passed: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
