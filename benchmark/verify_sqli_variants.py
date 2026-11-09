"""Check real Semgrep findings against independently annotated SQLi cases."""

import argparse
import json
from pathlib import Path

from benchmark import annotated_scan

FIXTURES = Path(__file__).resolve().parents[1] / "targets/sast-sqli-variants"
FILES = {
    f"{kind}-http.{extension}"
    for kind in ("benign", "vulnerable")
    for extension in ("js", "ts", "py", "php")
}


def expectations(fixtures=FIXTURES):
    return annotated_scan.expectations(fixtures, FILES)


def fixture_name(value):
    return annotated_scan.fixture_name(value, FIXTURES, FILES)


def verify(payload, fixtures=FIXTURES):
    return annotated_scan.verify(payload, fixtures, FILES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.report.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"SQLi variants FAILED: {exc}\n")
    print("SQLi variants passed: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
