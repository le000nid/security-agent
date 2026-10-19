"""Verify PHP local file inclusion detection and safe fixed-path choices."""

import argparse
import json
from pathlib import Path

from benchmark import annotated_scan

FIXTURES = Path(__file__).resolve().parents[1] / "targets/sast-lfi-variants"
FILES = {
    f"{kind}-{group}.php"
    for kind in ("benign", "vulnerable")
    for group in (
        "superglobals",
        "filter-input",
        "expressions",
        "weak-guards",
        "mappings",
    )
}


def expectations(fixtures=FIXTURES):
    return annotated_scan.expectations(fixtures, FILES)


def verify(payload, fixtures=FIXTURES):
    return annotated_scan.verify(payload, fixtures, FILES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.report.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"LFI variants FAILED: {exc}\n")
    print("LFI variants passed: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
