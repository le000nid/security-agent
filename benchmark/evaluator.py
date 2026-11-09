"""Compare normalized findings with the known educational fixture inventory."""

import argparse
import json
from pathlib import Path
from typing import Any

KEY_FIELDS = ("tool", "title", "source", "category")


def _key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    try:
        return tuple(str(record[field]) for field in KEY_FIELDS)  # type: ignore[return-value]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"Benchmark records require: {', '.join(KEY_FIELDS)}") from exc


def evaluate(
    actual: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    *,
    benchmark_id: str | None = None,
) -> dict[str, Any]:
    """Compute set-based fixture precision/recall; this is not a pentest metric."""

    actual_keys = {
        _key(record)
        for record in actual
        if benchmark_id or record.get("tool") == "semgrep"
    }
    expected_keys = {_key(record) for record in expected}
    detected = actual_keys & expected_keys
    missed = expected_keys - actual_keys
    unexpected = actual_keys - expected_keys
    precision = len(detected) / len(actual_keys) if actual_keys else 0.0
    recall = len(detected) / len(expected_keys) if expected_keys else 1.0

    def records(keys: set[tuple[str, str, str, str]]) -> list[dict[str, str]]:
        return [dict(zip(KEY_FIELDS, key, strict=True)) for key in sorted(keys)]

    return {
        **({"benchmark_id": benchmark_id} if benchmark_id else {}),
        "scope": "curated local benchmark coverage"
        if benchmark_id
        else "curated local Semgrep fixture coverage only",
        "expected_count": len(expected_keys),
        "detected_expected_count": len(detected),
        "detected_expected_findings": records(detected),
        "missed_findings": records(missed),
        "unexpected_findings": records(unexpected),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path, help="Normalized findings.json")
    parser.add_argument(
        "--expected",
        type=Path,
        default=Path(__file__).with_name("expected_findings.json"),
    )
    args = parser.parse_args()
    actual = json.loads(args.findings.read_text(encoding="utf-8"))
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    if not isinstance(actual, list) or not isinstance(expected, list):
        raise SystemExit("Both benchmark inputs must be JSON arrays")
    print(json.dumps(evaluate(actual, expected), indent=2))


if __name__ == "__main__":
    main()
