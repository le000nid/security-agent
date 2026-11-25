"""Код-уровень арсенала: кампании LFI/RFI/SQLI без зависимости от Semgrep."""

from app.agent import arsenal

EXPECTED_VECTORS = {"lfi": 31, "rfi": 26, "sqli": 21}


def main() -> None:
    results = arsenal.run_all_campaigns()
    for result in results:
        print(result.render())
        print()
    broken = [result.category for result in results if not result.ok]
    if broken:
        raise SystemExit(f"arsenal regression in: {', '.join(broken)}")
    drift = [
        result.category
        for result in results
        if len(result.outcomes) != EXPECTED_VECTORS[result.category]
    ]
    if drift:
        raise SystemExit(f"vector registry drift in: {', '.join(drift)}")
    total = sum(len(result.outcomes) for result in results)
    skipped = sum(result.skipped_count for result in results)
    print(f"Arsenal passed: {total} vectors, defense ahead (skipped: {skipped})")


if __name__ == "__main__":
    main()
