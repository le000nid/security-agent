"""Check a completed profile benchmark, including its common reports and raw proof."""

import argparse
import json
from pathlib import Path

from app.benchmarks import BenchmarkRegistry
from app.repository import RunRepository

EXPECTED = {
    "nosqli-profile-catalog": 1,
    "nosqli-profile-catalog-safe": 0,
    "nosqli-profile-inventory": 2,
    "nosqli-profile-inventory-safe": 0,
}


def verify(benchmark_id: str, base: Path = Path("runs")) -> dict:
    if benchmark_id not in EXPECTED:
        raise ValueError("Not a portable acceptance benchmark")
    run_id = json.loads((base / "latest.json").read_text(encoding="utf-8"))["run_id"]
    repository = RunRepository(base)
    summary = repository.summary(run_id)
    findings = repository.json(run_id, "findings.json")
    report = repository.text(run_id, "report.md")
    assert summary["benchmark_id"] == benchmark_id, (
        "Latest run belongs to another benchmark"
    )
    assert summary["status"] == "completed", summary["warnings"]
    assert summary["total"] == len(findings) == EXPECTED[benchmark_id]
    assert summary["llm_usage"]["total"]["requests"] == 0
    profiles = BenchmarkRegistry.load().get(benchmark_id).nosqli_profiles
    assert summary["nosqli_profiles"] == profiles
    raw = json.loads(
        (base / run_id / "logs" / "raw_nosqli.json").read_text(encoding="utf-8")
    )
    assert [entry["profile"] for entry in raw["profiles"]] == profiles
    for entry in raw["profiles"]:
        safe = benchmark_id.endswith("-safe")
        assert entry["status"] == ("rejected" if safe else "confirmed"), entry
        assert entry["http_statuses"] == ([200, 400, 200, 200] if safe else [200] * 4)
        assert entry["record_counts"] == ([1, None, 0, 1] if safe else [1, 3, 0, 1])
    for finding in findings:
        assert finding["tool"] == "nosqli-http" and finding["source"] == "DAST"
        assert finding["normalized_category"] == "injection"
        assert json.loads(finding["evidence"])["status"] == "confirmed"
        assert finding["title"] in report
    return {
        "status": "passed",
        "benchmark": benchmark_id,
        "run_id": run_id,
        "findings": len(findings),
        "profiles": profiles,
        "llm_requests": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", required=True, choices=EXPECTED)
    args = parser.parse_args()
    print(json.dumps(verify(args.benchmark), indent=2))


if __name__ == "__main__":
    main()
