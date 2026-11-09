"""Offline acceptance check for the latest real scanner-only benchmark run."""

import argparse

from app.repository import RunRepository


def verify(repository: RunRepository) -> dict:
    summary = repository.summary(repository.latest())
    if summary.get("benchmark_id") != "demo-full" or summary.get("mode") != "full":
        raise ValueError("Expected demo-full FULL run")
    if summary.get("status") != "completed" or not summary.get("same_application"):
        raise ValueError("Incomplete or mismatched benchmark")
    evaluation = summary.get("benchmark_evaluation", {})
    if (
        evaluation.get("expected_count") != 7
        or evaluation.get("detected_expected_count") != 7
        or evaluation.get("missed_findings")
        or evaluation.get("unexpected_findings")
    ):
        raise ValueError("Curated benchmark regression")
    findings = repository.findings(summary["run_id"])
    if (
        len(findings) != 7
        or sum(f["source"] == "SAST" for f in findings) != 4
        or sum(f["source"] == "DAST" for f in findings) != 3
    ):
        raise ValueError("Scanner finding count regression")
    if summary["llm_usage"]["total"]["requests"] != 0:
        raise ValueError("Smoke must not call LLM")
    if (
        summary["stages"]["enrichment"] != "skipped"
        or summary["stages"]["ai_brief"] != "skipped"
    ):
        raise ValueError("Smoke AI stages must be skipped")
    return {"run_id": summary["run_id"], "sast": 4, "dast": 3, "llm_requests": 0}


def main():
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args()
    print(json.dumps(verify(RunRepository(args.runs_dir))))


if __name__ == "__main__":
    main()
