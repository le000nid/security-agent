"""Verify a completed real FULL run for the MongoDB NoSQLi benchmark."""

import argparse
import json
from collections import Counter
from pathlib import Path

from app.repository import RunRepository
from benchmark.verify_nosqli_sast import verify as verify_sast


def verify(repository: RunRepository) -> dict:
    run_id = repository.latest()
    summary = repository.summary(run_id)
    if (
        summary.get("benchmark_id") != "nosqli-mongo-full"
        or summary.get("mode") != "full"
        or summary.get("status") != "completed"
        or not summary.get("same_application")
    ):
        raise ValueError("Expected a completed same-application MongoDB FULL run")
    evaluation = summary.get("benchmark_evaluation", {})
    if (
        evaluation.get("expected_count") != 5
        or evaluation.get("detected_expected_count") != 5
        or evaluation.get("missed_findings")
        or evaluation.get("unexpected_findings")
    ):
        raise ValueError("NoSQLi benchmark finding types differ from expectations")
    findings = repository.findings(run_id)
    actual = Counter((item["source"], item["title"]) for item in findings)
    expected = Counter(
        {
            ("SAST", "javascript-nosqli-scalar-operator"): 1,
            ("SAST", "javascript-nosqli-untrusted-filter"): 2,
            ("DAST", "MongoDB scalar operator injection"): 1,
            ("DAST", "MongoDB untrusted filter injection"): 1,
            ("DAST", "MongoDB server scope overwrite"): 1,
        }
    )
    if actual != expected:
        raise ValueError(f"Expected six scenario findings, received {actual}")
    if any(
        not item.get("evidence") or not item.get("raw_output_ref") for item in findings
    ):
        raise ValueError("Finding evidence or raw reference is missing")
    for item in findings:
        if item["source"] == "DAST" and not all(
            token in item["evidence"] for token in ("baseline=", "changed=", "control=")
        ):
            raise ValueError("DAST comparison evidence was not preserved")
    if summary["llm_usage"]["total"]["requests"] != 0:
        raise ValueError("Acceptance run must not call an LLM")
    return {
        "status": "passed",
        "run_id": run_id,
        "sast": 3,
        "dast": 3,
        "llm_requests": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args()
    repository = RunRepository(args.runs_dir)
    result = verify(repository)
    run_id = result["run_id"]
    raw = repository.base / run_id / "logs" / "raw_semgrep.json"
    source = Path(repository.summary(run_id)["source_path"])
    result["sast_annotations"] = verify_sast(
        json.loads(raw.read_text(encoding="utf-8")), source
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
