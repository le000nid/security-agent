"""Run the SAST owner's real scanner acceptance suite with one command."""

import argparse
import json
from pathlib import Path

from app.resources import config_directory
from app.semgrep import parse_semgrep_json, run_semgrep
from benchmark import (
    verify_lfi_variants,
    verify_rfi_variants,
    verify_sast_contract,
    verify_sqli_hardening,
    verify_sqli_variants,
)
from benchmark.evaluator import evaluate

ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    ("sast-sqli-hardening", 6, verify_sqli_hardening.verify),
    ("sast-sqli-variants", 14, verify_sqli_variants.verify),
    ("sast-lfi-variants", 14, verify_lfi_variants.verify),
    ("sast-rfi-variants", 14, verify_rfi_variants.verify),
)


def scan(source: Path, raw: Path):
    run_semgrep(source, raw)
    findings = parse_semgrep_json(raw)
    payload = json.loads(raw.read_text(encoding="utf-8-sig"))
    return findings, payload


def check_baseline(targets: Path, output: Path):
    findings, _ = scan(targets / "sast-contours", output / "sast-contours.json")
    expected = json.loads(
        (config_directory() / "expected/sast-contours.json").read_text(encoding="utf-8")
    )
    evaluation = evaluate([f.model_dump(mode="json") for f in findings], expected)
    if (
        evaluation["expected_count"] != 6
        or evaluation["detected_expected_count"] != 6
        or evaluation["missed_findings"]
        or evaluation["unexpected_findings"]
    ):
        raise ValueError(f"sast-contours regression: {evaluation}")
    return {"expected_rule_ids": 6, "detected_rule_ids": 6, "findings": len(findings)}


def check_variants(targets: Path, output: Path, name, count, verifier):
    source = targets / name
    findings, payload = scan(source, output / f"{name}.json")
    if name == "sast-sqli-hardening":
        verifier(payload)
    else:
        verifier(payload, fixtures=source)
    if len(findings) != count:
        raise ValueError(f"Expected {count} findings in {name}, got {len(findings)}")
    return {
        "findings": len(findings),
        "scanned_files": len(payload["paths"]["scanned"]),
    }


def run_all(targets: Path, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    checks = {}

    def record(name, operation):
        try:
            checks[name] = {"status": "passed", "details": operation()}
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            checks[name] = {"status": "failed", "error": str(exc)}

    record("sast-contours", lambda: check_baseline(targets, output))
    for name, count, verifier in SUITES:
        record(name, lambda: check_variants(targets, output, name, count, verifier))
    record("scanner-contract", verify_sast_contract.verify)
    report = {
        "status": "passed"
        if all(check["status"] == "passed" for check in checks.values())
        else "failed",
        "checks": checks,
    }
    (output / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--targets-dir",
        type=Path,
        default=Path("/targets") if Path("/targets").is_dir() else ROOT / "targets",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("logs/sast-regression"))
    args = parser.parse_args()
    report = run_all(args.targets_dir, args.output_dir)
    for name, check in report["checks"].items():
        print(f"{name}: {check['status']}")
        if check["status"] == "failed":
            print(check["error"])
    print(f"Summary: {args.output_dir / 'summary.json'}")
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
