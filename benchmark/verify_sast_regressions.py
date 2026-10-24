"""Run the SAST owner's real scanner acceptance suite with one command."""

import argparse
import json
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile

from app.resources import config_directory
from app.semgrep import parse_semgrep_json, run_semgrep
from benchmark import (
    verify_lfi_variants,
    verify_rfi_variants,
    verify_sast_contract,
    verify_sqli_hardening,
    verify_sqli_variants,
)
from benchmark.annotated_scan import fixture_name
from benchmark.evaluator import evaluate

ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILES = frozenset(
    {
        "benign.js",
        "benign.php",
        "benign-rfi-literal.php",
        "benign-sqli-taint.js",
        "benign-sqli-taint.php",
        "benign-sqli-taint.py",
        "vulnerable.js",
        "vulnerable.php",
        "vulnerable-rfi-literal.php",
        "vulnerable-sqli-taint.js",
        "vulnerable-sqli-taint.php",
        "vulnerable-sqli-taint.py",
    }
)
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


def check_baseline_coverage(source: Path, payload):
    present = {
        p.name for p in source.iterdir() if p.suffix in {".js", ".ts", ".py", ".php"}
    }
    if present != BASELINE_FILES:
        raise ValueError(
            f"Baseline fixture inventory mismatch: {sorted(present ^ BASELINE_FILES)}"
        )
    scanned = payload["paths"]["scanned"]
    if not isinstance(scanned, list):
        raise TypeError("Expected a scanned paths array")
    names = Counter(fixture_name(p, source, BASELINE_FILES) for p in scanned)
    if names != Counter(BASELINE_FILES):
        raise ValueError("Not all baseline fixtures were scanned exactly once")
    return len(scanned)


def check_baseline(targets: Path, output: Path):
    source = targets / "sast-contours"
    findings, payload = scan(source, output / "sast-contours.json")
    scanned_files = check_baseline_coverage(source, payload)
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
    return {
        "expected_rule_ids": 6,
        "detected_rule_ids": 6,
        "findings": len(findings),
        "scanned_files": scanned_files,
    }


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


def save_report(output: Path, report):
    temporary = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output,
            prefix=".summary-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, ensure_ascii=False, indent=2)
        temporary.replace(output / "summary.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_all(targets: Path, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    names = ["sast-contours", *(name for name, _, _ in SUITES), "scanner-contract"]
    checks = {name: {"status": "pending"} for name in names}
    report = {"status": "running", "checks": checks}
    save_report(output, report)

    def record(name, operation):
        checks[name] = {"status": "running"}
        save_report(output, report)
        try:
            checks[name] = {"status": "passed", "details": operation()}
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            checks[name] = {"status": "failed", "error": str(exc)}
        save_report(output, report)

    record("sast-contours", lambda: check_baseline(targets, output))
    for name, count, verifier in SUITES:
        record(name, lambda: check_variants(targets, output, name, count, verifier))
    record("scanner-contract", verify_sast_contract.verify)
    report["status"] = (
        "passed"
        if all(check["status"] == "passed" for check in checks.values())
        else "failed"
    )
    save_report(output, report)
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
