"""Command-line entry point for ai-security-agent."""

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console

from app.llm import LLMUsage, OpenAICompatibleClient, enrich_findings
from app.nuclei import NucleiError, run_nuclei
from app.parser import NucleiParseError, parse_nuclei_jsonl, save_findings
from app.preflight import check_target_reachable
from app.report import generate_markdown_report, save_summary
from app.semgrep import parse_semgrep_json, run_semgrep
from app.validation import (
    TargetValidationError,
    validate_source_path,
    validate_target_url,
)

RAW_OUTPUT = Path("logs/raw_nuclei.jsonl")
FINDINGS_OUTPUT = Path("reports/findings.json")
REPORT_OUTPUT = Path("reports/report.md")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-agent",
        description="Local-only OWASP Juice Shop security testing harness.",
    )
    parser.add_argument("--target-url", help="Allowed local target URL")
    parser.add_argument("--source-path", help="Local source file or directory")
    parser.add_argument("--mode", choices=("dast", "sast", "full"), default="dast")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM enrichment and all LLM API calls",
    )
    parser.add_argument(
        "--include-evidence-in-llm",
        action="store_true",
        help="Include normalized short evidence in LLM input (off by default)",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {
        "scan",
        "deterministic",
        "agent",
        "doctor",
        "latest",
        "--version",
        "--help",
        "-h",
    }:
        from app.cli import run as run_cli

        return run_cli(argv)
    load_dotenv()
    args = build_parser().parse_args(argv)
    console = Console()

    try:
        if args.mode in ("dast", "full") and not args.target_url:
            raise ValueError("--target-url is required for dast/full")
        if args.mode in ("sast", "full") and not args.source_path:
            raise ValueError("--source-path is required for sast/full")
        target_url = validate_target_url(args.target_url) if args.target_url else None
        source = validate_source_path(args.source_path) if args.source_path else None
        client = None
        findings = []
        if args.mode in ("dast", "full"):
            check_target_reachable(target_url)
        if args.mode in ("sast", "full"):
            raw_semgrep = Path("logs/raw_semgrep.json")
            run_semgrep(source, raw_semgrep)
            findings.extend(parse_semgrep_json(raw_semgrep))
        if args.mode in ("dast", "full"):
            run_nuclei(target_url, RAW_OUTPUT)
            findings.extend(parse_nuclei_jsonl(RAW_OUTPUT))
        scanner_findings = findings
        rationales = {}
        llm_status = "disabled" if args.no_llm else "completed"
        llm_error = None
        if not args.no_llm:
            try:
                client = OpenAICompatibleClient()
                findings, rationales = enrich_findings(
                    scanner_findings,
                    client,
                    include_evidence=args.include_evidence_in_llm,
                )
            except ValueError as exc:
                findings = scanner_findings
                rationales = {}
                llm_status = "failed"
                llm_error = str(exc)
                console.print(
                    f"LLM enrichment failed; scanner-only artifacts preserved: {exc}",
                    highlight=False,
                    markup=False,
                )
        save_findings(findings, FINDINGS_OUTPUT)
        generate_markdown_report(findings, target_url or str(source), REPORT_OUTPUT)
        save_summary(
            findings,
            args.mode,
            target_url,
            source,
            rationales,
            Path("reports/summary.json"),
            llm_status=llm_status,
            llm=client.public_metadata() if client else None,
            llm_usage=client.usage if client else LLMUsage(),
            llm_error=llm_error,
        )
    except (
        TargetValidationError,
        NucleiError,
        NucleiParseError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"Error: {exc}", highlight=False, markup=False)
        return 1

    if llm_status == "failed":
        return 1
    console.print(
        f"[green]Done.[/green] {len(findings)} finding(s); report: {REPORT_OUTPUT}"
    )
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
