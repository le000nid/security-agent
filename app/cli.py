"""CLI adapter over RunService; legacy flag-only invocation remains in app.main."""

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from app import __version__
from app.agent.planner import Planner
from app.benchmarks import BenchmarkRegistry
from app.llm import OpenAICompatibleClient
from app.preflight import check_target_reachable
from app.safe_logging import configure_logging
from app.service import RunRequest, RunService


def run(argv: list[str]) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="security-agent")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "deterministic", "agent"):
        command = sub.add_parser(name)
        command.add_argument("--mode", choices=("sast", "dast", "full"), default=None)
        command.add_argument("--benchmark")
        command.add_argument("--target-url")
        command.add_argument("--source-path")
        command.add_argument("--no-llm", action="store_true")
        command.add_argument("--include-evidence-in-llm", action="store_true")
        command.add_argument("--runs-dir", type=Path, default=Path("runs"))
        command.add_argument("--verbose", action="store_true")
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--check-llm", action="store_true")
    doctor.add_argument("--check-benchmarks", action="store_true")
    latest = sub.add_parser("latest")
    latest.add_argument("--runs-dir", type=Path, default=Path("runs"))
    benchmarks = sub.add_parser("benchmarks")
    benchmarks.add_argument(
        "operation", choices=("list", "show"), default="list", nargs="?"
    )
    benchmarks.add_argument("benchmark_id", nargs="?")
    ui = sub.add_parser("ui")
    ui.add_argument(
        "--host", choices=("127.0.0.1", "localhost", "0.0.0.0"), default="127.0.0.1"
    )
    ui.add_argument("--port", type=int, default=8080)
    ui.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args(argv)
    if args.command == "benchmarks":
        try:
            registry = BenchmarkRegistry.load()
            entries = (
                [registry.get(args.benchmark_id)]
                if args.operation == "show"
                else registry.list()
            )
            print(
                json.dumps(
                    [b.model_dump() for b in entries], indent=2, ensure_ascii=False
                )
            )
            return 0
        except (OSError, ValueError):
            print("benchmark_not_found or invalid registry")
            return 2
    if args.command == "ui":
        import uvicorn

        from app.web import create_app

        print(f"AI Security Agent UI: http://127.0.0.1:{args.port}")
        uvicorn.run(
            create_app(runs_dir=args.runs_dir),
            host=args.host,
            port=args.port,
            access_log=False,
        )
        return 0
    if args.command == "latest":
        from app.runs import show_latest

        return show_latest(args.runs_dir)
    if args.command == "doctor":
        from app.doctor import diagnose

        return diagnose(
            check_llm=args.check_llm, check_benchmarks=args.check_benchmarks
        )
    logger = configure_logging(args.verbose)
    try:
        request = RunRequest(
            benchmark_id=args.benchmark,
            mode=args.mode,
            orchestration="agent" if args.command == "agent" else "scan",
            target_url=args.target_url,
            source_path=args.source_path,
            llm_enabled=not args.no_llm,
            include_evidence_in_llm=args.include_evidence_in_llm,
        )
        # Compatibility seams retained; both interfaces use the same RunService.
        service = RunService(
            args.runs_dir,
            client_factory=OpenAICompatibleClient,
            planner_factory=Planner,
            preflight=check_target_reachable,
        )
        result = service.run(request)
    except ValueError:
        logger.error(
            "Invalid configuration/input; check benchmark, mode, local target, source and numeric limits"
        )
        return 2
    except OSError:
        logger.error("Cannot create run directory; check mount permissions")
        return 6
    logger.info(
        "Run %s: %d findings; reports: %s",
        result.run_id,
        result.findings_count,
        result.reports_path,
    )
    brief = result.summary.get("ai_brief")
    if brief:
        logger.info(
            "AI Security Brief: %s — %s", brief["headline"], brief["overall_summary"]
        )
    else:
        logger.info("AI Security Brief: %s", result.summary["ai_brief_status"])
    logger.info("Report: %s", Path(result.reports_path) / "report.md")
    logger.info("Summary: %s", Path(result.reports_path) / "summary.json")
    return result.exit_code
