"""CLI adapter over RunService; legacy flag-only invocation remains in app.main."""

import argparse
import json
import sys
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
    ctf = sub.add_parser("ctf", help="Run or package the embedded CTF agents")
    ctf.add_argument(
        "--profile",
        metavar="NAME",
        help="functional profile name (see --list-profiles)",
    )
    ctf.add_argument(
        "--package", type=Path, metavar="ZIP", help="build the standalone ZIP"
    )
    ctf.add_argument(
        "--list-profiles",
        action="store_true",
        help="list available profiles and exit",
    )
    ctf.add_argument(
        "--strategy",
        type=Path,
        metavar="MD",
        help="strategy text for the bounded evidence profile (optional)",
    )
    ui = sub.add_parser("ui")
    ui.add_argument(
        "--host", choices=("127.0.0.1", "localhost", "0.0.0.0"), default="127.0.0.1"
    )
    ui.add_argument("--port", type=int, default=8080)
    ui.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args(argv)
    if args.command == "ctf":
        return _run_ctf(args)
    load_dotenv()
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


def _run_ctf(args) -> int:
    """Dispatch the ``ctf`` subcommand to the embedded CTF engine."""
    from app.agent.ctf import PROFILES
    from app.agent.ctf.profiles import get_profile

    if args.list_profiles:
        for name in PROFILES:
            profile = get_profile(name)
            summary = profile.summary if profile else "bounded evidence loop"
            print(f"{name:22s} {summary}")
        return 0
    name = args.profile
    if not name:
        print("error: --profile is required (or --list-profiles)", file=sys.stderr)
        return 2
    key = str(name).strip().lower()
    if key not in PROFILES:
        print(f"error: unknown profile {name!r}; see --list-profiles", file=sys.stderr)
        return 2
    if args.package is not None:
        from app.agent.ctf.package import build_archive

        try:
            print(build_archive(key, args.package, strategy_path=args.strategy))
            return 0
        except (OSError, ValueError, SyntaxError) as exc:
            print(f"Cannot build archive: {exc}", file=sys.stderr)
            return 2
    if key == "evidence":
        from app.agent.ctf import evidence

        strategy = None
        if args.strategy is not None:
            strategy = args.strategy.read_text(encoding="utf-8", errors="replace")
        return evidence.main(strategy)
    profile = get_profile(key)
    from app.agent.ctf.runtime import run_profile

    return run_profile(profile)
