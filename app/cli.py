"""v0.3 subcommands; v0.2 flag-only invocation remains in app.main."""

import argparse
from pathlib import Path

from dotenv import load_dotenv

from app import __version__
from app.agent.loop import run_agent, run_deterministic
from app.agent.models import AgentState, Status
from app.agent.planner import Planner
from app.agent.reporting import finalize
from app.agent.tools import ToolRegistry
from app.config import Settings
from app.llm import OpenAICompatibleClient
from app.preflight import check_target_reachable
from app.runs import RunPaths
from app.safe_logging import configure_logging
from app.validation import validate_source_path, validate_target_url


def run(argv: list[str]) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="security-agent")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "deterministic", "agent"):
        command = sub.add_parser(name)
        command.add_argument("--mode", choices=("sast", "dast", "full"), default=None)
        command.add_argument("--target-url")
        command.add_argument("--source-path")
        command.add_argument("--no-llm", action="store_true")
        command.add_argument("--include-evidence-in-llm", action="store_true")
        command.add_argument("--runs-dir", type=Path, default=Path("runs"))
        command.add_argument("--verbose", action="store_true")
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--check-llm", action="store_true")
    latest = sub.add_parser("latest")
    latest.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args(argv)
    if args.command == "latest":
        from app.runs import show_latest

        return show_latest(args.runs_dir)
    if args.command == "doctor":
        from app.doctor import diagnose

        return diagnose(check_llm=args.check_llm)
    logger = configure_logging(args.verbose)
    try:
        settings = Settings.from_env()
        if args.command == "agent" and args.no_llm:
            raise ValueError("Agent mode requires LLM; use scan --no-llm")
        mode = args.mode or (
            "full"
            if args.target_url and args.source_path
            else "sast"
            if args.source_path
            else "dast"
        )
        if mode in ("dast", "full") and not args.target_url:
            raise ValueError("--target-url required for dast/full")
        if mode in ("sast", "full") and not args.source_path:
            raise ValueError("--source-path required for sast/full")
        target = validate_target_url(args.target_url) if args.target_url else None
        source = (
            str(validate_source_path(args.source_path)) if args.source_path else None
        )
    except (ValueError, OSError):
        logger.error(
            "Invalid configuration/input; check mode, local target, source and numeric limits"
        )
        return 2
    try:
        paths = RunPaths.create(args.runs_dir)
    except OSError:
        logger.error("Cannot create run directory; check mount permissions")
        return 6
    state = AgentState(
        run_id=paths.run_id,
        target_url=target,
        source_path=source,
        target_validated=bool(target),
        source_validated=bool(source),
        source_available=bool(source),
        orchestration="agent" if args.command == "agent" else "deterministic",
        report_tone=settings.llm_report_tone,
        report_language=settings.llm_report_language,
    )
    if mode == "sast":
        state.dast_status = Status.SKIPPED
    if mode == "dast":
        state.sast_status = Status.SKIPPED
    if args.no_llm:
        state.enrichment_status = Status.SKIPPED
    if args.no_llm or not settings.llm_brief_enabled:
        state.ai_brief_status = Status.SKIPPED
    if mode in ("dast", "full"):
        try:
            check_target_reachable(target)
            state.target_available = True
        except (ValueError, OSError):
            state.dast_status = Status.FAILED
            state.exit_code = 6
            state.last_error = (
                "Local target unreachable; start Juice Shop and run doctor"
            )
    client = None
    if not args.no_llm:
        try:
            client = OpenAICompatibleClient(settings=settings)
            client.ensure_model_available()
        except ValueError:
            state.enrichment_status = Status.FAILED
            state.last_error = (
                "LLM preflight failed; check configuration and model availability"
            )
            if args.command == "agent":
                state.exit_code = state.exit_code or 4
                state.finish_reason = "llm_preflight_failed"
                finalize(state, paths, client.public_metadata() if client else None)
                logger.error(state.last_error)
                return state.exit_code
            state.warnings.append("llm_preflight_failed")
            state.last_error_code = "llm_preflight_failed"
            if state.ai_brief_status != Status.SKIPPED:
                state.ai_brief_status = Status.FAILED
            client = None
    registry = ToolRegistry(
        paths,
        client,
        include_evidence=args.include_evidence_in_llm,
        batch_size=settings.llm_enrichment_batch_size,
        settings=settings,
    )
    if args.command == "agent":
        run_agent(state, Planner(client), registry, settings)
    else:
        run_deterministic(state, registry)
    logger.info(
        "Run %s: %d findings; reports: %s",
        paths.run_id,
        len(state.findings),
        paths.reports,
    )
    if state.report_status == Status.COMPLETED:
        if state.ai_brief:
            logger.info(
                "AI Security Brief: %s — %s",
                state.ai_brief.headline,
                state.ai_brief.overall_summary,
            )
        else:
            logger.info("AI Security Brief: %s", state.ai_brief_status.value)
        logger.info("Report: %s", paths.reports / "report.md")
        logger.info("Summary: %s", paths.reports / "summary.json")
    return state.exit_code
