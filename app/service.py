"""Shared run setup for CLI, Guided Scan and controlled Chat intents."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.agent.loop import run_agent, run_deterministic
from app.agent.models import AgentState, Status
from app.agent.planner import Planner
from app.agent.reporting import finalize
from app.agent.tools import ToolRegistry
from app.benchmarks import Benchmark, BenchmarkId, BenchmarkRegistry, Mode
from app.config import ReportLanguage, ReportTone, Settings
from app.events import Observer, RunEvent, emit
from app.llm import OpenAICompatibleClient
from app.preflight import check_target_reachable
from app.runs import RunPaths
from app.validation import validate_source_path, validate_target_url


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    benchmark_id: BenchmarkId | None = None
    mode: Mode | None = None
    orchestration: Literal["scan", "agent"] = "scan"
    llm_enabled: bool = False
    include_evidence_in_llm: bool = False
    report_tone: ReportTone | None = None
    report_language: ReportLanguage | None = None
    target_url: str | None = None
    source_path: str | None = None


class RunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    run_id: str
    status: Literal["completed", "completed_with_warnings", "failed"]
    reports_path: str
    findings_count: int
    counts: dict[str, int]
    exit_code: int
    summary: dict


class RunService:
    def __init__(
        self,
        runs_dir: Path = Path("runs"),
        *,
        registry: BenchmarkRegistry | None = None,
        client_factory=None,
        planner_factory=None,
        preflight=None,
    ):
        self.runs_dir = runs_dir
        self.benchmarks = registry or BenchmarkRegistry.load()
        self.client_factory = client_factory or OpenAICompatibleClient
        self.planner_factory = planner_factory or Planner
        self.preflight = preflight or check_target_reachable

    def resolve(
        self, request: RunRequest
    ) -> tuple[Benchmark | None, Mode, str | None, str | None]:
        if request.orchestration == "agent" and not request.llm_enabled:
            raise ValueError("agent_requires_llm")
        benchmark = None
        target, source = request.target_url, request.source_path
        if request.benchmark_id:
            if target or source:
                raise ValueError("ambiguous_benchmark_input")
            benchmark = self.benchmarks.get(request.benchmark_id)
            mode = benchmark.resolve_mode(request.mode)
            target = benchmark.target_url if mode != "sast" else None
            source = benchmark.local_source() if mode != "dast" else None
        else:
            mode = request.mode or (
                "full" if target and source else "sast" if source else "dast"
            )
        if mode in ("dast", "full") and not target:
            raise ValueError("target_required")
        if mode in ("sast", "full") and not source:
            raise ValueError("source_required")
        target = validate_target_url(target) if target else None
        source = str(validate_source_path(source)) if source else None
        return benchmark, mode, target, source

    def run(self, request: RunRequest, observer: Observer | None = None) -> RunResult:
        benchmark, mode, target, source = self.resolve(request)
        settings = Settings.from_env()
        overrides = {}
        if request.report_tone is not None:
            overrides["llm_report_tone"] = request.report_tone
        if request.report_language is not None:
            overrides["llm_report_language"] = request.report_language
        settings = settings.model_copy(update=overrides)
        paths = RunPaths.create(self.runs_dir)
        state = AgentState(
            run_id=paths.run_id,
            mode=mode,
            benchmark_id=benchmark.id if benchmark else None,
            benchmark_name=benchmark.name if benchmark else None,
            same_application=bool(benchmark and mode == "full"),
            benchmark_expected=benchmark.expected_findings if benchmark else None,
            target_url=target,
            source_path=source,
            target_validated=bool(target),
            source_validated=bool(source),
            source_available=bool(source),
            orchestration="agent"
            if request.orchestration == "agent"
            else "deterministic",
            report_tone=settings.llm_report_tone,
            report_language=settings.llm_report_language,
        )
        emit(
            observer,
            RunEvent(event="run_created", run_id=paths.run_id, status="running"),
        )
        if mode == "sast":
            state.dast_status = Status.SKIPPED
        if mode == "dast":
            state.sast_status = Status.SKIPPED
        if not request.llm_enabled:
            state.enrichment_status = Status.SKIPPED
        if not request.llm_enabled or not settings.llm_brief_enabled:
            state.ai_brief_status = Status.SKIPPED
        if mode in ("dast", "full"):
            try:
                self.preflight(target)
                state.target_available = True
            except (ValueError, OSError):
                state.dast_status = Status.FAILED
                state.exit_code = 6
                state.last_error = (
                    "Local target unreachable; start benchmark services and run doctor"
                )
                emit(
                    observer,
                    RunEvent(
                        event="stage_warning",
                        run_id=paths.run_id,
                        action="RUN_DAST",
                        status="failed",
                        message="target_unreachable",
                    ),
                )
        client = None
        if request.llm_enabled:
            try:
                client = self.client_factory(settings=settings)
                client.ensure_model_available()
            except ValueError:
                state.enrichment_status = Status.FAILED
                state.last_error = (
                    "LLM preflight failed; check configuration and model availability"
                )
                if request.orchestration == "agent":
                    state.exit_code = state.exit_code or 4
                    state.finish_reason = "llm_preflight_failed"
                    finalize(state, paths, client.public_metadata() if client else None)
                    return self._result(state, paths, observer)
                state.warnings.append("llm_preflight_failed")
                state.last_error_code = "llm_preflight_failed"
                if state.ai_brief_status != Status.SKIPPED:
                    state.ai_brief_status = Status.FAILED
                client = None
        registry = ToolRegistry(
            paths,
            client,
            include_evidence=request.include_evidence_in_llm,
            batch_size=settings.llm_enrichment_batch_size,
            settings=settings,
            observer=observer,
        )
        if request.orchestration == "agent":
            run_agent(state, self.planner_factory(client), registry, settings)
        else:
            run_deterministic(state, registry)
        return self._result(state, paths, observer)

    @staticmethod
    def _result(
        state: AgentState, paths: RunPaths, observer: Observer | None
    ) -> RunResult:
        status = (
            "failed"
            if state.exit_code
            else "completed_with_warnings"
            if state.warnings
            else "completed"
        )
        emit(
            observer,
            RunEvent(
                event="run_completed",
                run_id=paths.run_id,
                status=status,
                findings_count=len(state.findings),
            ),
        )
        return RunResult(
            run_id=paths.run_id,
            status=status,
            reports_path=str(paths.reports),
            findings_count=len(state.findings),
            counts=state.severity_summary,
            exit_code=state.exit_code,
            summary={
                "benchmark_id": state.benchmark_id,
                "mode": state.mode,
                "warnings": state.warnings,
                "finish_reason": state.finish_reason,
                "ai_brief": state.ai_brief.model_dump() if state.ai_brief else None,
                "ai_brief_status": state.ai_brief_status.value,
            },
        )
