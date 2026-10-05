"""Fixed registry. Tool arguments originate exclusively in validated application state."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from types import MappingProxyType

from app.agent.models import Action, AgentState, Status, ToolResult
from app.agent.reporting import write_reports
from app.agent.validator import STAGES, ActionValidator
from app.brief import generate_ai_brief
from app.config import Settings
from app.enrichment import enrich_independently
from app.events import Observer
from app.llm import OpenAICompatibleClient
from app.llm_output import LLMError
from app.nuclei import run_nuclei
from app.parser import parse_nuclei_jsonl
from app.runs import RunPaths
from app.semgrep import parse_semgrep_json, run_semgrep


@dataclass(frozen=True)
class AgentTool:
    name: Action
    description: str
    operation: Callable[[AgentState], ToolResult]

    def can_run(self, state: AgentState) -> bool:
        return self.name in ActionValidator().allowed(state)

    def run(self, state: AgentState) -> ToolResult:
        return self.operation(state)


class ToolRegistry:
    def __init__(
        self,
        paths: RunPaths,
        client: OpenAICompatibleClient | None,
        *,
        include_evidence: bool = False,
        batch_size: int = 1,
        settings: Settings | None = None,
        observer: Observer | None = None,
    ):
        self.paths, self.client = paths, client
        self.observer = observer
        self.include_evidence, self.batch_size = include_evidence, batch_size
        self.settings = settings or Settings()
        self.tools = MappingProxyType(
            {
                Action.RUN_SAST: AgentTool(
                    Action.RUN_SAST, "Local curated Semgrep rules", self._sast
                ),
                Action.RUN_DAST: AgentTool(
                    Action.RUN_DAST,
                    "Local low-impact HTTP Nuclei templates",
                    self._dast,
                ),
                Action.ENRICH_FINDINGS: AgentTool(
                    Action.ENRICH_FINDINGS, "Enrich existing findings", self._enrich
                ),
                Action.GENERATE_REPORT: AgentTool(
                    Action.GENERATE_REPORT, "Write run reports", self._report
                ),
                Action.GENERATE_AI_BRIEF: AgentTool(
                    Action.GENERATE_AI_BRIEF,
                    "Summarize existing findings only",
                    self._brief,
                ),
            }
        )

    def execute(self, action: Action, state: AgentState) -> ToolResult:
        ActionValidator().validate(action, state)
        if action not in self.tools:
            raise ValueError("Action is not a registered tool")
        tool = self.tools[action]
        if not tool.can_run(state):
            raise ValueError("Tool preconditions failed")
        setattr(state, STAGES[action], Status.RUNNING)
        started = monotonic()
        try:
            result = tool.run(state)
        except Exception as exc:
            # Exception messages may contain provider data, source or credentials.
            result = ToolResult(
                tool=action,
                success=False,
                status=Status.FAILED,
                error=exc.message
                if isinstance(exc, LLMError)
                else f"{action.value} failed; inspect local raw logs or run doctor",
                error_code=exc.code
                if isinstance(exc, LLMError)
                else f"{action.value.lower()}_failed",
            )
        result.duration_ms = max(0, int((monotonic() - started) * 1000))
        return result

    def _sast(self, state: AgentState) -> ToolResult:
        raw = self.paths.logs / "raw_semgrep.json"
        run_semgrep(Path(state.source_path), raw)
        findings = parse_semgrep_json(raw)
        return ToolResult(
            tool=Action.RUN_SAST,
            success=True,
            status=Status.COMPLETED,
            findings=findings,
            findings_added=len(findings),
            raw_output_ref=raw.as_posix(),
        )

    def _dast(self, state: AgentState) -> ToolResult:
        raw = self.paths.logs / "raw_nuclei.jsonl"
        run_nuclei(state.target_url, raw)
        findings = parse_nuclei_jsonl(raw)
        return ToolResult(
            tool=Action.RUN_DAST,
            success=True,
            status=Status.COMPLETED,
            findings=findings,
            findings_added=len(findings),
            raw_output_ref=raw.as_posix(),
        )

    def _enrich(self, state: AgentState) -> ToolResult:
        if self.client is None:
            raise ValueError("Enrichment client unavailable")
        result = enrich_independently(
            state.findings,
            self.client,
            include_evidence=self.include_evidence,
            batch_size=self.batch_size,
        )
        return ToolResult(
            tool=Action.ENRICH_FINDINGS,
            success=not result.stats.failed,
            status=Status.COMPLETED
            if not result.stats.failed
            else Status.COMPLETED_WITH_FAILURES
            if result.stats.completed
            else Status.FAILED,
            findings=result.findings,
            rationales=result.rationales,
            enrichment=result.stats,
            error="Some findings retain their original scanner description."
            if result.stats.failed
            else None,
            error_code=result.stats.failures[-1].error_code
            if result.stats.failures
            else None,
        )

    def _brief(self, state: AgentState) -> ToolResult:
        if self.client is None:
            raise LLMError("brief", "unavailable")
        return ToolResult(
            tool=Action.GENERATE_AI_BRIEF,
            success=True,
            status=Status.COMPLETED,
            ai_brief=generate_ai_brief(state, self.client, self.settings),
        )

    def _report(self, state: AgentState) -> ToolResult:
        write_reports(
            state, self.paths, self.client.public_metadata() if self.client else None
        )
        return ToolResult(
            tool=Action.GENERATE_REPORT, success=True, status=Status.COMPLETED
        )


def apply_result(state: AgentState, result: ToolResult) -> None:
    setattr(state, STAGES[result.tool], result.status)
    state.executed_actions.append(result.tool)
    if result.enrichment is not None:
        state.enrichment = result.enrichment
        state.findings = result.findings
        state.rationales = result.rationales
        state.recount()
    if not result.success:
        state.failed_actions.append(result.tool)
        state.last_error = result.error
        state.last_error_code = result.error_code
        if result.tool in (Action.ENRICH_FINDINGS, Action.GENERATE_AI_BRIEF):
            state.warnings.append(result.error_code or "optional_analysis_failed")
            return
        code = (
            4
            if result.tool == Action.ENRICH_FINDINGS
            else 6
            if result.tool == Action.GENERATE_REPORT
            else 3
        )
        state.exit_code = state.exit_code or code
        return
    if result.tool in (Action.RUN_SAST, Action.RUN_DAST):
        state.findings.extend(result.findings)
        state.scanner_finding_counts[result.tool.value] = result.findings_added
    elif result.tool == Action.ENRICH_FINDINGS:
        state.findings = result.findings
        state.rationales = result.rationales
    elif result.tool == Action.GENERATE_AI_BRIEF:
        state.ai_brief = result.ai_brief
    state.recount()
