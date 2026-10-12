"""Strict agent contracts, independent of scanner-specific formats."""

from collections import Counter
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.brief import AIBrief, BriefAttempt
from app.config import ReportLanguage, ReportTone
from app.enrichment import EnrichmentStats
from app.llm import LLMUsage
from app.models import SEVERITY_ORDER, Finding


class Status(StrEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_FAILURES = "completed_with_failures"
    FAILED = "failed"
    SKIPPED = "skipped"


class Action(StrEnum):
    RUN_SAST = "RUN_SAST"
    RUN_DAST = "RUN_DAST"
    ENRICH_FINDINGS = "ENRICH_FINDINGS"
    GENERATE_AI_BRIEF = "GENERATE_AI_BRIEF"
    GENERATE_REPORT = "GENERATE_REPORT"
    FINISH = "FINISH"


class AgentAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    action: Action
    reasoning_short: str = Field(min_length=1, max_length=300)

    @field_validator("reasoning_short")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Reason must not be blank")
        return value.strip()


class UsageBreakdown(BaseModel):
    model_config = ConfigDict(extra="forbid")
    planner: LLMUsage = Field(default_factory=LLMUsage)
    enrichment: LLMUsage = Field(default_factory=LLMUsage)
    brief: LLMUsage = Field(default_factory=LLMUsage)

    def report(self) -> dict:
        planner, enrichment = self.planner.model_dump(), self.enrichment.model_dump()
        brief = self.brief.model_dump()
        return {
            "planner": planner,
            "enrichment": enrichment,
            "brief": brief,
            "total": {
                key: planner[key] + enrichment[key] + brief[key] for key in planner
            },
        }


class TraceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    step: int
    action: str
    decision_source: Literal[
        "llm_planner", "deterministic_single_option", "deterministic"
    ] = "deterministic"
    decision_reason: str
    status: str
    findings_added: int = 0
    duration_ms: int = 0
    error: str | None = None
    error_code: str | None = None


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: Action
    success: bool
    status: Status
    findings_added: int = 0
    duration_ms: int = 0
    error: str | None = None
    error_code: str | None = None
    raw_output_ref: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    rationales: dict[str, str] = Field(default_factory=dict)
    enrichment: EnrichmentStats | None = None
    ai_brief: AIBrief | None = None


class AgentState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)
    run_id: str
    mode: Literal["sast", "dast", "full"] | None = None
    benchmark_id: str | None = None
    benchmark_name: str | None = None
    benchmark_expected: str | None = None
    same_application: bool = False
    llm_enabled: bool = False
    goal: str = "Analyze application security"
    target_url: str | None = None
    source_path: str | None = None
    target_validated: bool = False
    target_available: bool = False
    source_available: bool = False
    source_validated: bool = False
    sast_status: Status = Status.NOT_STARTED
    dast_status: Status = Status.NOT_STARTED
    enrichment_status: Status = Status.NOT_STARTED
    ai_brief_status: Status = Status.NOT_STARTED
    brief_attempts: list[BriefAttempt] = Field(default_factory=list, max_length=3)
    ai_brief: AIBrief | None = None
    enrichment: EnrichmentStats = Field(default_factory=EnrichmentStats)
    report_tone: ReportTone = ReportTone.PROFESSIONAL
    report_language: ReportLanguage = ReportLanguage.RU
    warnings: list[str] = Field(default_factory=list)
    report_status: Status = Status.NOT_STARTED
    findings: list[Finding] = Field(default_factory=list)
    scanner_finding_counts: dict[str, int] = Field(default_factory=dict)
    severity_summary: dict[str, int] = Field(default_factory=dict)
    executed_actions: list[Action] = Field(default_factory=list)
    failed_actions: list[Action] = Field(default_factory=list)
    agent_step_count: int = 0
    planner_request_count: int = 0
    llm_usage: UsageBreakdown = Field(default_factory=UsageBreakdown)
    last_error: str | None = None
    last_error_code: str | None = None
    finished: bool = False
    finish_reason: str | None = None
    exit_code: int = 0
    orchestration: Literal["agent", "deterministic"] = "agent"
    trace: list[TraceEntry] = Field(default_factory=list)
    rationales: dict[str, str] = Field(default_factory=dict)

    def recount(self) -> None:
        counts = Counter(f.severity for f in self.findings)
        self.severity_summary = {s: counts[s] for s in SEVERITY_ORDER if counts[s]}
