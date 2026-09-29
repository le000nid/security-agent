"""Run artifacts share one canonical state and deterministic finding order."""

import json
from collections import Counter

from app import __version__
from app.agent.models import AgentState, Status
from app.parser import save_findings
from app.report import _inline, generate_markdown_report
from app.runs import RunPaths
from app.safe_logging import redact, redact_data


def write_reports(
    state: AgentState, paths: RunPaths, metadata: dict | None = None
) -> None:
    paths.reports.mkdir(parents=True, exist_ok=True)
    save_findings(state.findings, paths.reports / "findings.json")
    trace = [item.model_dump(mode="json") for item in state.trace]
    (paths.reports / "agent_trace.json").write_text(
        json.dumps(redact_data(trace), indent=2), encoding="utf-8"
    )
    summary = {
        "version": __version__,
        "run_id": state.run_id,
        "orchestration": state.orchestration,
        "target_url": state.target_url,
        "source_path": state.source_path,
        "status": "failed"
        if state.exit_code
        else (
            "completed_with_warnings"
            if state.finished and state.warnings
            else "completed"
            if state.finished
            else "running"
        ),
        "total": len(state.findings),
        "by_severity": state.severity_summary,
        "by_source": dict(sorted(Counter(f.source for f in state.findings).items())),
        "scanner_finding_counts": state.scanner_finding_counts,
        "llm_status": "failed"
        if state.exit_code in (4, 5) or state.enrichment_status == Status.FAILED
        else state.enrichment_status.value,
        "llm": metadata,
        "llm_usage": state.llm_usage.report(),
        "enrichment": state.enrichment.model_dump(),
        "ai_brief_status": state.ai_brief_status.value,
        "report_tone": state.report_tone.value,
        "report_language": state.report_language.value,
        "warnings": state.warnings,
        "llm_rationales": dict(sorted(state.rationales.items())),
        "agent_steps": state.agent_step_count,
        "planner_request_count": state.planner_request_count,
        "finish_reason": state.finish_reason,
        "last_error": state.last_error,
        "last_error_code": state.last_error_code,
        "outcome": state.finish_reason or "running",
        "planner_failures": sum(
            t.status == "rejected" and t.decision_source == "llm_planner"
            for t in state.trace
        ),
        "enrichment_failures": sum(
            t.action == "ENRICH_FINDINGS"
            and t.status in ("failed", "completed_with_failures")
            for t in state.trace
        ),
        "stages": {
            name: getattr(state, f"{name}_status").value
            for name in ("sast", "dast", "enrichment", "ai_brief", "report")
        },
    }
    (paths.reports / "summary.json").write_text(
        json.dumps(redact_data(summary), indent=2), encoding="utf-8"
    )
    # Always write a small status object on failure/skip; never stale model output.
    brief_data = (
        state.ai_brief.model_dump()
        if state.ai_brief
        else {"status": state.ai_brief_status.value}
    )
    (paths.reports / "ai_brief.json").write_text(
        json.dumps(redact_data(brief_data), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report = paths.reports / "report.md"
    generate_markdown_report(
        state.findings,
        "SAST source and DAST target are listed separately above",
        report,
    )
    status = (
        "FAILED / PARTIAL"
        if state.exit_code
        else "COMPLETED WITH WARNINGS"
        if state.finished and state.warnings
        else "COMPLETED"
        if state.finished
        else "RUNNING"
    )
    scope = [
        f"Run status: **{status}**",
        f"SAST source: {_inline(state.source_path or 'not configured')} (stage: {state.sast_status.value})",
        f"DAST target: {_inline(state.target_url or 'not configured')} (stage: {state.dast_status.value})",
        "Stages: " + ", ".join(f"{k}={v}" for k, v in summary["stages"].items()),
    ]
    if state.source_path and state.target_url:
        scope.append(
            "Source and HTTP target are independent inputs; their application identity is not verified. The default sample-app source and Juice Shop target are different applications."
        )
    if state.last_error:
        scope.append(
            f"Last error: {_inline(state.last_error_code or 'run_error')} — {_inline(state.last_error)}"
        )
    scope.extend(render_brief(state))
    lines = ["", "## Agent execution", "", f"Orchestration: {state.orchestration}", ""]
    for item in state.trace:
        decision_label = {
            "llm_planner": "LLM Planner",
            "deterministic_single_option": "automatic (only valid action)",
            "deterministic": "fixed deterministic workflow",
        }[item.decision_source]
        lines.append(
            f"{item.step}. {_inline(item.action)} — {decision_label} — {_inline(item.status)} — {item.findings_added} findings. {_inline(item.decision_reason)}"
        )
        if item.error:
            lines.append(
                f"   Error: {_inline(item.error_code or 'run_error')} — {_inline(item.error)}"
            )
    if state.finish_reason:
        lines.extend(["", "Finish: " + _inline(state.finish_reason)])
    report.write_text(
        redact(
            report.read_text(encoding="utf-8").replace(
                "# Security Scan Report\n",
                "# Security Scan Report\n\n" + "\n\n".join(scope) + "\n",
                1,
            )
            + "\n".join(lines)
            + "\n"
        ),
        encoding="utf-8",
    )


def finalize(state: AgentState, paths: RunPaths, metadata: dict | None = None) -> None:
    """Best-effort final report even after planner or scanner failure."""
    state.finished = True
    if state.report_status != Status.FAILED:
        state.report_status = Status.COMPLETED
    try:
        write_reports(state, paths, metadata)
    except OSError:
        state.report_status = Status.FAILED
        state.exit_code = state.exit_code or 6
        state.last_error = (
            "Reports could not be written; check run directory permissions"
        )


def render_brief(state: AgentState) -> list[str]:
    if not state.ai_brief:
        return [f"AI Security Brief: {state.ai_brief_status.value}."]
    brief = state.ai_brief
    lines = [
        "## AI Security Brief",
        _inline(brief.headline),
        _inline(brief.overall_summary),
    ]
    lines += ["Top findings:"]
    lines += [
        f"- {_inline(item.finding_id)}: {_inline(item.why_it_matters)}"
        for item in brief.top_findings
    ]
    lines += ["Recommended next steps:"]
    lines += [f"- {_inline(step)}" for step in brief.recommended_next_steps]
    lines += ["Limitations: " + _inline(brief.limitations), _inline(brief.closing_line)]
    return lines
