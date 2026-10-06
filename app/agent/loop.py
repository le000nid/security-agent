"""Bounded explicit planner -> validator -> tool -> state machine."""

import logging

from app.agent.models import Action, AgentState, Status, TraceEntry
from app.agent.planner import Planner
from app.agent.reporting import finalize
from app.agent.tools import ToolRegistry, apply_result
from app.agent.validator import STAGES, ActionValidator
from app.config import Settings
from app.llm_output import LLMError
from app.safe_logging import redact


def sync_usage(state: AgentState, registry: ToolRegistry) -> None:
    if registry.client:
        state.llm_usage.planner = registry.client.planner_usage.model_copy()
        state.llm_usage.enrichment = registry.client.usage.model_copy()
        state.llm_usage.brief = registry.client.brief_usage.model_copy()


def execute_action(
    action: Action,
    reason: str,
    state: AgentState,
    registry: ToolRegistry,
    decision_source: str = "deterministic",
) -> None:
    from app.events import RunEvent, emit

    emit(
        registry.observer,
        RunEvent(
            event="stage_started",
            run_id=state.run_id,
            action=action.value,
            status="running",
            findings_count=len(state.findings),
        ),
    )
    if action == Action.FINISH:
        state.finished = True
        state.finish_reason = (
            "completed_with_failures"
            if state.exit_code
            else "completed_with_warnings"
            if state.warnings
            else "completed"
        )
        state.executed_actions.append(action)
        state.trace.append(
            TraceEntry(
                step=len(state.trace) + 1,
                action=action.value,
                decision_source=decision_source,
                decision_reason=redact(reason),
                status="completed",
            )
        )
        emit(
            registry.observer,
            RunEvent(
                event="stage_completed",
                run_id=state.run_id,
                action=action.value,
                status="completed",
                findings_count=len(state.findings),
            ),
        )
        return
    result = registry.execute(action, state)
    apply_result(state, result)
    emit(
        registry.observer,
        RunEvent(
            event="stage_completed" if result.success else "stage_warning",
            run_id=state.run_id,
            action=action.value,
            status=result.status.value,
            findings_count=len(state.findings),
            message=result.error_code,
        ),
    )
    sync_usage(state, registry)
    state.trace.append(
        TraceEntry(
            step=len(state.trace) + 1,
            action=action.value,
            decision_source=decision_source,
            decision_reason=redact(reason),
            status=result.status.value,
            findings_added=result.findings_added,
            duration_ms=result.duration_ms,
            error=result.error,
            error_code=result.error_code,
        )
    )
    logging.getLogger("security_agent").info(
        "%s: %s (%d findings)", action.value, result.status.value, result.findings_added
    )
    if result.error:
        logging.getLogger("security_agent").error(
            "%s: %s", result.error_code, result.error
        )


def skip_empty_enrichment(state: AgentState) -> None:
    if ActionValidator.scanning_terminal(state) and not state.findings:
        if state.enrichment_status == Status.NOT_STARTED:
            state.enrichment_status = Status.SKIPPED


def run_agent(
    state: AgentState, planner: Planner, registry: ToolRegistry, settings: Settings
) -> AgentState:
    prepare_optional_stages(state, registry)
    validator = ActionValidator()
    rejected = 0
    while not state.finished:
        skip_empty_enrichment(state)
        if state.agent_step_count >= settings.agent_max_steps:
            state.exit_code = state.exit_code or 5
            state.finish_reason = "agent_limit_reached"
            state.last_error_code = "agent_step_limit_reached"
            state.last_error = "Executed action limit reached before FINISH."
            break
        allowed = validator.allowed(state)
        if not allowed:
            state.exit_code = state.exit_code or 6
            state.finish_reason = "no_allowed_actions"
            state.last_error_code = "agent_no_allowed_actions"
            state.last_error = "No approved action satisfies current preconditions."
            break
        single = len(allowed) == 1
        if (
            not single
            and state.planner_request_count >= settings.agent_max_planner_calls
        ):
            state.exit_code = state.exit_code or 5
            state.finish_reason = "agent_limit_reached"
            if state.last_error is None:
                state.last_error_code = "planner_request_limit_reached"
                state.last_error = (
                    "Planner request limit reached while a choice is still required."
                )
            break
        source = "deterministic_single_option" if single else "llm_planner"
        action = "INVALID"
        try:
            if single:
                selected = allowed[0]
                reason = f"{selected.value} is the only remaining valid action."
            else:
                decision = planner.choose(
                    state, settings.agent_max_steps - state.agent_step_count
                )
                selected, reason = decision.action, decision.reasoning_short
            action = selected.value
            try:
                validator.validate(selected, state)
            except (ValueError, OSError):
                raise LLMError("planner", "action_not_allowed") from None
        except Exception as exc:
            sync_usage(state, registry)
            rejected += 1
            safe = (
                exc if isinstance(exc, LLMError) else LLMError("planner", "unavailable")
            )
            state.last_error, state.last_error_code = safe.message, safe.code
            logging.getLogger("security_agent").warning(
                "%s: %s", safe.code, safe.message
            )
            state.trace.append(
                TraceEntry(
                    step=len(state.trace) + 1,
                    action=action,
                    decision_source=source,
                    decision_reason="Decision rejected by application",
                    status="rejected",
                    error=state.last_error,
                    error_code=state.last_error_code,
                )
            )
            if rejected >= 3:
                state.exit_code = state.exit_code or 5
                state.finish_reason = "planner_rejections_exhausted"
                break
            continue
        rejected = 0
        state.agent_step_count += 1
        try:
            execute_action(selected, reason, state, registry, source)
        except (ValueError, OSError):
            # A source can disappear after planner validation but before dispatch.
            state.exit_code = state.exit_code or 6
            state.last_error = "Tool preconditions changed before execution"
            state.last_error_code = "tool_preconditions_failed"
            state.agent_step_count -= 1
            state.finish_reason = "tool_preconditions_failed"
            state.trace.append(
                TraceEntry(
                    step=len(state.trace) + 1,
                    action=selected.value,
                    decision_source=source,
                    decision_reason="Dispatch rejected by application",
                    status="rejected",
                    error=state.last_error,
                    error_code=state.last_error_code,
                )
            )
            break
    sync_usage(state, registry)
    finalize(
        state,
        registry.paths,
        registry.client.public_metadata() if registry.client else None,
    )
    return state


def run_deterministic(state: AgentState, registry: ToolRegistry) -> AgentState:
    prepare_optional_stages(state, registry)
    validator = ActionValidator()
    for action in Action:
        skip_empty_enrichment(state)
        if action not in validator.allowed(state):
            stage = STAGES.get(action)
            if stage and getattr(state, stage) == Status.NOT_STARTED:
                setattr(state, stage, Status.FAILED)
                state.failed_actions.append(action)
                state.exit_code = state.exit_code or 6
                state.last_error = "Requested stage preconditions are unavailable"
                state.last_error_code = "tool_preconditions_failed"
            continue
        state.agent_step_count += 1
        try:
            execute_action(action, "Fixed deterministic sequence", state, registry)
        except (ValueError, OSError):
            state.exit_code = state.exit_code or 6
            state.agent_step_count -= 1
            state.last_error = "Tool preconditions changed before execution"
            state.last_error_code = "tool_preconditions_failed"
            state.finish_reason = "tool_preconditions_failed"
            break
    state.finish_reason = state.finish_reason or "completed_with_failures"
    sync_usage(state, registry)
    finalize(
        state,
        registry.paths,
        registry.client.public_metadata() if registry.client else None,
    )
    return state


def prepare_optional_stages(state: AgentState, registry: ToolRegistry) -> None:
    if state.ai_brief_status == Status.NOT_STARTED and (
        registry.client is None or not registry.settings.llm_brief_enabled
    ):
        state.ai_brief_status = Status.SKIPPED
