"""Authoritative deterministic action permissions; planner is untrusted."""

from app.agent.models import Action, AgentState, Status
from app.validation import validate_source_path, validate_target_url

TERMINAL = {
    Status.COMPLETED,
    Status.COMPLETED_WITH_FAILURES,
    Status.SKIPPED,
    Status.FAILED,
}
STAGES = {
    Action.RUN_SAST: "sast_status",
    Action.RUN_DAST: "dast_status",
    Action.ENRICH_FINDINGS: "enrichment_status",
    Action.GENERATE_AI_BRIEF: "ai_brief_status",
    Action.GENERATE_REPORT: "report_status",
}


class ActionValidator:
    def validate(self, action: Action, state: AgentState) -> None:
        if not isinstance(action, Action):
            raise ValueError("Unknown action")
        if state.finished:
            raise ValueError("Run is already finished")
        if action in state.executed_actions:
            raise ValueError("Action already attempted")
        stage = STAGES.get(action)
        if stage and getattr(state, stage) != Status.NOT_STARTED:
            raise ValueError("Stage is not eligible")
        if action == Action.RUN_SAST:
            if not (
                state.source_available and state.source_validated and state.source_path
            ):
                raise ValueError("Validated source is required")
            validate_source_path(state.source_path)
        elif action == Action.RUN_DAST:
            if not (
                state.target_validated and state.target_available and state.target_url
            ):
                raise ValueError("Validated reachable target is required")
            validate_target_url(state.target_url)
        elif action == Action.ENRICH_FINDINGS:
            if not self.scanning_terminal(state) or not state.findings:
                raise ValueError(
                    "Complete scanning before enrichment; findings required"
                )
            if Status.COMPLETED not in (state.sast_status, state.dast_status):
                raise ValueError("A successful scanner is required")
        elif action in (Action.GENERATE_AI_BRIEF, Action.GENERATE_REPORT):
            if not self.scanning_terminal(state):
                raise ValueError("Complete scanning before reporting")
            if state.enrichment_status not in TERMINAL:
                raise ValueError("Complete or skip enrichment before reporting")
            if (
                action == Action.GENERATE_REPORT
                and state.ai_brief_status not in TERMINAL
            ):
                raise ValueError("Complete or skip AI brief before reporting")
        elif action == Action.FINISH:
            if state.report_status != Status.COMPLETED and not (
                state.exit_code
                and self.scanning_terminal(state)
                and state.report_status == Status.FAILED
            ):
                raise ValueError("A report or terminal reporting failure is required")

    @staticmethod
    def scanning_terminal(state: AgentState) -> bool:
        return state.sast_status in TERMINAL and state.dast_status in TERMINAL

    def allowed(self, state: AgentState) -> list[Action]:
        allowed = []
        for action in Action:
            try:
                self.validate(action, state)
                allowed.append(action)
            except (ValueError, OSError):
                pass
        return allowed
