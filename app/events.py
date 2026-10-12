"""Small typed, best-effort observer API; never contains raw output or prompts."""

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict


class RunEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    event: Literal[
        "run_created",
        "stage_started",
        "stage_completed",
        "stage_warning",
        "run_completed",
    ]
    run_id: str
    action: str | None = None
    status: str | None = None
    findings_count: int = 0
    message: str | None = None


Observer = Callable[[RunEvent], None]


def emit(observer: Observer | None, event: RunEvent) -> None:
    if observer:
        try:
            observer(event)
        except Exception:
            pass  # Presentation failure must not cancel scanning or persistence.
