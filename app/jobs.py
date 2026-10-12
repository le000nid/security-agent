"""Single-flight in-process worker; persisted reports remain authoritative."""

from collections import OrderedDict
from threading import Lock, Thread
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.events import RunEvent
from app.service import RunRequest, RunResult, RunService


class Job(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    job_id: str
    run_id: str | None = None
    status: Literal[
        "queued", "running", "completed", "completed_with_warnings", "failed"
    ] = "queued"
    events: list[RunEvent] = Field(default_factory=list)
    result: RunResult | None = None
    error: str | None = None


class JobManager:
    def __init__(self, service: RunService):
        self.service = service
        self._lock = Lock()
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._active: str | None = None

    def start(self, request: RunRequest) -> Job:
        self.service.resolve(request)
        with self._lock:
            if self._active is not None:
                raise ValueError("scan_already_running")
            job = Job(job_id=uuid4().hex)
            self._active = job.job_id
            self._jobs[job.job_id] = job
            while len(self._jobs) > 50:
                self._jobs.popitem(last=False)
            snapshot = job.model_copy(deep=True)
        try:
            Thread(
                target=self._execute, args=(job.job_id, request), daemon=True
            ).start()
        except RuntimeError:
            with self._lock:
                job.status, job.error, self._active = (
                    "failed",
                    "worker_unavailable",
                    None,
                )
            raise ValueError("worker_unavailable") from None
        return snapshot

    def get(self, job_id: str) -> Job:
        with self._lock:
            if job_id not in self._jobs:
                raise ValueError("job_not_found")
            return self._jobs[job_id].model_copy(deep=True)

    def _execute(self, job_id: str, request: RunRequest) -> None:
        def observe(event: RunEvent):
            with self._lock:
                job = self._jobs[job_id]
                job.run_id = event.run_id
                job.events.append(event)
                job.events = job.events[-100:]

        with self._lock:
            self._jobs[job_id].status = "running"
        try:
            result = self.service.run(request, observer=observe)
            with self._lock:
                job = self._jobs[job_id]
                job.result, job.status, job.run_id = (
                    result,
                    result.status,
                    result.run_id,
                )
        except Exception:
            with self._lock:
                self._jobs[job_id].status = "failed"
                self._jobs[job_id].error = "run_failed"
        finally:
            with self._lock:
                self._active = None
