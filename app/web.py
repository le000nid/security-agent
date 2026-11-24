"""Loopback-only web adapter. No scanner subprocesses or Docker control here."""

import secrets
import time
from collections import deque
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict

from app import __version__
from app.benchmarks import BenchmarkId, Mode
from app.chat import ChatController, ChatLLM, ChatRequest, ScanConfirmation
from app.http_guard import (
    header_safe,
    no_scheme,
    read_filters,
    safe_segment,
)
from app.jobs import JobManager
from app.repository import RunRepository
from app.service import RunRequest, RunService


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    benchmark_id: BenchmarkId
    mode: Mode | None = None
    orchestration: Literal["scan", "agent"] = "scan"
    llm_enabled: bool = False
    include_evidence_in_llm: bool = False
    report_tone: Literal["professional", "concise", "funny"] = "professional"
    report_language: Literal["ru", "en"] = "ru"


ERRORS = {
    "benchmark_not_found",
    "benchmark_mode_not_supported",
    "scan_already_running",
    "llm_unavailable",
    "llm_busy",
    "agent_requires_llm",
    "run_not_found",
    "invalid_run_id",
    "run_unreadable",
    "invalid_report_file",
    "job_not_found",
    "finding_not_found",
    "benchmark_required",
    "worker_unavailable",
    "unsupported_intent",
    "chat_response_truncated",
    "chat_json_invalid",
    "chat_schema_invalid",
    "chat_context_mismatch",
    "chat_internal_error",
    "proposal_expired",
}

# brute-force resistance: POSTs are throttled per sliding window
POST_RATE_LIMIT = 30  # max POSTs ...
POST_RATE_WINDOW = 60.0  # ... per this many seconds
MAX_QUERY_CHARS = 2_000  # a longer query string is an attack, not a filter
MAX_HEADERS = 60  # header-count cap (request smuggling / parser abuse)

# codes raised by app.http_guard — surfaced as 400, never echoing the input
GUARD_ERRORS = {
    "invalid_text",
    "invalid_path_segment",
    "invalid_report_file",
    "invalid_run_id",
    "invalid_header_value",
    "duplicate_parameter",
    "input_too_long",
    "path_outside_base",
    "rate_limited",
    "query_too_long",
    "too_many_headers",
    "invalid_uri_scheme",
}


def create_app(
    *,
    runs_dir: Path = Path("runs"),
    service: RunService | None = None,
    llm: ChatLLM | None = None,
) -> FastAPI:
    app = FastAPI(
        title="AI Security Agent",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    service = service or RunService(runs_dir)
    repository = RunRepository(runs_dir)
    jobs = JobManager(service)
    llm = llm or ChatLLM()
    chat = ChatController(service.benchmarks, repository, jobs, llm)
    token = secrets.token_urlsafe(32)
    app.state.jobs, app.state.repository, app.state.chat = jobs, repository, chat
    app.state.post_times = deque()
    assets = Path(__file__).with_name("ui")
    templates = Jinja2Templates(directory=assets / "templates")
    app.mount("/static", StaticFiles(directory=assets / "static"), name="static")

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.headers.get("host", "")
        try:
            parsed = urlsplit("http://" + host)
            valid_host = (
                parsed.hostname in {"127.0.0.1", "localhost"}
                and parsed.username is None
                and parsed.password is None
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
            )
            _ = parsed.port
        except ValueError:
            valid_host = False
        if not valid_host:
            return JSONResponse({"error": "host_not_allowed"}, status_code=403)
        # header-count cap: parser abuse and smuggling helpers
        if len(request.headers) > MAX_HEADERS:
            return JSONResponse({"error": "too_many_headers"}, status_code=400)
        # query budget: long encoded chains are traversal probes, not filters
        if len(request.url.query) > MAX_QUERY_CHARS:
            return JSONResponse({"error": "query_too_long"}, status_code=414)
        if request.method == "POST":
            now = time.monotonic()
            bucket = request.app.state.post_times
            while bucket and now - bucket[0] > POST_RATE_WINDOW:
                bucket.popleft()
            if len(bucket) >= POST_RATE_LIMIT:
                return JSONResponse({"error": "rate_limited"}, status_code=429)
            bucket.append(now)
            origin = request.headers.get("origin")
            if (
                (origin and origin != f"{request.url.scheme}://{host}")
                or request.headers.get("sec-fetch-site") == "cross-site"
                or not secrets.compare_digest(
                    request.headers.get("x-csrf-token", ""), token
                )
            ):
                return JSONResponse({"error": "csrf_failed"}, status_code=403)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 16_384:
                    return JSONResponse({"error": "request_too_large"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response

    @app.exception_handler(ValueError)
    async def safe_value_error(request, exc):
        code = str(exc) if str(exc) in ERRORS | GUARD_ERRORS else "invalid_request"
        status = (
            409
            if code == "scan_already_running"
            else 404
            if code in {"run_not_found", "job_not_found", "finding_not_found"}
            else 503
            if code in {"llm_unavailable", "llm_busy"}
            else 400
        )
        return JSONResponse({"error": code}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def safe_schema_error(request, exc):
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @app.exception_handler(Exception)
    async def safe_error(request, exc):
        return JSONResponse({"error": "internal_error"}, status_code=500)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"csrf_token": token, "version": __version__},
        )

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/benchmarks")
    def benchmarks():
        return [b.ui_metadata() for b in service.benchmarks.list()]

    @app.get("/api/runs")
    def runs():
        return repository.list()

    @app.get("/api/runs/{run_id}")
    def detail(run_id: str, request: Request):
        safe_segment(run_id, code="invalid_run_id")
        return repository.detail(run_id)

    @app.get("/api/runs/{run_id}/findings")
    def findings(run_id: str, request: Request):
        safe_segment(run_id, code="invalid_run_id")
        filters = read_filters(request.query_params)
        return repository.findings(
            run_id,
            severity=filters.severity,
            source=filters.source,
            category=filters.category,
        )

    @app.get("/api/runs/{run_id}/artifacts/{filename}")
    def artifact(run_id: str, filename: str):
        safe_segment(run_id, code="invalid_run_id")
        no_scheme(filename, code="invalid_report_file")
        safe_segment(filename, code="invalid_report_file")
        text = repository.text(run_id, filename)
        safe_name = header_safe(filename)
        return PlainTextResponse(
            text,
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )

    @app.post("/api/scans", status_code=202)
    def start_scan(request: ScanRequest):
        return jobs.start(
            RunRequest.model_validate_json(request.model_dump_json())
        ).model_dump(mode="json")

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        safe_segment(job_id, code="job_not_found")
        return jobs.get(job_id).model_dump(mode="json")

    @app.get("/api/llm")
    def llm_status():
        return llm.status()

    @app.post("/api/llm/check")
    def check_llm():
        return llm.check()

    @app.post("/api/chat")
    def chat_message(request: ChatRequest):
        return chat.handle(request)

    @app.post("/api/chat/confirm")
    def confirm_scan(request: ScanConfirmation):
        return chat.confirm(request)

    return app
