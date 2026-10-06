"""Registry/service regressions; scanners and every provider request are mocked."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.agent.models import Action, AgentAction
from app.benchmarks import Benchmark, BenchmarkRegistry
from app.brief import brief_input
from app.config import Settings
from app.events import emit
from app.llm import LLMUsage
from app.models import Finding
from app.repository import RunRepository
from app.service import RunRequest, RunService
from app.validation import validate_target_url


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.service.Settings.from_env", lambda: Settings(llm_brief_enabled=False)
    )
    expected = json.loads(Path("config/expected/demo-full.json").read_text())
    findings = [
        Finding(
            id=str(i),
            **item,
            severity="high" if item["source"] == "SAST" else "info",
            raw_output_ref="logs/raw.json",
            description="Observed test finding",
        )
        for i, item in enumerate(expected)
    ]
    monkeypatch.setattr("app.agent.tools.run_semgrep", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.run_nuclei", lambda *_: None)
    monkeypatch.setattr(
        "app.agent.tools.parse_semgrep_json",
        lambda *_: [f for f in findings if f.source == "SAST"],
    )
    monkeypatch.setattr(
        "app.agent.tools.parse_nuclei_jsonl",
        lambda *_: [f for f in findings if f.source == "DAST"],
    )
    no_client = Mock(side_effect=AssertionError("No LLM calls permitted"))
    return RunService(tmp_path / "runs", client_factory=no_client, preflight=Mock())


def test_builtin_registry():
    registry = BenchmarkRegistry.load()
    assert {b.id for b in registry.list()} == {
        "sample-sast",
        "juice-shop",
        "demo-full",
        "sast-contours",
    }
    assert registry.trusted_hosts() == {"juice-shop", "demo-full"}
    assert validate_target_url("http://demo-full:3000") == "http://demo-full:3000"
    assert Path(registry.get("demo-full").local_source()).is_dir()
    with pytest.raises(ValueError, match="benchmark_not_found"):
        registry.get("unknown")


@pytest.mark.parametrize(
    "change",
    [
        {"id": "../bad"},
        {"id": "Bad id"},
        {"capabilities": ["network"]},
        {"capabilities": ["sast", "sast"]},
        {"source_path": "/etc"},
        {"source_path": "/targets/../etc"},
        {"source_path": "https://evil.example"},
        {"source_path": "/targets/a//b"},
        {"source_path": "/targets/a\\b"},
        {"target_url": "http://example.com", "capabilities": ["sast", "dast"]},
        {"docker_service": "evil.example"},
        {"expected_findings": "../secret.json"},
        {"enabled": "true"},
        {"command": "whoami"},
    ],
)
def test_invalid_registry_entries(change):
    data = BenchmarkRegistry.load().get("sample-sast").model_dump()
    with pytest.raises(ValidationError):
        Benchmark.model_validate({**data, **change})


def test_duplicate_and_disabled_registry():
    entry = BenchmarkRegistry.load().get("sample-sast")
    with pytest.raises(ValueError, match="duplicate_benchmark_id"):
        BenchmarkRegistry([entry, entry])
    disabled = BenchmarkRegistry([entry.model_copy(update={"enabled": False})])
    assert disabled.list() == []
    with pytest.raises(ValueError):
        disabled.get(entry.id)


@pytest.mark.parametrize(
    "benchmark,mode,count",
    [("sample-sast", "sast", 4), ("juice-shop", "dast", 3), ("demo-full", "full", 7)],
)
def test_benchmark_service_without_llm(service, benchmark, mode, count):
    events = []
    result = service.run(RunRequest(benchmark_id=benchmark), events.append)
    assert result.status == "completed" and result.findings_count == count
    service.client_factory.assert_not_called()
    summary = RunRepository(service.runs_dir).detail(result.run_id)
    assert summary["benchmark_id"] == benchmark and summary["mode"] == mode
    assert summary["llm_usage"]["total"]["requests"] == 0
    assert summary["stages"]["enrichment"] == summary["stages"]["ai_brief"] == "skipped"
    assert events[0].event == "run_created" and events[-1].event == "run_completed"
    assert any(e.event == "stage_started" for e in events)
    if benchmark == "demo-full":
        assert summary["same_application"]
        assert summary["benchmark_evaluation"]["recall"] == 1
        assert summary["benchmark_evaluation"]["precision"] == 1
        report = (Path(result.reports_path) / "report.md").read_text()
        assert "same application project" in report
        assert "different applications" not in report


@pytest.mark.parametrize(
    "run_request",
    [
        RunRequest(benchmark_id="juice-shop", mode="sast"),
        RunRequest(benchmark_id="sample-sast", mode="full"),
        RunRequest(benchmark_id="demo-full", target_url="http://localhost:3000"),
        RunRequest(benchmark_id="sample-sast", source_path="targets/sample-app"),
        RunRequest(benchmark_id="unknown"),
        RunRequest(benchmark_id="demo-full", orchestration="agent"),
        RunRequest(mode="sast"),
        RunRequest(target_url="http://evil.example"),
    ],
)
def test_invalid_run_requests(service, run_request):
    with pytest.raises(ValueError):
        service.run(run_request)
    assert not service.runs_dir.exists()


def test_legacy_direct_same_identity_not_assumed(service):
    result = service.run(
        RunRequest(source_path="targets/sample-app", target_url="http://localhost:3000")
    )
    summary = RunRepository(service.runs_dir).summary(result.run_id)
    assert summary["benchmark_id"] is None and not summary["same_application"]
    assert (
        "different applications"
        in (Path(result.reports_path) / "report.md").read_text()
    )


def test_partial_dast_failure_preserves_sast(service):
    service.preflight.side_effect = ValueError("private exception")
    result = service.run(RunRequest(benchmark_id="demo-full"))
    assert result.status == "failed" and result.findings_count == 4
    assert (
        "private exception"
        not in (Path(result.reports_path) / "summary.json").read_text()
    )


def test_agent_service_wiring(service, monkeypatch):
    client = Mock()
    client.usage = LLMUsage()
    client.planner_usage = LLMUsage()
    client.brief_usage = LLMUsage()
    client.public_metadata.return_value = {"provider": "mock"}
    service.client_factory = Mock(return_value=client)
    planner = Mock()
    planner.choose.return_value = AgentAction(
        action=Action.RUN_DAST, reasoning_short="Approved ordering"
    )
    service.planner_factory = Mock(return_value=planner)
    # The enrichment layer is already covered exhaustively by the v0.3 suite.
    client.enrich.side_effect = ValueError("offline")
    result = service.run(
        RunRequest(benchmark_id="demo-full", orchestration="agent", llm_enabled=True)
    )
    assert result.findings_count == 7 and result.status == "completed_with_warnings"
    planner.choose.assert_called_once()
    client.ensure_model_available.assert_called_once()
    trace = RunRepository(service.runs_dir).detail(result.run_id)["trace"]
    assert trace[0]["action"] == "RUN_DAST"
    assert trace[1]["decision_source"] == "deterministic_single_option"


def test_observer_failure_is_nonfatal(service):
    def broken(event):
        raise RuntimeError("presentation failed")

    assert service.run(RunRequest(benchmark_id="demo-full"), broken).exit_code == 0
    emit(None, None)


def test_brief_projection_knows_same_application():
    from app.agent.models import AgentState

    state = AgentState(run_id="test", same_application=True)
    assert "Same application" in brief_input(state)["run"]["subjects_correspondence"]
