import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.agent.loop import run_agent, run_deterministic
from app.agent.models import Action, AgentAction, AgentState, Status
from app.agent.planner import Planner, planner_input
from app.agent.tools import ToolRegistry
from app.agent.validator import ActionValidator
from app.cli import run
from app.config import Settings
from app.llm import Enrichment, LLMUsage
from app.models import Finding
from app.runs import RunPaths


@pytest.fixture
def state(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("pass", encoding="utf-8")
    return AgentState(
        run_id="test",
        source_path=str(source),
        source_available=True,
        source_validated=True,
        target_url="http://localhost:3000",
        target_validated=True,
        target_available=True,
    )


@pytest.fixture
def findings():
    return [
        Finding(
            id="sast",
            title="Debug",
            source="SAST",
            tool="semgrep",
            category="configuration",
            evidence="private code",
            raw_output_ref="logs/private.json",
        )
    ]


@pytest.fixture
def client():
    client = Mock()
    client.planner_usage = LLMUsage()
    client.usage = LLMUsage()
    client.brief_usage = LLMUsage()
    client.complete_json.return_value = json.dumps(
        {
            "headline": "Security review",
            "overall_summary": "Review scanner findings.",
            "top_findings": [],
            "recommended_next_steps": ["Review findings."],
            "limitations": "Limited checks only.",
            "closing_line": "Review before release.",
        }
    )
    client.public_metadata.return_value = {"provider": "mock"}
    client.enrich.return_value = Enrichment(
        description="Observed debug setting.",
        severity="low",
        normalized_category="debug_configuration",
        recommendation="Disable debug.",
        reasoning_short="Scanner match.",
    )
    return client


@pytest.fixture
def registry(monkeypatch, tmp_path, findings, client):
    monkeypatch.setattr("app.agent.tools.run_semgrep", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.run_nuclei", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: findings)
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: [])
    return ToolRegistry(RunPaths.create(tmp_path / "runs"), client)


def planner_for(*actions):
    planner = Mock()
    sequence = iter(actions)

    def choose(state, _remaining):
        # This fake simulates one completion HTTP attempt per choice.
        state.planner_request_count += 1
        return AgentAction(
            action=next(sequence), reasoning_short="Next approved stage."
        )

    planner.choose.side_effect = choose
    return planner


def test_initial_state_and_serialization(state):
    assert state.sast_status == Status.NOT_STARTED
    assert not state.finished and state.agent_step_count == 0
    assert state.findings == []
    assert "api_key" not in state.model_dump_json()
    with pytest.raises(ValidationError):
        AgentState(run_id="bad", LLM_API_KEY="secret")


@pytest.mark.parametrize("action", list(Action))
def test_action_json_valid(action):
    assert (
        AgentAction.model_validate_json(
            json.dumps({"action": action.value, "reasoning_short": "Next."})
        ).action
        == action
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "SHELL", "reasoning_short": "Run"},
        {"action": "RUN_SAST", "reasoning_short": "Run", "command": "whoami"},
        {
            "action": "RUN_DAST",
            "reasoning_short": "Run",
            "target_url": "https://example.com",
        },
        {"action": "RUN_SAST", "reasoning_short": " "},
        {"action": "RUN_SAST", "reasoning_short": "x" * 301},
        {"action": "FINISH"},
    ],
)
def test_action_rejects_untrusted_payload(payload):
    with pytest.raises(ValidationError):
        AgentAction.model_validate_json(json.dumps(payload))


def test_validator_sequence_and_duplicates(state, findings):
    validator = ActionValidator()
    assert validator.allowed(state) == [Action.RUN_SAST, Action.RUN_DAST]
    state.sast_status = Status.COMPLETED
    state.findings = findings
    assert validator.allowed(state) == [Action.RUN_DAST]
    state.dast_status = Status.COMPLETED
    assert validator.allowed(state) == [Action.ENRICH_FINDINGS]
    state.enrichment_status = Status.COMPLETED
    assert validator.allowed(state) == [Action.GENERATE_AI_BRIEF]
    state.ai_brief_status = Status.COMPLETED
    assert validator.allowed(state) == [Action.GENERATE_REPORT]
    state.report_status = Status.COMPLETED
    assert validator.allowed(state) == [Action.FINISH]
    state.finished = True
    assert validator.allowed(state) == []


@pytest.mark.parametrize(
    "attribute,value,action",
    [
        ("source_validated", False, Action.RUN_SAST),
        ("source_available", False, Action.RUN_SAST),
        ("source_path", "/does/not/exist", Action.RUN_SAST),
        ("target_validated", False, Action.RUN_DAST),
        ("target_available", False, Action.RUN_DAST),
        ("target_url", "https://example.com", Action.RUN_DAST),
        ("sast_status", Status.RUNNING, Action.RUN_SAST),
        ("dast_status", Status.FAILED, Action.RUN_DAST),
    ],
)
def test_validator_checks_actual_preconditions(state, attribute, value, action):
    setattr(state, attribute, value)
    with pytest.raises((ValueError, OSError)):
        ActionValidator().validate(action, state)


def test_normal_loop_and_reports(state, registry):
    planner = planner_for(*Action)
    run_agent(state, planner, registry, Settings())
    assert state.finished and state.exit_code == 0
    assert state.executed_actions == list(Action)
    assert state.planner_request_count == 1
    planner.choose.assert_called_once()
    assert len(state.findings) == 1 and state.findings[0].category == "configuration"
    assert state.findings[0].evidence == "private code"
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["status"] == "completed" and summary["version"] == "0.4.1"
    assert summary["agent_steps"] == 6
    assert set(summary["llm_usage"]) == {"planner", "enrichment", "brief", "total"}
    trace = json.loads((registry.paths.reports / "agent_trace.json").read_text())
    assert [t["action"] for t in trace] == [a.value for a in Action]
    assert [t["decision_source"] for t in trace] == ["llm_planner"] + [
        "deterministic_single_option"
    ] * 5
    assert "## Agent execution" in (registry.paths.reports / "report.md").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("limits", [{"agent_max_steps": 1}])
def test_loop_limits_preserve_findings(state, registry, limits):
    run_agent(state, planner_for(Action.RUN_SAST), registry, Settings(**limits))
    assert state.exit_code == 5 and state.finish_reason == "agent_limit_reached"
    assert len(state.findings) == 1
    assert (registry.paths.reports / "findings.json").exists()


def test_repeated_invalid_decisions_never_execute(state, registry):
    planner = planner_for(Action.FINISH, Action.FINISH, Action.FINISH)
    run_agent(state, planner, registry, Settings())
    assert state.exit_code == 5 and state.agent_step_count == 0
    assert state.planner_request_count == 3
    assert state.executed_actions == []
    assert all(t.status == "rejected" for t in state.trace)


def test_duplicate_scanning_rejected(state, registry):
    planner = planner_for(
        Action.RUN_SAST, Action.RUN_SAST, Action.RUN_SAST, Action.RUN_SAST
    )
    run_agent(state, planner, registry, Settings())
    assert state.executed_actions == list(Action)
    planner.choose.assert_called_once()
    assert len(state.findings) == 1


def test_scanner_failure_preserves_other_results(monkeypatch, state, registry):
    monkeypatch.setattr(
        "app.agent.tools.run_nuclei", Mock(side_effect=RuntimeError("private secret"))
    )
    run_agent(state, planner_for(*Action), registry, Settings())
    assert state.exit_code == 3
    assert state.dast_status == Status.FAILED and len(state.findings) == 1
    assert "private secret" not in state.model_dump_json()


def test_enrichment_failure_preserves_scanner_findings(
    state, registry, client, findings
):
    client.enrich.side_effect = ValueError("Authorization: Bearer SECRET")
    run_agent(state, planner_for(*Action), registry, Settings())
    assert state.exit_code == 0 and state.finish_reason == "completed_with_warnings"
    assert state.findings == findings
    assert state.enrichment_status == Status.FAILED
    assert "SECRET" not in state.model_dump_json()


def test_planner_failure_preserves_scanner_findings(state, registry, findings):
    state.findings = findings
    planner = planner_for(Action.FINISH, Action.FINISH, Action.FINISH)
    run_agent(state, planner, registry, Settings())
    assert state.exit_code == 5 and len(state.findings) == 1


def test_planner_projection_contains_no_finding_or_path(state, findings, client):
    state.findings = findings
    state.goal = "SECRET custom input"
    state.last_error = "private provider error"
    state.recount()
    body = json.dumps(planner_input(state, 7))
    for private in (
        state.source_path,
        state.target_url,
        "private",
        "SECRET",
        "raw_output",
        "evidence",
    ):
        assert private not in body
    client.complete_json.return_value = (
        '{"action":"RUN_SAST","reasoning_short":"Source available."}'
    )
    assert Planner(client).choose(state, 7).action == Action.RUN_SAST
    assert client.complete_json.call_args.kwargs["role"] == "planner"


def test_registry_has_no_arbitrary_execution(state, registry):
    assert set(registry.tools) == set(Action) - {Action.FINISH}
    with pytest.raises(ValueError):
        registry.execute("whoami", state)
    with pytest.raises(TypeError):
        registry.tools["shell"] = Mock()


def test_deterministic_does_not_plan(state, registry):
    state.orchestration = "deterministic"
    state.enrichment_status = Status.SKIPPED
    registry.client = None
    run_deterministic(state, registry)
    assert state.planner_request_count == 0
    assert state.exit_code == 0
    assert state.executed_actions == [
        Action.RUN_SAST,
        Action.RUN_DAST,
        Action.GENERATE_REPORT,
        Action.FINISH,
    ]


def test_run_paths_are_unique_and_portable(tmp_path):
    first, second = RunPaths.create(tmp_path), RunPaths.create(tmp_path)
    assert first.root != second.root
    assert first.logs.is_dir() and second.reports.is_dir()
    assert ":" not in first.run_id
    assert json.loads((tmp_path / "latest.json").read_text())["run_id"] == second.run_id


def test_config_never_serializes_secret(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sentinel-secret")
    settings = Settings.from_env()
    assert "sentinel-secret" not in settings.model_dump_json()
    assert "sentinel-secret" not in repr(settings)
    with pytest.raises(ValidationError):
        Settings(agent_max_steps=0)


def test_new_cli_scanner_only(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr("app.cli.check_target_reachable", lambda _: None)
    monkeypatch.setattr(
        "app.cli.OpenAICompatibleClient", Mock(side_effect=AssertionError("no LLM"))
    )
    monkeypatch.setattr("app.agent.tools.run_nuclei", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: [])
    assert run(["scan", "--target-url", "http://localhost:3000", "--no-llm"]) == 0
    latest = json.loads(Path("runs/latest.json").read_text())["run_id"]
    assert Path("runs", latest, "reports", "agent_trace.json").is_file()


def test_agent_requires_llm(monkeypatch):
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    assert run(["agent", "--target-url", "http://localhost:3000", "--no-llm"]) == 2


def test_report_not_allowed_with_pending_scanners(state):
    with pytest.raises(ValueError):
        ActionValidator().validate(Action.GENERATE_REPORT, state)


def test_finish_on_terminal_report_failure(state):
    state.sast_status = state.dast_status = Status.FAILED
    state.report_status = Status.FAILED
    state.exit_code = 6
    ActionValidator().validate(Action.FINISH, state)


def test_zero_findings_skip_enrichment(monkeypatch, state, registry):
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: [])
    run_agent(
        state,
        planner_for(
            Action.RUN_SAST, Action.RUN_DAST, Action.GENERATE_REPORT, Action.FINISH
        ),
        registry,
        Settings(),
    )
    assert state.enrichment_status == Status.SKIPPED and state.exit_code == 0
    registry.client.enrich.assert_not_called()


def test_trace_redacts_secret_and_remains_valid_json(monkeypatch, state, registry):
    monkeypatch.setenv("LLM_API_KEY", "sentinel-private-key")
    planner = Mock()
    planner.choose.side_effect = [
        AgentAction(
            action=a, reasoning_short="Authorization: Bearer sentinel-private-key"
        )
        for a in Action
    ]
    run_agent(state, planner, registry, Settings())
    for name in ("summary.json", "agent_trace.json"):
        text = (registry.paths.reports / name).read_text()
        json.loads(text)
        assert "sentinel-private-key" not in text
    assert "sentinel-private-key" not in state.model_dump_json()


def test_report_failure_preserves_findings(monkeypatch, state, registry):
    monkeypatch.setattr(
        "app.agent.tools.write_reports", Mock(side_effect=OSError("private failure"))
    )
    run_agent(state, planner_for(*Action), registry, Settings())
    assert state.exit_code == 6 and len(state.findings) == 1
    assert (registry.paths.reports / "findings.json").exists()


def test_new_cli_full_agent(monkeypatch, tmp_path, client, findings):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr("app.cli.check_target_reachable", lambda _: None)
    monkeypatch.setattr("app.cli.OpenAICompatibleClient", lambda **_: client)
    monkeypatch.setattr("app.cli.Planner", lambda _: planner_for(*Action))
    monkeypatch.setattr("app.agent.tools.run_semgrep", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.run_nuclei", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: findings)
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: [])
    assert (
        run(
            [
                "agent",
                "--target-url",
                "http://localhost:3000",
                "--source-path",
                str(tmp_path),
            ]
        )
        == 0
    )
    client.ensure_model_available.assert_called()
    latest = json.loads(Path("runs/latest.json").read_text())["run_id"]
    summary = json.loads(Path("runs", latest, "reports/summary.json").read_text())
    assert summary["orchestration"] == "agent" and summary["agent_steps"] == 6


def test_new_cli_failed_llm_preflight_saves_status(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr(
        "app.cli.OpenAICompatibleClient", Mock(side_effect=ValueError("private key"))
    )
    assert run(["agent", "--source-path", str(tmp_path)]) == 4
    latest = json.loads(Path("runs/latest.json").read_text())["run_id"]
    text = Path("runs", latest, "reports/summary.json").read_text()
    assert "private key" not in text
    assert json.loads(text)["status"] == "failed"


def test_new_cli_reachability_failure_does_not_scan_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr(
        "app.cli.check_target_reachable", Mock(side_effect=ValueError("offline"))
    )
    runner = Mock(side_effect=AssertionError("Must not scan"))
    monkeypatch.setattr("app.agent.tools.run_nuclei", runner)
    assert run(["scan", "--target-url", "http://localhost:3000", "--no-llm"]) == 6
    runner.assert_not_called()


def test_disappearing_source_cannot_produce_false_success(state, registry):
    Path(state.source_path).unlink()
    state.enrichment_status = Status.SKIPPED
    run_deterministic(state, registry)
    assert state.exit_code == 6 and state.sast_status == Status.FAILED
    assert state.finished and (registry.paths.reports / "summary.json").exists()


def test_dispatch_race_still_finalizes(monkeypatch, state, registry):
    monkeypatch.setattr(
        registry, "execute", Mock(side_effect=OSError("private source path"))
    )
    run_agent(state, planner_for(Action.RUN_SAST), registry, Settings())
    assert state.exit_code == 6 and state.finished
    assert state.trace[-1].status == "rejected"
    assert "private source path" not in state.model_dump_json()
    assert (registry.paths.reports / "summary.json").exists()
