"""v0.3.1 regressions use real contracts and mocked HTTP, never a live provider."""

import json
import logging
from unittest.mock import Mock

import httpx
import pytest
from pydantic import SecretStr

from app.agent.loop import run_agent
from app.agent.models import Action, AgentAction, AgentState, Status
from app.agent.planner import Planner
from app.agent.tools import ToolRegistry
from app.cli import run
from app.config import Settings
from app.llm import Enrichment, OpenAICompatibleClient
from app.llm_output import LLMError, validate_output
from app.models import Finding
from app.runs import RunPaths

DECISION = {"action": "RUN_SAST", "reasoning_short": "Source first."}
ENRICHMENT = {
    "description": "Observed setting.",
    "severity": "low",
    "normalized_category": "debug_configuration",
    "recommendation": "Review setting.",
    "reasoning_short": "Scanner evidence.",
}


def chat(content, finish="stop"):
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "finish_reason": finish,
                    "message": {
                        "content": content,
                        "reasoning": "PRIVATE-CHAIN-OF-THOUGHT",
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


@pytest.fixture
def rig(tmp_path, monkeypatch):
    source = tmp_path / "source.py"
    source.write_text("pass", encoding="utf-8")
    state = AgentState(
        run_id="test",
        source_path=str(source),
        source_available=True,
        source_validated=True,
        target_url="http://localhost:3000",
        target_available=True,
        target_validated=True,
    )
    client = OpenAICompatibleClient(
        settings=Settings(
            llm_provider="openai_compatible",
            llm_model="test-model",
            llm_base_url="https://example.invalid/api",
            llm_api_key=SecretStr("SECRET-KEY"),
        ),
        sleeper=lambda _: None,
    )
    client._model_available = True
    http = Mock()
    http.__enter__ = Mock(return_value=http)
    http.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("app.llm.httpx.Client", Mock(return_value=http))
    finding = Finding(
        id="sample",
        title="Debug",
        source="SAST",
        tool="semgrep",
        category="configuration",
        raw_output_ref="logs/raw_semgrep.json#/results/0",
    )
    monkeypatch.setattr("app.agent.tools.run_semgrep", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.run_nuclei", lambda *_: None)
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: [finding])
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: [])
    registry = ToolRegistry(
        RunPaths.create(tmp_path / "runs"),
        client,
        settings=Settings(llm_brief_enabled=False),
    )
    return state, client, http, registry, finding


@pytest.mark.parametrize(
    "wrapper", ["{}", " \n{}\n ", "```json\n{}\n```", "Result follows:\n{}\nEnd."]
)
@pytest.mark.parametrize(
    "payload,model,role",
    [(DECISION, AgentAction, "planner"), (ENRICHMENT, Enrichment, "enrichment")],
)
def test_shared_json_formats(wrapper, payload, model, role):
    assert validate_output(wrapper.format(json.dumps(payload)), model, role)


@pytest.mark.parametrize(
    "content,kind",
    [
        ("", "empty_content"),
        ("   ", "empty_content"),
        ("not json", "json_decode_error"),
        ('{"action":', "json_decode_error"),
        ("{} {}", "json_decode_error"),
        ("[{}]", "json_decode_error"),
        ('{"broken": {"action":"RUN_SAST"}', "json_decode_error"),
        ('{"action":"RUN_SAST","action":"RUN_DAST"}', "json_decode_error"),
        ("```json\n{}\n```\n```json\n{}\n```", "json_decode_error"),
        (json.dumps({**DECISION, "action": "SHELL SECRET-KEY"}), "unknown_action"),
        (
            json.dumps({**DECISION, "SECRET-KEY": "PRIVATE-CHAIN-OF-THOUGHT"}),
            "schema_validation_error",
        ),
    ],
)
def test_planner_safe_parse_diagnostics(content, kind):
    with pytest.raises(LLMError) as caught:
        validate_output(content, AgentAction, "planner")
    assert caught.value.code == "planner_" + kind
    assert "SECRET-KEY" not in str(caught.value)
    assert "PRIVATE-CHAIN" not in str(caught.value)


@pytest.mark.parametrize("role", ["planner", "enrichment"])
@pytest.mark.parametrize(
    "outcome,kind",
    [
        (httpx.Response(401), "http_error"),
        (httpx.Response(429), "rate_limited"),
        (httpx.ReadTimeout("SECRET-KEY"), "timeout"),
        (chat(None), "empty_content"),
        (chat(""), "empty_content"),
        (chat("{}", "length"), "response_truncated"),
        (chat([]), "schema_validation_error"),
    ],
)
def test_completion_diagnostics_and_actual_request_accounting(rig, role, outcome, kind):
    _, client, http, _, _ = rig
    http.request.side_effect = [outcome] * 3
    with pytest.raises(LLMError) as caught:
        client.complete_json("test", "test", max_tokens=160, role=role)
    assert caught.value.code == role + "_" + kind
    assert "SECRET-KEY" not in str(caught.value)
    usage = client.planner_usage if role == "planner" else client.usage
    assert usage.requests == http.request.call_count
    if role == "planner":
        assert usage.requests == 1


@pytest.mark.parametrize("first", [Action.RUN_SAST, Action.RUN_DAST])
def test_full_agent_one_actual_planner_call_and_no_reasoning_leak(rig, first):
    state, client, http, registry, _ = rig
    http.request.side_effect = [
        chat("```json\n" + json.dumps({**DECISION, "action": first.value}) + "\n```"),
        chat(json.dumps(ENRICHMENT)),
    ]
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=1))
    expected = [a for a in Action if a != Action.GENERATE_AI_BRIEF]
    if first == Action.RUN_DAST:
        expected[:2] = reversed(expected[:2])
    assert state.exit_code == 0 and state.executed_actions == expected
    assert state.agent_step_count == 5
    assert state.planner_request_count == client.planner_usage.requests == 1
    assert client.usage.requests == 1 and http.request.call_count == 2
    assert state.llm_usage.planner.total_tokens == 15
    assert [t.decision_source for t in state.trace] == ["llm_planner"] + [
        "deterministic_single_option"
    ] * 4
    for path in registry.paths.reports.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE-CHAIN-OF-THOUGHT" not in text and "SECRET-KEY" not in text
    report = (registry.paths.reports / "report.md").read_text(encoding="utf-8")
    assert "SAST source:" in report and "DAST target:" in report
    assert (
        "different applications" in report and "automatic (only valid action)" in report
    )


@pytest.mark.parametrize("skipped", ["sast_status", "dast_status"])
def test_single_scope_never_calls_planner(rig, skipped):
    state, client, http, registry, _ = rig
    setattr(state, skipped, Status.SKIPPED)
    http.request.return_value = chat(json.dumps(ENRICHMENT))
    planner = Mock(choose=Mock(side_effect=AssertionError("Do not call Planner")))
    run_agent(state, planner, registry, Settings())
    planner.choose.assert_not_called()
    assert state.exit_code == 0 and state.planner_request_count == 0
    assert client.planner_usage.model_dump() == dict(
        requests=0, prompt_tokens=0, completion_tokens=0, total_tokens=0
    )


@pytest.mark.parametrize("budget,expected", [(1, 1), (2, 2), (8, 3)])
def test_malformed_retries_bounded_and_repair_prompt(rig, budget, expected):
    state, client, http, registry, finding = rig
    state.findings = [finding]
    http.request.return_value = chat("malformed SECRET-KEY")
    run_agent(
        state, Planner(client), registry, Settings(agent_max_planner_calls=budget)
    )
    assert http.request.call_count == state.planner_request_count == expected
    assert state.exit_code == 5 and state.agent_step_count == 0
    assert state.findings == [finding]
    assert all(t.error_code == "planner_json_decode_error" for t in state.trace)
    if expected > 1:
        sent = http.request.call_args.kwargs["json"]["messages"]
        assert (
            "Return only one JSON object matching the required schema."
            in sent[0]["content"]
        )
        assert "malformed" not in json.dumps(sent)
    assert "FAILED / PARTIAL" in (registry.paths.reports / "report.md").read_text(
        encoding="utf-8"
    )


def test_disallowed_action_is_not_executed(rig):
    state, client, http, registry, _ = rig
    http.request.return_value = chat(json.dumps({**DECISION, "action": "FINISH"}))
    run_agent(state, Planner(client), registry, Settings())
    assert not state.executed_actions
    assert all(t.error_code == "planner_action_not_allowed" for t in state.trace)


def test_no_allowed_actions_controlled_failure(rig):
    state, client, http, registry, _ = rig
    state.source_available = state.target_available = False
    run_agent(state, Planner(client), registry, Settings())
    http.request.assert_not_called()
    assert state.exit_code == 6 and state.last_error_code == "agent_no_allowed_actions"


@pytest.mark.parametrize(
    "content,kind",
    [
        ("not json", "json_decode_error"),
        ("", "empty_content"),
        (
            json.dumps({**ENRICHMENT, "normalized_category": "unknown"}),
            "invalid_category",
        ),
        (json.dumps({**ENRICHMENT, "id": "changed"}), "identity_mismatch"),
        (json.dumps({**ENRICHMENT, "severity": "urgent"}), "schema_validation_error"),
    ],
)
def test_enrichment_failures_preserve_scanner_findings_and_diagnostics(
    rig, content, kind, caplog, monkeypatch
):
    monkeypatch.setattr(logging.getLogger("security_agent"), "propagate", True)
    state, client, http, registry, finding = rig
    http.request.side_effect = [chat(json.dumps(DECISION)), chat(content)]
    run_agent(state, Planner(client), registry, Settings())
    assert state.exit_code == 0 and state.findings == [finding]
    assert state.finish_reason == "completed_with_warnings"
    assert state.last_error_code == "enrichment_" + kind
    assert state.last_error_code in caplog.text
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert (
        summary["status"] == "completed_with_warnings"
        and summary["enrichment_failures"] == 1
    )
    assert summary["last_error_code"] == state.last_error_code
    assert state.trace[2].error_code == state.last_error_code


@pytest.mark.parametrize(
    "ids,kind",
    [([], "missing"), (["extra"], "extra"), (["sample", "sample"], "duplicate")],
)
def test_batch_id_diagnostics_preserve_findings(rig, ids, kind):
    state, client, http, registry, finding = rig
    registry.batch_size = 3
    http.request.side_effect = [
        chat(json.dumps(DECISION)),
        chat(
            json.dumps(
                {"results": [{"id": id_, "enrichment": ENRICHMENT} for id_ in ids]}
            )
        ),
    ]
    run_agent(state, Planner(client), registry, Settings())
    assert state.findings == [finding] and state.exit_code == 0
    assert state.last_error_code == f"enrichment_batch_{kind}_id"


def test_latest_read_only_and_invalid_pointer(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr(
        "app.cli.OpenAICompatibleClient", Mock(side_effect=AssertionError("no LLM"))
    )
    paths = RunPaths.create(tmp_path)
    (paths.reports / "summary.json").write_text('{"status":"failed"}', encoding="utf-8")
    assert run(["latest", "--runs-dir", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert paths.run_id in text and "failed" in text and "agent_trace.json" in text
    (tmp_path / "latest.json").write_text('{"run_id":"../private"}', encoding="utf-8")
    assert run(["latest", "--runs-dir", str(tmp_path)]) == 6


def test_recovery_after_invalid_decision_counts_only_executed_actions(rig):
    state, client, http, registry, _ = rig
    http.request.side_effect = [
        chat("bad JSON"),
        chat(json.dumps(DECISION)),
        chat(json.dumps(ENRICHMENT)),
    ]
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=2))
    assert state.exit_code == 0 and state.agent_step_count == 5
    assert state.planner_request_count == 2 and len(state.trace) == 6
    assert client.planner_usage.total_tokens == 30
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["planner_failures"] == 1 and summary["status"] == "completed"


def test_dast_only_observed_failure_reaches_reports_without_planner(rig, monkeypatch):
    state, client, http, registry, finding = rig
    state.sast_status = Status.SKIPPED
    dast = [
        finding.model_copy(
            update={"source": "DAST", "tool": "nuclei", "id": f"dast-{i}"}
        )
        for i in range(3)
    ]
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: dast)
    http.request.return_value = chat("", finish="length")
    run_agent(state, Planner(client), registry, Settings())
    assert state.planner_request_count == client.planner_usage.requests == 0
    assert client.usage.requests == http.request.call_count == 6
    assert state.enrichment.retried == state.enrichment.failed == 3
    assert state.findings == dast and state.exit_code == 0
    assert state.last_error_code == "enrichment_response_truncated"
    assert state.executed_actions == [
        Action.RUN_DAST,
        Action.ENRICH_FINDINGS,
        Action.GENERATE_REPORT,
        Action.FINISH,
    ]


def test_fenced_batch_preserves_identity(rig):
    state, client, http, registry, finding = rig
    registry.batch_size = 3
    batch = {"results": [{"id": finding.id, "enrichment": ENRICHMENT}]}
    http.request.side_effect = [
        chat(json.dumps(DECISION)),
        chat("```json\n" + json.dumps(batch) + "\n```"),
    ]
    run_agent(state, Planner(client), registry, Settings())
    assert state.exit_code == 0 and len(state.findings) == 1
    assert state.findings[0].id == finding.id
    assert state.findings[0].category == finding.category
