"""Real compatible-client contracts with mocked transport; never provider access."""

import json

import httpx
import pytest
from test_brief_and_enrichment import BRIEF
from test_stabilization import DECISION, ENRICHMENT, chat
from test_stabilization import rig as rig

from app.agent.loop import run_agent, run_deterministic
from app.agent.models import Status, TraceEntry
from app.agent.planner import Planner
from app.agent.reporting import llm_components
from app.brief import AIBrief, brief_input
from app.config import Settings
from app.llm_output import LLMError
from app.presentation import run_banner


@pytest.mark.parametrize(
    "bad",
    [
        {"llm_planner_max_tokens": 255},
        {"llm_planner_max_tokens": 2049},
        {"llm_planner_retry_max_tokens": 320},
        {"llm_planner_retry_max_tokens": 2049},
        {"llm_brief_max_tokens": 255},
        {"llm_brief_retry_max_tokens": 8193},
        {"llm_brief_retry_max_tokens": 2000},
    ],
)
def test_token_bounds(bad):
    with pytest.raises(ValueError):
        Settings(**bad)


def test_env_budgets(monkeypatch):
    for name, value in {
        "LLM_PLANNER_MAX_TOKENS": "400",
        "LLM_PLANNER_RETRY_MAX_TOKENS": "700",
        "LLM_BRIEF_MAX_TOKENS": "2200",
        "LLM_BRIEF_RETRY_MAX_TOKENS": "3500",
    }.items():
        monkeypatch.setenv(name, value)
    settings = Settings.from_env()
    assert settings.llm_planner_max_tokens == 400
    assert settings.llm_planner_retry_max_tokens == 700
    assert settings.llm_brief_max_tokens == 2200
    assert settings.llm_brief_retry_max_tokens == 3500


@pytest.mark.parametrize("truncated", [False, True])
def test_planner_truncation_regression(rig, truncated):
    state, client, http, registry, _ = rig
    state.enrichment_status = Status.SKIPPED
    http.request.side_effect = ([chat("PRIVATE", "length")] if truncated else []) + [
        chat(json.dumps(DECISION))
    ]
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=2))
    budgets = [
        call.kwargs["json"]["max_tokens"] for call in http.request.call_args_list
    ]
    assert budgets == ([320, 512] if truncated else [320])
    assert state.planner_request_count == client.planner_usage.requests == len(budgets)
    assert state.exit_code == 0 and state.report_status == Status.COMPLETED
    if truncated:
        assert state.trace[0].error_code == "planner_response_truncated"
        assert state.trace[0].status == "rejected"
        assert state.trace[1].status == "completed"
    for path in registry.paths.reports.iterdir():
        assert "PRIVATE" not in path.read_text(encoding="utf-8")
    components = llm_components(state)
    assert components["planner"]["failures"] == int(truncated)
    assert components["planner"]["status"] == (
        "completed_with_retries" if truncated else "completed"
    )


def test_planner_bound_still_prevents_hidden_retry(rig):
    state, client, http, registry, _ = rig
    http.request.return_value = chat("", "length")
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=1))
    assert http.request.call_count == state.planner_request_count == 1
    assert state.exit_code == 5


def test_planner_other_rejection_does_not_raise_budget(rig):
    state, client, http, _, _ = rig
    state.last_error_code = "planner_response_truncated"
    state.trace.append(
        TraceEntry(
            step=1,
            action="INVALID",
            status="rejected",
            error_code="planner_schema_validation_error",
            decision_reason="Rejected",
            decision_source="llm_planner",
        )
    )
    http.request.return_value = chat(json.dumps(DECISION))
    Planner(client).choose(state, 8)
    assert http.request.call_args.kwargs["json"]["max_tokens"] == 320


@pytest.mark.parametrize("both_truncated", [False, True])
def test_brief_truncation_preserves_results(rig, both_truncated):
    state, client, http, registry, finding = rig
    registry.settings = Settings()
    http.request.side_effect = [
        chat(json.dumps(ENRICHMENT)),
        chat("PRIVATE", "length"),
        chat("PRIVATE", "length") if both_truncated else chat(json.dumps(BRIEF)),
    ]
    run_deterministic(state, registry)
    assert [
        call.kwargs["json"]["max_tokens"] for call in http.request.call_args_list
    ] == [1200, 2000, 3200]
    assert len(state.findings) == 1 and state.findings[0].id == finding.id
    assert state.findings[0].description == ENRICHMENT["description"]
    assert state.enrichment.completed == 1
    assert state.report_status == Status.COMPLETED and state.exit_code == 0
    assert state.ai_brief_status == (
        Status.FAILED if both_truncated else Status.COMPLETED
    )
    assert (
        client.brief_usage.requests == 2 and client.brief_usage.completion_tokens == 10
    )
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["llm_usage"]["brief"]["requests"] == 2
    assert summary["status"] == (
        "completed_with_warnings" if both_truncated else "completed"
    )
    assert summary["llm_components"]["brief"]["error_code"] == (
        "brief_response_truncated" if both_truncated else None
    )
    assert (registry.paths.reports / "report.md").is_file()


@pytest.mark.parametrize(
    "field,value",
    [
        ("headline", "x" * 101),
        ("overall_summary", "x" * 451),
        ("top_findings", BRIEF["top_findings"] * 4),
        ("top_findings", [{"finding_id": "sample", "why_it_matters": "x" * 181}]),
        ("recommended_next_steps", ["step"] * 5),
        ("recommended_next_steps", ["x" * 181]),
        ("limitations", "x" * 301),
        ("closing_line", "x" * 161),
    ],
)
def test_small_brief_contract(field, value):
    with pytest.raises(ValueError):
        AIBrief.model_validate({**BRIEF, field: value})


def test_brief_projection(rig):
    state, _, _, _, finding = rig
    state.findings = [
        finding.model_copy(
            update={"description": "x" * 500, "recommendation": "PRIVATE"}
        )
    ]
    projected = brief_input(state)["findings"][0]
    assert len(projected["description"]) == 120
    assert set(projected) == {
        "id",
        "title",
        "description",
        "source",
        "severity",
        "normalized_category",
    }


@pytest.mark.parametrize("role", ["chat", "chat_analysis"])
@pytest.mark.parametrize("status", [401, 403, 429, 503])
def test_chat_transport_has_no_hidden_retries_or_scan_usage(rig, role, status):
    _, client, http, _, _ = rig
    http.request.return_value = httpx.Response(status, text="PRIVATE provider body")
    with pytest.raises(LLMError):
        client.complete_json("test", "test", max_tokens=600, role=role)
    assert http.request.call_count == client.usage_for(role).requests == 1
    assert (
        client.usage.requests
        == client.planner_usage.requests
        == client.brief_usage.requests
        == 0
    )


@pytest.mark.parametrize(
    "change,expected,absent",
    [
        ({"llm_enabled": False}, "ИИ отключён", "Итог ИИ сформирован"),
        ({}, "Обогащено находок: 7 из 7", "ИИ отключён"),
        (
            {
                "status": "completed_with_warnings",
                "stages": {
                    "ai_brief": "failed",
                    "report": "completed",
                    "enrichment": "completed",
                },
                "llm_components": {"brief": {"error_code": "brief_response_truncated"}},
            },
            "Обычный отчёт сохранён",
            "ИИ отключён",
        ),
        (
            {"status": "failed", "stages": {"sast": "failed"}},
            "SAST: ошибка этапа",
            "DAST: ошибка этапа",
        ),
        ({"warnings": ["llm_preflight_failed"]}, "LLM недоступен", "ИИ отключён"),
    ],
)
def test_actual_status_banner(change, expected, absent):
    run = {
        "status": "completed",
        "total": 7,
        "llm_enabled": True,
        "stages": {
            "sast": "completed",
            "dast": "completed",
            "enrichment": "completed",
            "ai_brief": "completed",
            "report": "completed",
        },
        "enrichment": {"requested": 7, "completed": 7},
        **change,
    }
    banner = run_banner(run)
    assert expected in banner and absent not in banner
