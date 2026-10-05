"""Offline regression of real failure paths, including pre-analyst classification."""

import json
from unittest.mock import Mock

import httpx
import pytest
from test_brief_and_enrichment import BRIEF, encoded
from test_chat_recovery import PARTIAL, STRUCTURED, analyst
from test_stabilization import ENRICHMENT, chat
from test_stabilization import rig as rig
from test_v040_service import service as service
from test_v040_web_chat import web as web

from app.agent.loop import run_deterministic
from app.agent.models import Status
from app.brief import AIBrief, generate_ai_brief
from app.chat_analysis import analyze
from app.config import Settings
from app.llm_output import LLMError, validate_output
from app.service import RunRequest

BAD = {
    **BRIEF,
    "overall_summary": "PRIVATE-MODEL-TEXT" * 50,
    "PRIVATE-UNKNOWN-KEY": "PRIVATE-VALUE",
}
WIDE = "Какие утверждения об этих находках точно подтверждены сканерами, а какие являются предположениями и требуют ручной проверки?"


@pytest.mark.parametrize(
    "prefix,kinds",
    [
        ([], ["normal"]),
        ([chat("", "length")], ["normal", "concise_retry"]),
        ([encoded(BAD)], ["normal", "schema_repair"]),
        (
            [chat("", "length"), encoded(BAD)],
            ["normal", "concise_retry", "schema_repair"],
        ),
        ([chat("broken JSON")], ["normal", "schema_repair"]),
    ],
)
def test_brief_bounded_paths_and_usage(rig, prefix, kinds):
    state, client, http, _, finding = rig
    state.findings = [finding]
    http.request.side_effect = [*prefix, encoded(BRIEF)]
    assert generate_ai_brief(state, client, Settings()).headline == BRIEF["headline"]
    assert [a.kind for a in state.brief_attempts] == kinds
    assert [a.max_tokens for a in state.brief_attempts] == [2000] + [3200] * len(prefix)
    assert client.brief_usage.requests == http.request.call_count == len(kinds)
    assert client.brief_usage.completion_tokens == len(kinds) * 5
    requests = [call.kwargs["json"] for call in http.request.call_args_list]
    assert len({r["messages"][1]["content"] for r in requests}) == 1
    if "concise_retry" in kinds:
        assert (
            "Start again"
            in requests[kinds.index("concise_retry")]["messages"][0]["content"]
        )
    if "schema_repair" in kinds:
        prompt = requests[-1]["messages"][0]["content"]
        assert "completely NEW" in prompt and "Safe validation problems" in prompt
        assert "PRIVATE" not in prompt
    diagnostics = json.dumps([a.model_dump() for a in state.brief_attempts])
    assert "PRIVATE" not in diagnostics
    assert state.brief_attempts[-1].finish_reason == "stop"
    assert state.brief_attempts[-1].reasoning_present


@pytest.mark.parametrize(
    "responses,expected",
    [
        ([chat("", "length"), chat("", "length")], 2),
        ([encoded(BAD), encoded(BAD)], 2),
        ([encoded(BAD), chat("", "length")], 2),
        ([chat("", "length"), encoded(BAD), encoded(BAD)], 3),
        ([chat("", "length"), encoded(BAD), chat("", "length")], 3),
    ],
)
def test_all_failures_terminal_with_saved_findings(rig, responses, expected):
    state, client, http, registry, _ = rig
    registry.settings = Settings()
    http.request.side_effect = [encoded(ENRICHMENT), *responses]
    run_deterministic(state, registry)
    assert state.finish_reason == "completed_with_warnings" and state.exit_code == 0
    assert (
        state.sast_status
        == state.dast_status
        == state.report_status
        == Status.COMPLETED
    )
    assert state.enrichment.completed == 1 and len(state.findings) == 1
    assert client.brief_usage.requests == expected
    assert len(state.brief_attempts) == expected
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["llm_usage"]["brief"]["requests"] == expected
    attempts = summary["llm_components"]["brief"]["attempts"]
    assert len(attempts) == expected
    assert attempts[-1]["error_code"]
    assert "PRIVATE" not in json.dumps(attempts)
    assert (registry.paths.reports / "findings.json").is_file()
    assert (
        registry.paths.reports / "ai_brief.json"
    ).read_text().strip() == '{\n  "status": "failed"\n}'


def test_safe_diagnostics_keep_only_schema_owned_fields():
    with pytest.raises(LLMError) as caught:
        validate_output(json.dumps(BAD), AIBrief, "brief")
    assert sorted(caught.value.validation_issues, key=lambda v: v["field"]) == sorted(
        [
            {"field": "overall_summary", "type": "string_too_long"},
            {"field": "<unknown>", "type": "extra_forbidden"},
        ],
        key=lambda v: v["field"],
    )
    assert "PRIVATE" not in str(caught.value) + repr(caught.value.validation_issues)
    for prefix, suffix in [
        ("Here is JSON:\n```json\n", "\n```\nDone."),
        ("Answer:\n", "\nDone."),
    ]:
        assert validate_output(prefix + json.dumps(BRIEF) + suffix, AIBrief, "brief")
    for content in [
        '{"outer":' + json.dumps(BRIEF),
        json.dumps(BRIEF) * 2,
        "```json\n{}\n```\n```json\n{}\n```",
    ]:
        with pytest.raises(LLMError):
            validate_output(content, AIBrief, "brief")


def test_finish_reason_not_usage_controls_truncation(rig):
    state, client, http, _, finding = rig
    state.findings = [finding]
    envelope = encoded(BRIEF).json()
    envelope["usage"]["completion_tokens"] = 2000
    http.request.return_value = httpx.Response(200, json=envelope)
    assert generate_ai_brief(state, client, Settings())
    assert client.brief_usage.requests == 1  # stop + high usage is not length


def test_transport_retries_count_http_not_logical_attempts(rig):
    state, client, http, _, finding = rig
    state.findings = [finding]
    http.request.side_effect = [httpx.Response(503), encoded(BRIEF)]
    assert generate_ai_brief(state, client, Settings())
    assert len(state.brief_attempts) == 1 and client.brief_usage.requests == 2


@pytest.mark.parametrize(
    "error", ["response_truncated", "json_decode_error", "schema_validation_error"]
)
def test_parser_failure_reaches_analyst_not_error_placeholder(web, service, error):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    llm.client, llm.connectivity = Mock(), "available"
    # Old path stopped at the first exception and never invoked the analyst.
    from app.llm_output import ChatResponseTruncated

    llm.client.complete_json.side_effect = [
        LLMError("chat", error),
        ChatResponseTruncated(PARTIAL),
        ChatResponseTruncated(PARTIAL),
    ]
    app.state.jobs.start = Mock(side_effect=AssertionError("Must not scan"))
    response = client.post("/api/chat", json={"run_id": run.run_id, "message": WIDE})
    assert response.status_code == 200
    result = response.json()["analysis"]
    assert result["truncated"] and result["summary"] == "Полезная первая часть"
    assert set(result["follow_up_actions"]) == {
        "continue",
        "shorten",
        "by_finding",
        "confirmed",
        "manual",
    }
    assert [c.kwargs["role"] for c in llm.client.complete_json.call_args_list] == [
        "chat",
        "chat_analysis",
        "chat_analysis",
    ]
    assert llm.connectivity == "available"
    app.state.jobs.start.assert_not_called()


def test_full_http_envelope_parser_truncation_then_answer(web, service, rig):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    _, real, http, _, _ = rig
    llm.client, llm.connectivity = real, "available"
    http.request.side_effect = [
        chat('{"intent":"ANALY', "length"),
        chat(json.dumps(STRUCTURED)),
    ]
    response = client.post("/api/chat", json={"run_id": run.run_id, "message": WIDE})
    assert response.status_code == 200 and not response.json()["analysis"]["truncated"]
    assert real.chat_usage.requests == real.chat_analysis_usage.requests == 1
    assert not app.state.jobs._jobs


@pytest.mark.parametrize(
    "bad",
    [
        "Десериализация pickle из недоверенного ввода ведёт к RCE.",
        "Обогащение и проверка эксплуатации не выполнялись.",
        "Это критичный риск.",
    ],
)
def test_actual_reported_claims_are_corrected(rig, bad):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(json.dumps({**STRUCTURED, "summary": bad}))
    result = analyze(llm, summary, findings, WIDE, "ANALYZE_RUN")
    assert result["summary"] != bad
    assert result["enrichment_status"] == "completed"
    assert result["exploit_validation_performed"] is False
    assert result["finding_facts"][0]["severity"] == "high"
    payload = json.loads(
        http.request.call_args.kwargs["json"]["messages"][1]["content"]
    )
    assert payload["validation_context"]["exploit_validation_performed"] is False


def test_ui_brief_safe_diagnostic_renderer(web):
    js = web[0].get("/static/app.js").text
    assert "Безопасная диагностика AI Brief" in js and "attempt.validation_issues" in js
    assert "попробуйте более узкий вопрос" not in js
