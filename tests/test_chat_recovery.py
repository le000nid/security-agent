"""Analyst-only recovery; mocked providers, unchanged saved runs, no scanner calls."""

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from test_stabilization import chat
from test_stabilization import rig as rig
from test_v040_service import service as service
from test_v040_web_chat import web as web

from app.chat import ChatLLM, ChatRequest
from app.chat_analysis import (
    ANALYST_PROMPT,
    ChatAnalysisResponse,
    analysis_input,
    analyze,
    recover_partial,
)
from app.config import Settings
from app.llm_output import ChatResponseTruncated, LLMError, validate_output
from app.service import RunRequest

STRUCTURED = {
    "answer": "",
    "summary": "Сканер обнаружил паттерн, но эксплуатация не подтверждена.",
    "confirmed_points": ["Semgrep сообщил о небезопасном паттерне."],
    "assumptions_or_manual_checks": [
        "Проверить, достигает ли недоверенный ввод этого участка кода."
    ],
    "remediation_priorities": [
        "Сначала проверить HIGH и исправить подтверждённые дефекты."
    ],
    "referenced_finding_ids": [],
    "caveats": [],
    "suggested_next_questions": [],
}
PARTIAL = (
    '{"summary":"Полезная первая часть", "confirmed_points":["Сканер сообщил о паттерне'
)


def analyst(rig):
    _, client, http, _, finding = rig
    llm = ChatLLM()
    llm.client, llm.connectivity = client, "available"
    findings = [finding.model_copy(update={"severity": "high"}).model_dump(mode="json")]
    summary = {"run_id": "test", "stages": {"enrichment": "completed"}}
    return llm, http, summary, findings


def test_retry_concise_with_separate_budgets_and_preserved_first_part(rig, monkeypatch):
    llm, http, summary, findings = analyst(rig)
    monkeypatch.setenv("LLM_CHAT_MAX_TOKENS", "1200")
    monkeypatch.setenv("LLM_CHAT_RETRY_MAX_TOKENS", "1800")
    http.request.side_effect = [chat(PARTIAL, "length"), chat(json.dumps(STRUCTURED))]
    result = analyze(
        llm, summary, findings, "Какие утверждения подтверждены?", "ANALYZE_RUN"
    )
    assert not result["truncated"] and result["attempts"] == 2
    assert result["previous_partial"]["summary"] == "Полезная первая часть"
    assert result["summary"] == STRUCTURED["summary"]
    requests = [c.kwargs["json"] for c in http.request.call_args_list]
    assert [r["max_tokens"] for r in requests] == [1200, 1800]
    assert "much shorter structured answer" in requests[1]["messages"][0]["content"]
    assert "much shorter structured answer" not in requests[0]["messages"][0]["content"]
    assert requests[0]["messages"][1] == requests[1]["messages"][1]
    assert llm.client.usage_for("chat_analysis").requests == 2
    assert llm.connectivity == "available"
    assert "PRIVATE-CHAIN" not in json.dumps(result)


@pytest.mark.parametrize(
    "second",
    [
        chat(PARTIAL, "length"),
        chat("", "length"),
        chat("bad JSON"),
        httpx.ReadTimeout("private"),
    ],
)
def test_second_failure_preserves_partial(rig, second):
    llm, http, summary, findings = analyst(rig)
    http.request.side_effect = [chat(PARTIAL, "length"), second]
    result = analyze(llm, summary, findings, "Объясни все находки", "ANALYZE_RUN")
    assert result["summary"] == "Полезная первая часть"
    assert result["confirmed_points"] == ["Сканер сообщил о паттерне"]
    assert result["status"] == "completed_with_warnings"
    assert result["truncated"] and result["error_code"] == "chat_response_truncated"
    assert result["referenced_finding_ids"] == []
    assert "Показана первая часть" in result["notice"]
    assert http.request.call_count == 2
    assert llm.connectivity == (
        "unavailable" if isinstance(second, Exception) else "available"
    )


def test_truncated_api_keeps_run_immutable(web, service):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    original = {p: p.read_bytes() for p in service.runs_dir.rglob("*") if p.is_file()}
    llm.client = Mock()
    llm.client.complete_json.side_effect = ChatResponseTruncated(PARTIAL)
    llm.connectivity = "available"
    app.state.jobs.start = Mock(side_effect=AssertionError("Must not scan"))
    response = client.post(
        "/api/chat", json={"run_id": run.run_id, "action": {"intent": "ANALYZE_RUN"}}
    )
    assert response.status_code == 200
    assert response.json()["analysis"]["summary"] == "Полезная первая часть"
    assert response.json()["analysis"]["truncated"]
    assert llm.client.complete_json.call_count == 2
    assert {
        p: p.read_bytes() for p in service.runs_dir.rglob("*") if p.is_file()
    } == original
    app.state.jobs.start.assert_not_called()


@pytest.mark.parametrize(
    "content",
    [
        "Доступная первая часть",
        '```json\n{"answer":"Доступная первая часть',
        '{"summary":"Доступная первая часть","reasoning":"PRIVATE", "referenced_finding_ids":["invented"]',
    ],
)
def test_salvage_only_display_fields(rig, content, monkeypatch):
    _, _, summary, findings = analyst(rig)
    payload = analysis_input(summary, findings, "help", "ANALYZE_RUN")
    result = recover_partial(content, payload)
    assert "Доступная первая часть" in json.dumps(result, ensure_ascii=False)
    assert "PRIVATE" not in json.dumps(result) and "invented" not in json.dumps(result)
    assert result["referenced_finding_ids"] == []
    monkeypatch.setenv("LLM_API_KEY", "private-token")
    assert "private-token" not in str(ChatResponseTruncated("private-token"))
    assert "private-token" not in ChatResponseTruncated("private-token").partial_content


@pytest.mark.parametrize(
    "content",
    [
        "",
        "  ",
        '{"reasoning":"PRIVATE"',
        '["PRIVATE"]',
        'prefix {"reasoning":"PRIVATE"}',
        "<think>PRIVATE</think>",
    ],
)
def test_non_answer_content_not_salvaged(rig, content):
    _, _, summary, findings = analyst(rig)
    assert (
        recover_partial(content, analysis_input(summary, findings, "", "ANALYZE_RUN"))
        is None
    )


def test_empty_truncation_returns_stored_observations(rig):
    llm, http, summary, findings = analyst(rig)
    http.request.side_effect = [chat(None, "length"), chat("", "length")]
    result = analyze(llm, summary, findings, "help", "ANALYZE_RUN")
    assert result["truncated"] and "Debug — HIGH" in result["answer"]


@pytest.mark.parametrize(
    "change",
    [
        {"summary": "x" * 351},
        {"answer": "x" * 1801},
        {"confirmed_points": ["x"] * 4, "assumptions_or_manual_checks": ["y"] * 4},
    ],
)
def test_character_and_point_overflow_also_retries(rig, change):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(json.dumps({**STRUCTURED, **change}))
    result = analyze(llm, summary, findings, "help", "ANALYZE_RUN")
    assert result["truncated"] and http.request.call_count == 2
    assert len(result["summary"]) <= 350 and len(result["answer"]) <= 1800
    assert (
        sum(
            len(result[k])
            for k in (
                "confirmed_points",
                "assumptions_or_manual_checks",
                "remediation_priorities",
            )
        )
        <= 7
    )


def test_tool_calls_and_other_roles_do_not_use_analyst_recovery(rig):
    llm, http, _, _ = analyst(rig)
    body = chat(PARTIAL, "length").json()
    body["choices"][0]["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
    http.request.return_value = httpx.Response(200, json=body)
    with pytest.raises(ValueError, match="chat_schema_invalid"):
        llm.complete("test", {}, ChatAnalysisResponse, role="chat_analysis")
    assert http.request.call_count == 1
    http.request.return_value = chat(PARTIAL, "length")
    with pytest.raises(LLMError) as caught:
        llm.client.complete_json("test", "test", role="planner", max_tokens=320)
    assert not isinstance(caught.value, ChatResponseTruncated)


def test_wide_question_compact_schema_and_grounded_metadata(rig):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(json.dumps(STRUCTURED))
    question = "Какие утверждения точно подтверждены сканерами, а какие являются предположениями?"
    result = analyze(llm, summary, findings, question, "ANALYZE_RUN")
    assert all(
        result[k]
        for k in (
            "summary",
            "confirmed_points",
            "assumptions_or_manual_checks",
            "remediation_priorities",
        )
    )
    assert result["finding_facts"][0]["severity"] == "high"
    assert result["enrichment_status"] == "completed"
    for text in (
        "observed by scanner",
        "inferred risk",
        "requires manual validation",
        "3-7 short points",
        "эксплуатация не подтверждена",
    ):
        assert text in ANALYST_PROMPT
    request = http.request.call_args.kwargs["json"]
    assert request["response_format"] == {"type": "json_object"}
    assert (
        json.loads(request["messages"][1]["content"])["run"]["stages"]["enrichment"]
        == "completed"
    )


@pytest.mark.parametrize(
    "incorrect,correct",
    [
        ("This finding is CRITICAL.", "CRITICAL не подтверждается"),
        ("Enrichment was not performed.", "Обогащение выполнено"),
        ("Обогащение не выполнялось.", "Обогащение выполнено"),
    ],
)
@pytest.mark.parametrize("finish", ["stop", "length"])
def test_known_contradictions_corrected(rig, incorrect, correct, finish):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(
        json.dumps({**STRUCTURED, "summary": incorrect}), finish
    )
    result = analyze(llm, summary, findings, "help", "ANALYZE_RUN")
    assert incorrect not in result["summary"] and correct in result["summary"]
    assert "chat_claim_corrected" in result["warnings"]
    assert result["finding_facts"][0]["severity"] == "high"


def test_unknown_fields_still_fail_strict_validation():
    with pytest.raises(LLMError) as caught:
        validate_output(
            json.dumps({**STRUCTURED, "command": "ignored"}),
            ChatAnalysisResponse,
            "chat_analysis",
        )
    assert not isinstance(caught.value, ChatResponseTruncated)


def test_followup_is_readonly_explicit_context(web, service):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    llm.client, llm.connectivity = Mock(), "available"
    llm.client.complete_json.return_value = json.dumps(STRUCTURED)
    app.state.jobs.start = Mock(side_effect=AssertionError("Must not scan"))
    payload = {
        "run_id": run.run_id,
        "follow_up": "continue",
        "previous_answer": "Первая часть",
        "message": "Проверь demo-full полностью",
    }
    assert client.post("/api/chat", json=payload).status_code == 200
    projected = json.loads(llm.client.complete_json.call_args.args[1])
    assert (
        projected["intent"] == "ANALYZE_RUN"
        and projected["previous_answer"] == "Первая часть"
    )
    assert projected["run"]["run_id"] == run.run_id
    assert (
        client.post(
            "/api/chat", json={**payload, "action": {"intent": "START_SCAN"}}
        ).status_code
        == 400
    )
    app.state.jobs.start.assert_not_called()
    with pytest.raises(ValueError):
        ChatRequest(follow_up="shell")
    with pytest.raises(ValueError):
        ChatRequest(previous_answer="x" * 2401)


def test_chat_settings_validation(monkeypatch):
    monkeypatch.setenv("LLM_CHAT_MAX_TOKENS", "256")
    monkeypatch.setenv("LLM_CHAT_RETRY_MAX_TOKENS", "512")
    assert Settings.from_env().llm_chat_retry_max_tokens == 512
    for key, value in (
        ("LLM_CHAT_MAX_TOKENS", "0"),
        ("LLM_CHAT_RETRY_MAX_TOKENS", "9000"),
    ):
        with monkeypatch.context() as scoped:
            scoped.setenv(key, value)
            with pytest.raises(ValueError):
                Settings.from_env()


def test_chat_dom_rendering_and_followup_actions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is only needed for the standalone UI DOM contract test")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("chat_ui.cjs"))],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
