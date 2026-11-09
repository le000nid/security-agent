"""Analyst text mode, truncation recovery and backward-compatible UI contracts."""

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
    "remediation_priorities": ["Сначала проверить HIGH и исправить дефект."],
    "referenced_finding_ids": [],
    "caveats": [],
    "suggested_next_questions": [],
}
PARTIAL = "Полезная первая часть: сканер обнаружил паттерн."
COMPLETE = (
    "Сканер обнаружил небезопасный паттерн, но эксплуатация не подтверждена.\n\n"
    "Сначала проверьте достижимость от недоверенного ввода, затем устраните источник риска."
)


def analyst(rig):
    _, client, http, _, finding = rig
    llm = ChatLLM()
    llm.client, llm.connectivity = client, "available"
    findings = [finding.model_copy(update={"severity": "high"}).model_dump(mode="json")]
    summary = {"run_id": "test", "stages": {"enrichment": "completed"}}
    return llm, http, summary, findings


def test_retry_with_larger_budget_preserves_first_part(rig, monkeypatch):
    llm, http, summary, findings = analyst(rig)
    monkeypatch.setenv("LLM_CHAT_MAX_TOKENS", "1200")
    monkeypatch.setenv("LLM_CHAT_RETRY_MAX_TOKENS", "1800")
    http.request.side_effect = [chat(PARTIAL, "length"), chat(COMPLETE)]
    result = analyze(
        llm, summary, findings, "Какие утверждения подтверждены?", "ANALYZE_RUN"
    )
    assert not result["truncated"] and result["attempts"] == 2
    assert result["previous_partial"]["answer"] == PARTIAL
    assert result["answer"] == COMPLETE
    requests = [call.kwargs["json"] for call in http.request.call_args_list]
    assert [request["max_tokens"] for request in requests] == [1200, 1800]
    assert all("response_format" not in request for request in requests)
    assert "complete, coherent answer" in requests[1]["messages"][0]["content"]
    assert requests[0]["messages"][1] == requests[1]["messages"][1]


@pytest.mark.parametrize(
    "second",
    [
        chat("Ещё одна неполная часть", "length"),
        chat("", "length"),
        httpx.ReadTimeout("private"),
    ],
)
def test_second_failure_preserves_best_partial(rig, second):
    llm, http, summary, findings = analyst(rig)
    http.request.side_effect = [chat(PARTIAL, "length"), second]
    result = analyze(llm, summary, findings, "Объясни все находки", "ANALYZE_RUN")
    assert PARTIAL in result["answer"]
    assert result["status"] == "completed_with_warnings"
    assert result["truncated"] and result["error_code"] == "chat_response_truncated"
    assert "полезная часть" in result["notice"]
    assert http.request.call_count == 2


def test_truncated_api_keeps_run_immutable(web, service):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    original = {
        path: path.read_bytes()
        for path in service.runs_dir.rglob("*")
        if path.is_file()
    }
    llm.client = Mock()
    llm.client.complete_text.side_effect = ChatResponseTruncated(PARTIAL)
    llm.connectivity = "available"
    app.state.jobs.start = Mock(side_effect=AssertionError("Must not scan"))
    response = client.post(
        "/api/chat", json={"run_id": run.run_id, "action": {"intent": "ANALYZE_RUN"}}
    )
    assert response.status_code == 200
    assert response.json()["analysis"]["answer"] == PARTIAL
    assert response.json()["analysis"]["truncated"]
    assert llm.client.complete_text.call_count == 2
    assert {
        path: path.read_bytes()
        for path in service.runs_dir.rglob("*")
        if path.is_file()
    } == original
    app.state.jobs.start.assert_not_called()


def test_partial_recovery_uses_visible_content_only(rig, monkeypatch):
    _, _, summary, findings = analyst(rig)
    payload = analysis_input(summary, findings, "help", "ANALYZE_RUN")
    result = recover_partial("<think>PRIVATE</think>Доступная часть", payload)
    assert result["answer"] == "Доступная часть"
    monkeypatch.setenv("LLM_API_KEY", "private-token")
    assert "private-token" not in str(ChatResponseTruncated("private-token"))
    assert "private-token" not in ChatResponseTruncated("private-token").partial_content


@pytest.mark.parametrize(
    "content", ["", "  ", "<think>PRIVATE</think>", "<analysis>PRIVATE"]
)
def test_non_answer_content_not_recovered(rig, content):
    _, _, summary, findings = analyst(rig)
    payload = analysis_input(summary, findings, "", "ANALYZE_RUN")
    assert recover_partial(content, payload) is None


def test_long_chat_answer_passes_without_retry(rig):
    llm, http, summary, findings = analyst(rig)
    long_answer = ("Подробное объяснение наблюдения и ограничений. " * 100)[:4800]
    http.request.return_value = chat(long_answer)
    result = analyze(llm, summary, findings, "Объясни запуск", "ANALYZE_RUN")
    assert result["answer"] == long_answer.strip()
    assert not result["truncated"] and http.request.call_count == 1


def test_tool_calls_rejected_and_truncated_planner_json_not_executed(rig):
    llm, http, _, _ = analyst(rig)
    body = chat(PARTIAL, "stop").json()
    body["choices"][0]["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
    http.request.return_value = httpx.Response(200, json=body)
    with pytest.raises(ValueError, match="chat_schema_invalid"):
        llm.complete_text("test", {}, role="chat_analysis")
    http.request.return_value = chat('{"action":"RUN_REPORT"', "length")
    with pytest.raises(LLMError, match="response truncated"):
        llm.client.complete_json("test", "test", role="planner", max_tokens=320)


def test_wide_question_uses_plain_text_and_grounded_metadata(rig):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(COMPLETE)
    question = "Какие утверждения подтверждены, а какие требуют ручной проверки?"
    result = analyze(llm, summary, findings, question, "ANALYZE_RUN")
    assert result["answer"] == COMPLETE
    assert result["finding_facts"][0]["severity"] == "high"
    assert result["enrichment_status"] == "completed"
    for text in (
        "scanner observed",
        "risk interpretation",
        "manual validation",
        "two to six",
    ):
        assert text in ANALYST_PROMPT
    request = http.request.call_args.kwargs["json"]
    assert "response_format" not in request
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
def test_known_contradictions_corrected(rig, incorrect, correct):
    llm, http, summary, findings = analyst(rig)
    http.request.return_value = chat(incorrect)
    result = analyze(llm, summary, findings, "help", "ANALYZE_RUN")
    assert incorrect not in result["answer"] and correct in result["answer"]
    assert "chat_claim_corrected" in result["warnings"]


def test_legacy_structured_chat_response_still_validates():
    legacy = validate_output(
        json.dumps(STRUCTURED), ChatAnalysisResponse, "chat_analysis"
    )
    assert legacy.summary == STRUCTURED["summary"] and not legacy.answer


def test_followup_is_readonly_explicit_context(web, service):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    llm.client, llm.connectivity = Mock(), "available"
    llm.client.complete_text.return_value = COMPLETE
    app.state.jobs.start = Mock(side_effect=AssertionError("Must not scan"))
    payload = {
        "run_id": run.run_id,
        "follow_up": "continue",
        "previous_answer": "Первая часть",
        "message": "Проверь demo-full полностью",
    }
    assert client.post("/api/chat", json=payload).status_code == 200
    projected = json.loads(llm.client.complete_text.call_args.args[1])
    assert projected["intent"] == "ANALYZE_RUN"
    assert projected["previous_answer"] == "Первая часть"
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
        ChatRequest(previous_answer="x" * 12001)


def test_chat_settings_validation(monkeypatch):
    monkeypatch.setenv("LLM_CHAT_MAX_TOKENS", "32767")
    monkeypatch.setenv("LLM_CHAT_RETRY_MAX_TOKENS", "32768")
    assert Settings.from_env().llm_chat_retry_max_tokens == 32768
    for key, value in (
        ("LLM_CHAT_MAX_TOKENS", "0"),
        ("LLM_CHAT_RETRY_MAX_TOKENS", "32769"),
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
