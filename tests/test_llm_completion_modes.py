"""Explicit structured-vs-text completion regression contracts."""

import json
from unittest.mock import Mock

import httpx
import pytest
from test_llm_openai_compatible import (
    MODEL,
    install_stub,
    models_payload,
    response,
)
from test_llm_openai_compatible import configured as configured

from app.chat import ChatLLM
from app.config import Settings
from app.llm import OpenAICompatibleClient
from app.llm_output import LLMError


def envelope(content, finish_reason="stop", *, reasoning="private"):
    return {
        "choices": [
            {
                "message": {
                    "content": content,
                    "reasoning_content": reasoning,
                },
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
    }


def client(monkeypatch, configured, payload):
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), response(payload=payload)],
    )
    return OpenAICompatibleClient(sleeper=lambda _: None), stub


def test_documented_default_budgets_are_code_defaults():
    settings = Settings()
    assert (
        settings.llm_planner_max_tokens,
        settings.llm_planner_retry_max_tokens,
        settings.llm_enrichment_max_tokens,
        settings.llm_enrichment_retry_max_tokens,
        settings.llm_brief_max_tokens,
        settings.llm_brief_retry_max_tokens,
        settings.llm_chat_max_tokens,
        settings.llm_chat_retry_max_tokens,
    ) == (320, 512, 1800, 3200, 6000, 10000, 6000, 10000)


def test_chat_status_shows_resolved_auto_model(monkeypatch, configured):
    monkeypatch.setenv("LLM_MODEL", "auto")
    monkeypatch.setenv("LLM_MODEL_POLICY", "fast")
    resolved = Mock()
    resolved.public_metadata.return_value = {
        "provider": "openai_compatible",
        "model": "resolved-flash-model",
    }
    resolved.complete_text.return_value = "OK"
    llm = ChatLLM(factory=Mock(return_value=resolved))

    status = llm.check()

    assert status["connectivity"] == "available"
    assert status["configured_model"] == "auto"
    assert status["model"] == "resolved-flash-model"


@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [
        (401, "authentication_failed"),
        (403, "access_denied"),
        (404, "endpoint_invalid"),
        (429, "rate_limited"),
        (500, "provider_unreachable"),
    ],
)
def test_connection_check_reports_chat_failure_code(
    monkeypatch, configured, status_code, expected_code
):
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), response(status_code)],
    )
    status = ChatLLM(factory=OpenAICompatibleClient).check()
    assert status["connectivity"] == "unavailable"
    assert status["error_code"] == expected_code
    assert status["error_message"]
    assert "runtime-secret" not in json.dumps(status)
    assert len(stub.calls) == 2


def test_connection_check_rejects_html_200(monkeypatch, configured):
    install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(content=b"<html>login</html>"),
        ],
    )
    status = ChatLLM(factory=OpenAICompatibleClient).check()
    assert status["connectivity"] == "unavailable"
    assert status["error_code"] == "response_invalid"


def test_failed_auto_probe_still_shows_resolved_model(monkeypatch, configured):
    monkeypatch.setenv("LLM_MODEL", "auto")
    install_stub(
        monkeypatch,
        [
            response(payload=models_payload("embedding-v1", "chat-flash-v1")),
            response(401),
        ],
    )
    status = ChatLLM(factory=OpenAICompatibleClient).check()
    assert status["configured_model"] == "auto"
    assert status["model"] == "chat-flash-v1"
    assert status["error_code"] == "authentication_failed"


def test_connection_check_rejects_timeout(monkeypatch, configured):
    timeout = httpx.ReadTimeout(
        "timeout", request=httpx.Request("POST", "https://example.test")
    )
    stub, _ = install_stub(
        monkeypatch, [response(payload=models_payload(MODEL)), timeout]
    )
    status = ChatLLM(factory=OpenAICompatibleClient).check()
    assert status["error_code"] == "provider_unreachable"
    assert len(stub.calls) == 2


def test_connection_check_requires_complete_nonempty_text(monkeypatch, configured):
    for content, finish_reason, expected_code in (
        ("", "stop", "response_invalid"),
        ("partial", "length", "response_truncated"),
    ):
        install_stub(
            monkeypatch,
            [
                response(payload=models_payload(MODEL)),
                response(payload=envelope(content, finish_reason)),
            ],
        )
        status = ChatLLM(factory=OpenAICompatibleClient).check()
        assert status["error_code"] == expected_code


def test_complete_text_omits_response_format_and_keeps_only_content(
    monkeypatch, configured
):
    llm, stub = client(monkeypatch, configured, envelope("Обычный подробный ответ"))
    assert llm.complete_text("system", "user", max_tokens=6000) == (
        "Обычный подробный ответ"
    )
    body = stub.calls[1][2]["json"]
    assert "response_format" not in body
    assert "private" not in llm.complete_text.__doc__


def test_complete_json_enables_json_mode(monkeypatch, configured):
    content = json.dumps({"action": "FINISH"})
    llm, stub = client(monkeypatch, configured, envelope(content))
    assert (
        llm.complete_json("system", "user", max_tokens=320, role="planner") == content
    )
    assert stub.calls[1][2]["json"]["response_format"] == {"type": "json_object"}


def test_length_text_is_preserved_but_length_json_is_rejected(monkeypatch, configured):
    llm, _ = client(monkeypatch, configured, envelope("Полезная часть", "length"))
    assert llm.complete_text("system", "user", max_tokens=6000) == "Полезная часть"
    assert llm.last_response_meta["chat_analysis"]["truncated"] is True

    llm, _ = client(monkeypatch, configured, envelope('{"action":', "length"))
    with pytest.raises(LLMError, match="response truncated"):
        llm.complete_json("system", "user", max_tokens=320, role="planner")


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_text_provider_statuses_are_safe(monkeypatch, configured, status):
    attempts = 1  # User-facing chat has no hidden transport retry.
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), *[response(status)] * attempts],
    )
    llm = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(LLMError) as caught:
        llm.complete_text("system", "user", max_tokens=6000)
    assert "runtime-secret" not in str(caught.value)
    assert len(stub.calls) == attempts + 1
