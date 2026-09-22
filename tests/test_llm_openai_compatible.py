import json
from unittest.mock import Mock

import httpx
import pytest
from pydantic import ValidationError

from app import main
from app.llm import SYSTEM_PROMPT, Enrichment, OpenAICompatibleClient, enrich_findings
from app.models import Finding

MODEL = "deepseek-ai/DeepSeek-V4-Flash-0731"
BASE_URL = "https://deepcode.ci.nsu.ru/api"


class StubHTTPClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def response(status=200, payload=None, *, content=None):
    request = httpx.Request("GET", BASE_URL)
    if content is not None:
        return httpx.Response(status, content=content, request=request)
    return httpx.Response(status, json=payload, request=request)


@pytest.fixture
def configured(monkeypatch):
    values = {
        "LLM_PROVIDER": "openai_compatible",
        "LLM_BASE_URL": BASE_URL,
        "LLM_MODEL": MODEL,
        "LLM_API_KEY": "runtime-secret",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


@pytest.fixture
def finding():
    return Finding(
        id="fixed-id",
        title="python-debug-enabled",
        source="SAST",
        tool="semgrep",
        category="configuration",
        severity="medium",
        confidence="high",
        location="C:\\private\\project\\app.py:7",
        evidence="debug=True and secret source text",
        description="Debug mode is enabled.",
        recommendation="Disable debug mode.",
        raw_output_ref="logs/raw_semgrep.json#/results/0",
    )


@pytest.fixture
def enrichment_payload():
    return {
        "description": "Debug mode increases diagnostic exposure.",
        "normalized_category": "debug_configuration",
        "severity": "medium",
        "recommendation": "Disable `debug=True` outside development.",
        "reasoning_short": "The scanner matched a literal debug flag.",
    }


def install_stub(monkeypatch, outcomes):
    stub = StubHTTPClient(outcomes)
    factory = Mock(return_value=stub)
    monkeypatch.setattr("app.llm.httpx.Client", factory)
    return stub, factory


def models_payload(*ids):
    return {"data": [{"id": model_id} for model_id in ids]}


def chat_payload(content, *, usage=None, reasoning="private provider reasoning"):
    return {
        "choices": [
            {
                "message": {"content": json.dumps(content), "reasoning": reasoning},
                "finish_reason": "stop",
            }
        ],
        "usage": usage or {},
    }


def test_model_discovery_url_bearer_exact_match_and_cache(monkeypatch, configured):
    stub, _ = install_stub(
        monkeypatch, [response(payload=models_payload("other", MODEL))]
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    client.ensure_model_available()
    client.ensure_model_available()

    assert client.models_url == f"{BASE_URL}/models"
    assert client.chat_url == f"{BASE_URL}/chat/completions"
    assert client.available_model_ids == (MODEL, "other")
    assert client.model_available is True
    assert "runtime-secret" not in json.dumps(client.public_metadata())
    assert len(stub.calls) == 1
    method, url, kwargs = stub.calls[0]
    assert (method, url) == ("GET", f"{BASE_URL}/models")
    assert kwargs["headers"] == {"Authorization": "Bearer runtime-secret"}
    assert kwargs["json"] is None


def test_model_missing_lists_available_and_never_calls_chat(monkeypatch, configured):
    stub, _ = install_stub(monkeypatch, [response(payload=models_payload("a", "b"))])
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError, match="Configured model unavailable.*a, b"):
        client.ensure_model_available()
    assert len(stub.calls) == 1
    assert client.model_available is False


@pytest.mark.parametrize(
    ("status", "message", "attempts"),
    [
        (401, "authentication failed", 1),
        (403, "access denied", 1),
        (404, "wrong model-discovery endpoint", 1),
        (429, "rate limited", 3),
        (500, "gateway/backend failure", 3),
        (503, "gateway/backend failure", 3),
    ],
)
def test_model_discovery_status_errors(
    monkeypatch, configured, status, message, attempts
):
    stub, _ = install_stub(monkeypatch, [response(status)] * attempts)
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError, match=message):
        client.ensure_model_available()
    assert len(stub.calls) == attempts


@pytest.mark.parametrize(
    "payload",
    [None, {}, {"data": None}, {"data": [{}]}, {"data": [{"id": 7}]}],
)
def test_invalid_model_discovery_json(monkeypatch, configured, payload):
    outcome = (
        response(content=b"not-json") if payload is None else response(payload=payload)
    )
    install_stub(monkeypatch, [outcome])
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError, match="Invalid OpenAI-compatible model discovery"):
        client.ensure_model_available()


@pytest.mark.parametrize(
    "url",
    [
        "http://deepcode.ci.nsu.ru/api",
        "not-a-url",
        "https://user:pass@example.com/api",
        "https://example.com/api?token=x",
        "https://example.com/api#fragment",
        "https://example.com/api/models",
        "https://example.com/api/chat/completions",
    ],
)
def test_invalid_base_url(monkeypatch, configured, url):
    monkeypatch.setenv("LLM_BASE_URL", url)
    with pytest.raises(ValueError):
        OpenAICompatibleClient()


def test_chat_content_model_auth_reasoning_ignored_and_usage(
    monkeypatch, configured, finding, enrichment_payload
):
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(
                payload=chat_payload(
                    enrichment_payload,
                    usage={
                        "prompt_tokens": 92,
                        "completion_tokens": 17,
                        "total_tokens": 109,
                    },
                    reasoning="must not be exposed",
                )
            ),
        ],
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    result = client.enrich(finding)

    assert result.reasoning_short == enrichment_payload["reasoning_short"]
    assert "must not be exposed" not in result.model_dump_json()
    assert client.usage.model_dump() == {
        "requests": 1,
        "prompt_tokens": 92,
        "completion_tokens": 17,
        "total_tokens": 109,
    }
    method, url, kwargs = stub.calls[1]
    assert (method, url) == ("POST", f"{BASE_URL}/chat/completions")
    assert kwargs["headers"] == {"Authorization": "Bearer runtime-secret"}
    assert kwargs["json"]["model"] == MODEL
    assert kwargs["json"]["max_tokens"] == 600
    assert "tools" not in kwargs["json"]
    assert "observed facts" in kwargs["json"]["messages"][0]["content"]
    assert "Modern browsers reject wildcard" in SYSTEM_PROMPT


def test_usage_aggregates_and_identity_is_immutable(
    monkeypatch, configured, finding, enrichment_payload
):
    second = Finding.model_validate(
        {**finding.model_dump(), "id": "second", "title": "second finding"}
    )
    usage = {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(payload=chat_payload(enrichment_payload, usage=usage)),
            response(payload=chat_payload(enrichment_payload, usage=usage)),
        ],
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    enriched, rationales = enrich_findings([finding, second], client)
    assert len(enriched) == 2
    assert len(stub.calls) == 3
    assert client.usage.model_dump() == {
        "requests": 2,
        "prompt_tokens": 20,
        "completion_tokens": 8,
        "total_tokens": 28,
    }
    immutable = (
        "id",
        "title",
        "source",
        "tool",
        "category",
        "confidence",
        "location",
        "evidence",
        "raw_output_ref",
    )
    for before, after in zip((finding, second), enriched, strict=True):
        assert all(
            getattr(before, field) == getattr(after, field) for field in immutable
        )
        assert after.normalized_category == "debug_configuration"
    assert set(rationales) == {"fixed-id", "second"}


def test_default_request_minimizes_data(
    monkeypatch, configured, finding, enrichment_payload
):
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(payload=chat_payload(enrichment_payload)),
        ],
    )
    OpenAICompatibleClient(sleeper=lambda _: None).enrich(finding)
    body = stub.calls[1][2]["json"]
    user_content = body["messages"][1]["content"]
    sent = json.loads(user_content)
    assert sent["location"] == "app.py:7"
    assert "evidence" not in sent
    assert "raw_output_ref" not in sent
    for secret in (
        "runtime-secret",
        "debug=True and secret source text",
        "logs/raw_semgrep.json",
    ):
        assert secret not in json.dumps(body)
    assert os_environ_keys_absent(body)


def os_environ_keys_absent(body):
    serialized = json.dumps(body)
    return all(
        name not in serialized
        for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_PROVIDER")
    )


def test_evidence_opt_in_is_still_normalized_only(
    monkeypatch, configured, finding, enrichment_payload
):
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(payload=chat_payload(enrichment_payload)),
        ],
    )
    OpenAICompatibleClient(sleeper=lambda _: None).enrich(
        finding, include_evidence=True
    )
    sent = json.loads(stub.calls[1][2]["json"]["messages"][1]["content"])
    assert sent["evidence"] == finding.evidence
    assert "raw_output_ref" not in sent
    assert "logs/raw_semgrep.json" not in json.dumps(sent)


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_chat_deterministic_http_failures_are_not_retried(
    monkeypatch, configured, finding, status
):
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), response(status)],
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError):
        client.enrich(finding)
    assert len(stub.calls) == 2


@pytest.mark.parametrize("failure", [429, 500])
def test_chat_transient_status_is_retried(
    monkeypatch, configured, finding, enrichment_payload, failure
):
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(failure),
            response(payload=chat_payload(enrichment_payload)),
        ],
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    assert client.enrich(finding).severity == "medium"
    assert len(stub.calls) == 3


def test_chat_timeout_is_retried(monkeypatch, configured, finding, enrichment_payload):
    timeout = httpx.ReadTimeout("timeout", request=httpx.Request("POST", BASE_URL))
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            timeout,
            response(payload=chat_payload(enrichment_payload)),
        ],
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    assert client.enrich(finding).severity == "medium"
    assert len(stub.calls) == 3


@pytest.mark.parametrize(
    ("outcomes", "message"),
    [
        ([response(429)] * 3, "rate limited"),
        ([response(500)] * 3, "gateway/backend failure"),
    ],
)
def test_chat_transient_failure_stops_after_two_retries(
    monkeypatch, configured, finding, outcomes, message
):
    stub, _ = install_stub(
        monkeypatch, [response(payload=models_payload(MODEL)), *outcomes]
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError, match=message):
        client.enrich(finding)
    assert len(stub.calls) == 4


def test_chat_timeout_stops_after_two_retries(monkeypatch, configured, finding):
    timeouts = [
        httpx.ReadTimeout("timeout", request=httpx.Request("POST", BASE_URL))
        for _ in range(3)
    ]
    stub, _ = install_stub(
        monkeypatch, [response(payload=models_payload(MODEL)), *timeouts]
    )
    client = OpenAICompatibleClient(sleeper=lambda _: None)
    with pytest.raises(ValueError, match="timed out after retries"):
        client.enrich(finding)
    assert len(stub.calls) == 4


def test_finish_reason_and_schema_failures_are_not_retried(
    monkeypatch, configured, finding, enrichment_payload
):
    invalid = chat_payload(enrichment_payload)
    invalid["choices"][0]["finish_reason"] = "length"
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), response(payload=invalid)],
    )
    with pytest.raises(ValueError, match="Incomplete"):
        OpenAICompatibleClient(sleeper=lambda _: None).enrich(finding)
    assert len(stub.calls) == 2


def test_malformed_chat_json_is_not_retried(monkeypatch, configured, finding):
    stub, _ = install_stub(
        monkeypatch,
        [response(payload=models_payload(MODEL)), response(content=b"not-json")],
    )
    with pytest.raises(ValueError, match="Invalid OpenAI-compatible chat response"):
        OpenAICompatibleClient(sleeper=lambda _: None).enrich(finding)
    assert len(stub.calls) == 2


def test_invalid_enrichment_schema_is_not_retried(monkeypatch, configured, finding):
    malformed = {
        "description": "Valid text",
        "normalized_category": "debug_configuration",
        "severity": "urgent",
        "recommendation": "Review it.",
        "reasoning_short": "Scanner match.",
    }
    stub, _ = install_stub(
        monkeypatch,
        [
            response(payload=models_payload(MODEL)),
            response(payload=chat_payload(malformed)),
        ],
    )
    with pytest.raises(ValueError, match="schema validation"):
        OpenAICompatibleClient(sleeper=lambda _: None).enrich(finding)
    assert len(stub.calls) == 2


def test_no_llm_constructs_no_client_or_models_request(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "check_target_reachable", lambda _: None)
    monkeypatch.setattr(
        main,
        "OpenAICompatibleClient",
        Mock(side_effect=AssertionError("LLM client must not be constructed")),
    )

    def fake_nuclei(_target, output):
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("", encoding="utf-8")

    monkeypatch.setattr(main, "run_nuclei", fake_nuclei)
    assert (
        main.run(
            ["--mode", "dast", "--target-url", "http://localhost:3000", "--no-llm"]
        )
        == 0
    )
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert summary["llm"] is None
    assert summary["llm_status"] == "disabled"
    assert summary["llm_usage"]["requests"] == 0


def test_llm_failure_preserves_scanner_artifacts(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "check_target_reachable", lambda _: None)

    def fake_nuclei(_target, output):
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "template-id": "headers",
                    "info": {"name": "Header finding", "severity": "info"},
                    "matched-at": "http://localhost:3000",
                }
            ),
            encoding="utf-8",
        )

    client = Mock()
    client.ensure_model_available.side_effect = ValueError("authentication failed")
    client.public_metadata.return_value = {
        "provider": "openai_compatible",
        "base_url": BASE_URL,
        "model": MODEL,
        "model_available": False,
    }
    client.usage.model_dump.return_value = {
        "requests": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    monkeypatch.setattr(main, "run_nuclei", fake_nuclei)
    monkeypatch.setattr(main, "OpenAICompatibleClient", Mock(return_value=client))

    assert main.run(["--mode", "dast", "--target-url", "http://localhost:3000"]) == 1
    findings = json.loads((tmp_path / "reports/findings.json").read_text())
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert len(findings) == 1 and findings[0]["title"] == "Header finding"
    assert (tmp_path / "reports/report.md").is_file()
    assert (tmp_path / "logs/raw_nuclei.jsonl").is_file()
    assert summary["llm_status"] == "failed"
    assert summary["llm_error"] == "authentication failed"


def test_enrichment_schema_forbids_identity_fields(enrichment_payload):
    for field in (
        "id",
        "title",
        "source",
        "tool",
        "category",
        "confidence",
        "location",
        "evidence",
        "raw_output_ref",
    ):
        with pytest.raises(ValidationError):
            Enrichment.model_validate({**enrichment_payload, field: "changed"})
