"""Read-only analytical context, content/transport split and explicit confirmation."""

import json
from unittest.mock import Mock

import pytest
from test_v040_service import service as service
from test_v040_web_chat import wait_job
from test_v040_web_chat import web as web

from app.chat import ChatRequest, ScanConfirmation
from app.chat_analysis import ChatAnalysisResponse, analysis_input
from app.llm_output import LLMError
from app.service import RunRequest

ANALYSIS = {
    "answer": "Наблюдение сканера требует проверки. Возможный риск — интерпретация, а не доказательство эксплуатации.",
    "referenced_finding_ids": ["0"],
    "caveats": ["Возможны ложные срабатывания."],
    "suggested_next_questions": ["Как проверить эту находку?"],
}


@pytest.mark.parametrize(
    "intent",
    [
        "ANALYZE_RUN",
        "PRIORITIZE_FINDINGS",
        "REMEDIATION_PLAN",
        "COMPARE_SAST_DAST",
        "EXPLAIN_FINDING",
        "SUMMARIZE_RUN",
    ],
)
def test_analysis_is_readonly_and_contextual(web, service, intent):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    newer = service.run(RunRequest(benchmark_id="sample-sast"))
    original = {p: p.read_bytes() for p in service.runs_dir.rglob("*") if p.is_file()}
    fake = Mock()
    fake.complete_json.return_value = json.dumps(ANALYSIS)
    llm.client, llm.connectivity = fake, "available"
    app.state.jobs.start = Mock(side_effect=AssertionError("Analyst must not scan"))
    response = client.post(
        "/api/chat",
        json={
            "run_id": run.run_id,
            "finding_id": "0",
            "action": {"intent": intent},
            "message": "Почему это high?",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["run_id"] == run.run_id != newer.run_id
    analysis = response.json()["analysis"]
    assert {key: analysis[key] for key in ANALYSIS} == ANALYSIS
    assert analysis["status"] == "completed" and not analysis["truncated"]
    call = fake.complete_json.call_args
    assert call.kwargs["role"] == "chat_analysis"
    projected = json.loads(call.args[1])
    assert projected["run"]["run_id"] == run.run_id
    assert projected["selected_finding_id"] == "0"
    assert "raw_output_ref" not in call.args[1] and "location" not in call.args[1]
    assert "target_url" not in call.args[1] and "source_path" not in call.args[1]
    app.state.jobs.start.assert_not_called()
    assert {p: p.read_bytes() for p in original} == original


@pytest.mark.parametrize("ids", [["unknown"], ["0", "0"]])
def test_analyst_rejects_invalid_references(web, service, ids):
    client, _, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    fake = Mock()
    fake.complete_json.return_value = json.dumps(
        {**ANALYSIS, "referenced_finding_ids": ids}
    )
    llm.client, llm.connectivity = fake, "available"
    response = client.post(
        "/api/chat", json={"run_id": run.run_id, "action": {"intent": "ANALYZE_RUN"}}
    )
    assert response.json() == {"error": "chat_schema_invalid"}
    assert llm.connectivity == "available" and fake.complete_json.call_count == 1


@pytest.mark.parametrize(
    "kind,error,health",
    [
        ("response_truncated", "chat_response_truncated", "available"),
        ("json_decode_error", "chat_json_invalid", "available"),
        ("schema_validation_error", "chat_schema_invalid", "available"),
        ("timeout", "llm_unavailable", "unavailable"),
        ("http_error", "llm_unavailable", "unavailable"),
    ],
)
@pytest.mark.parametrize("role", ["chat", "chat_analysis"])
def test_connectivity_classification(web, service, kind, error, health, role):
    client, _, llm = web
    fake = Mock()
    fake.complete_json.side_effect = LLMError(role, kind)
    llm.client, llm.connectivity = fake, "available"
    payload = {"message": "Which local targets?"}
    if role == "chat_analysis":
        run = service.run(RunRequest(benchmark_id="demo-full"))
        payload = {"run_id": run.run_id, "action": {"intent": "ANALYZE_RUN"}}
    result = client.post("/api/chat", json=payload)
    if role == "chat_analysis" and kind == "response_truncated":
        assert result.status_code == 200
        assert result.json()["analysis"]["error_code"] == error
        assert result.json()["analysis"]["status"] == "completed_with_warnings"
        assert llm.connectivity == health and fake.complete_json.call_count == 2
        return
    assert result.json() == {"error": error}
    assert llm.connectivity == health and fake.complete_json.call_count == 1
    if health == "unavailable":
        client.post("/api/chat", json=payload)
        assert fake.complete_json.call_count == 1


@pytest.mark.parametrize(
    "message,agent",
    [
        ("Проверь demo-full полностью", False),
        ("Проверь demo-full полностью агентом", True),
        ("Проверь Demo Full полностью агентом", True),
    ],
)
def test_start_proposal_does_not_scan(web, message, agent):
    client, app, llm = web
    start = app.state.jobs.start = Mock()
    response = client.post("/api/chat", json={"message": message})
    assert response.status_code == 200
    proposal = response.json()["proposal"]
    assert proposal["benchmark_id"] == "demo-full" and proposal["mode"] == "full"
    assert proposal["llm_enabled"] is agent
    assert proposal["orchestration"] == ("agent" if agent else "scan")
    start.assert_not_called()
    llm.factory.assert_not_called()


def test_confirmation_cancel_replay_and_csrf(web):
    client, app, _ = web
    proposal = client.post(
        "/api/chat", json={"message": "Проверь demo-full полностью"}
    ).json()["proposal"]
    payload = {"proposal_id": proposal["proposal_id"], "confirm": True}
    assert (
        client.post(
            "/api/chat/confirm", json=payload, headers={"X-CSRF-Token": "bad"}
        ).status_code
        == 403
    )
    assert not app.state.jobs._jobs
    response = client.post("/api/chat/confirm", json=payload)
    assert wait_job(app, response.json()["job"]["job_id"]).status == "completed"
    assert client.post("/api/chat/confirm", json=payload).json() == {
        "error": "proposal_expired"
    }
    second = client.post(
        "/api/chat", json={"message": "Проверь demo-full полностью"}
    ).json()["proposal"]
    payload = {"proposal_id": second["proposal_id"], "confirm": False}
    assert client.post("/api/chat/confirm", json=payload).status_code == 200
    assert (
        client.post("/api/chat/confirm", json={**payload, "confirm": True}).status_code
        == 400
    )
    assert len(app.state.jobs._jobs) == 1


def test_proposal_expiry_and_forbidden_fields(web):
    client, app, _ = web
    proposal = client.post(
        "/api/chat", json={"message": "Проверь demo-full полностью"}
    ).json()["proposal"]
    pid = proposal["proposal_id"]
    _, request = app.state.chat._proposals[pid]
    app.state.chat._proposals[pid] = (0, request)
    assert (
        client.post(
            "/api/chat/confirm", json={"proposal_id": pid, "confirm": True}
        ).status_code
        == 400
    )
    with pytest.raises(ValueError):
        ScanConfirmation(
            proposal_id=pid, confirm=True, target_url="https://example.com"
        )
    with pytest.raises(ValueError):
        ChatRequest(action={"intent": "START_SCAN", "confirmation_id": pid})


def test_bad_context_rejected_before_provider_and_legacy_supported(web, service):
    client, app, llm = web
    run = service.run(RunRequest(benchmark_id="demo-full"))
    for payload in [
        {"run_id": "../secret"},
        {"run_id": "20200101T000000Z-000000000000"},
        {"run_id": run.run_id, "finding_id": "absent"},
    ]:
        response = client.post(
            "/api/chat", json={**payload, "action": {"intent": "ANALYZE_RUN"}}
        )
        assert response.status_code in (400, 404, 422)
    path = app.state.repository.path(run.run_id, "summary.json")
    data = json.loads(path.read_text())
    data.pop("benchmark_id")
    data.pop("llm_components")
    path.write_text(json.dumps(data))
    fallback = client.post(
        "/api/chat", json={"message": "Что здесь самое опасное и почему?"}
    ).json()
    assert fallback["run_id"] == run.run_id and fallback["offline"]
    assert fallback["finding"]["severity"] == "high"
    llm.factory.assert_not_called()


def test_latest_and_explicit_context(web, service):
    client, _, _ = web
    first = service.run(RunRequest(benchmark_id="demo-full"))
    latest = service.run(RunRequest(benchmark_id="juice-shop"))
    action = {"intent": "SHOW_FINDINGS"}
    assert (
        client.post("/api/chat", json={"action": action}).json()["run_id"]
        == latest.run_id
    )
    assert (
        client.post(
            "/api/chat", json={"run_id": first.run_id, "action": action}
        ).json()["run_id"]
        == first.run_id
    )
    conflict = {"run_id": first.run_id, "action": {**action, "run_id": latest.run_id}}
    assert client.post("/api/chat", json=conflict).json() == {
        "error": "chat_context_mismatch"
    }


@pytest.mark.parametrize(
    "message",
    ["Сколько нашёл SAST?", "Покажи результаты DAST", "Покажи HIGH", "Где отчёт?"],
)
def test_offline_phrases(web, service, message):
    service.run(RunRequest(benchmark_id="demo-full"))
    assert web[0].post("/api/chat", json={"message": message}).status_code == 200
    web[2].factory.assert_not_called()


def test_localized_ui_and_registry_metadata(web):
    client, _, _ = web
    html = client.get("/").text
    for label in (
        "Сканирование",
        "ИИ-помощник",
        "История запусков",
        "Учебные стенды",
        "Обсудить этот запуск",
        "Текущий запуск",
        "Стиль итогового вывода",
    ):
        assert label in html
    assert 'lang="ru"' in html and 'id="chat-finding"' in html
    js = client.get("/static/app.js").text
    assert "Объяснить в ИИ-помощнике" in js and "ui_banner" in js
    assert (
        "payload.run_id = contextRun" in js
        and "payload.finding_id = contextFinding" in js
    )
    entries = {b["id"]: b for b in client.get("/api/benchmarks").json()}
    assert all(b["description_ru"] for b in entries.values())
    assert entries["demo-full"]["baseline_count"] == 7
    assert entries["sample-sast"]["baseline_count"] == 9
    assert entries["juice-shop"]["baseline_count"] is None


def test_unchecked_is_not_an_outage(web):
    client, _, llm = web
    assert (
        client.post("/api/chat", json={"message": "unrecognized request"}).status_code
        == 503
    )
    assert llm.connectivity == "unchecked"
    llm.factory.assert_not_called()


def test_minimized_projection_and_schema(web, service, monkeypatch):
    run = service.run(RunRequest(benchmark_id="demo-full"))
    repo = web[1].state.repository
    findings = repo.findings(run.run_id)
    monkeypatch.setenv("LLM_API_KEY", "PRIVATE-SECRET")
    findings[0].update(
        description="PRIVATE-SECRET" + "x" * 500,
        evidence="PRIVATE-EVIDENCE",
        location="PRIVATE-PATH",
    )
    projected = analysis_input(
        repo.summary(run.run_id), findings, "help", "ANALYZE_RUN"
    )
    assert "PRIVATE" not in json.dumps(projected)
    assert len(projected["findings"][0]["description"]) == 180
    for change in (
        {"answer": "x" * 1801},
        {"referenced_finding_ids": ["0"] * 8},
        {"caveats": ["x"] * 5},
        {"suggested_next_questions": ["x"] * 5},
        {"command": "whoami"},
        {"findings": []},
    ):
        with pytest.raises(ValueError):
            ChatAnalysisResponse.model_validate({**ANALYSIS, **change})
