"""Contract/transport/report tests; MockTransport never opens a network socket."""

import json
from unittest.mock import Mock

import httpx
import pytest
from pydantic import ValidationError

from app.benchmarks import Benchmark, BenchmarkRegistry
from app.config import Settings
from app.nosqli.profiles import Profile, load_profiles
from app.nosqli.scanner import Inconclusive, compare, records, scan_profiles
from app.repository import RunRepository
from app.service import RunRequest, RunService


def responder(variant="positive", inventory=False):
    calls = []
    baseline = "WIDGET-42" if inventory else "APPLE"
    one = (
        {"itemId": "arbitrary-A", "code": baseline}
        if inventory
        else {"_id": "arbitrary-A", "sku": baseline}
    )
    other = (
        {"itemId": "arbitrary-B", "code": "DIFFERENT"}
        if inventory
        else {"_id": "arbitrary-B", "sku": "DIFFERENT"}
    )

    def handle(request):
        calls.append(request)
        payload = (
            json.loads(request.content)
            if request.method == "POST"
            else json.loads(request.url.params["criteria"])
        )
        value = payload["selection"]["code"] if inventory else payload["sku"]
        probe = isinstance(value, dict)
        third = {**other, ("itemId" if inventory else "_id"): "arbitrary-C"}
        rows = [one, other, third] if probe else [one] if value == baseline else []
        if variant == "safe" and probe:
            return httpx.Response(400)
        if variant == "validation422" and probe:
            return httpx.Response(422)
        if variant == "http500" and probe:
            return httpx.Response(500)
        if variant == "unauthorized":
            return httpx.Response(401)
        if variant == "redirect":
            return httpx.Response(302, headers={"Location": "https://example.com"})
        if variant == "timeout":
            raise httpx.ReadTimeout("secret must not appear in logs")
        if variant == "identical":
            rows = [one]
        if variant == "empty":
            rows = []
        if variant == "unstable" and len(calls) == 4:
            rows = [other]
        if variant == "changed-id-only" and probe:
            rows = [one, {**one, "_id": "arbitrary-B"}]
        if variant == "duplicate" and probe:
            rows = [one, one, other]
        if variant == "echo":
            return httpx.Response(200, json=payload)
        if variant == "malformed":
            return httpx.Response(
                200, text="{", headers={"Content-Type": "application/json"}
            )
        if variant == "wrong-type":
            return httpx.Response(
                200, text="{}", headers={"Content-Type": "text/plain"}
            )
        if variant == "duplicate-json":
            return httpx.Response(
                200,
                content=b'{"data":[],"data":[]}',
                headers={"Content-Type": "application/json"},
            )
        if variant == "oversize":
            return httpx.Response(
                200,
                content=b" " * 1_048_577,
                headers={"Content-Type": "application/json"},
            )
        body = {"payload": {"items": rows}, "ok": True} if inventory else {"data": rows}
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handle), calls


@pytest.mark.parametrize(
    "profile", ["catalog-operator", "inventory-post", "inventory-get"]
)
def test_profiles_confirm_with_unseen_record_ids(tmp_path, profile):
    transport, calls = responder(inventory=profile.startswith("inventory"))
    result = scan_profiles(
        "http://localhost:3000", [profile], tmp_path / "raw.json", transport=transport
    )
    assert len(calls) == 4
    assert len(result.findings) == 1
    assert result.warnings == []
    assert result.outcomes[0]["record_counts"] == [1, 3, 0, 1]
    assert result.findings[0].tool == "nosqli-http"
    assert result.findings[0].normalized_category == "injection"
    # No returned record contents or IDs are persisted in logs/evidence.
    assert "arbitrary-A" not in (tmp_path / "raw.json").read_text()
    assert "DIFFERENT" not in result.findings[0].evidence
    assert {r.url.host for r in calls} == {"localhost"}
    assert {r.method for r in calls} == {load_profiles([profile])[0].method}


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("safe", "rejected"),
        ("validation422", "rejected"),
        ("http500", "inconclusive"),
        ("unauthorized", "inconclusive"),
        ("redirect", "inconclusive"),
        ("timeout", "inconclusive"),
        ("identical", "inconclusive"),
        ("empty", "inconclusive"),
        ("unstable", "inconclusive"),
        ("changed-id-only", "not_detected"),
        ("duplicate", "inconclusive"),
        ("echo", "inconclusive"),
        ("malformed", "inconclusive"),
        ("wrong-type", "inconclusive"),
        ("oversize", "inconclusive"),
        ("duplicate-json", "inconclusive"),
    ],
)
def test_negative_responses_are_not_findings(tmp_path, variant, expected):
    transport, calls = responder(variant)
    result = scan_profiles(
        "http://localhost:3000",
        ["catalog-operator"],
        tmp_path / "raw.json",
        transport=transport,
    )
    assert result.findings == []
    assert result.outcomes[0]["status"] == expected
    assert bool(result.warnings) == (expected == "inconclusive")
    assert len(calls) <= 4
    assert "secret" not in (tmp_path / "raw.json").read_text()


@pytest.mark.parametrize(
    "change",
    [
        {"path": "https://example.com/a"},
        {"path": "//example.com/a"},
        {"path": "/a/../b"},
        {"path": "/%2fexample.com"},
        {"path": "/a?x=1"},
        {"method": "DELETE"},
        {"field_path": []},
        {"field_path": ["$where"]},
        {"field_path": ["__proto__"]},
        {"records_path": ["constructor"]},
        {"baseline": {"$ne": ""}},
        {"command": "anything"},
    ],
)
def test_profile_contract_validation(change):
    data = load_profiles(["catalog-operator"])[0].model_dump()
    with pytest.raises(ValidationError):
        Profile.model_validate({**data, **change})


@pytest.mark.parametrize(
    "selected", [[], ["missing"], ["catalog-operator"] * 2, ["x"] * 9]
)
def test_profile_selection_validation(selected):
    with pytest.raises(ValueError):
        load_profiles(selected)


@pytest.mark.parametrize(
    "target", ["https://example.com", "http://localhost/prefix", "http://localhost?x=1"]
)
def test_bad_target_never_sends_request(tmp_path, target):
    transport, calls = responder()
    with pytest.raises(ValueError):
        scan_profiles(
            target, ["catalog-operator"], tmp_path / "raw.json", transport=transport
        )
    assert not calls


@pytest.mark.parametrize(
    "rows",
    [
        None,
        {},
        [{}],
        [{"_id": None, "sku": "APPLE"}],
        [{"_id": True, "sku": "APPLE"}],
        [{"_id": [], "sku": "APPLE"}],
        [{"_id": "id", "sku": {"$ne": "x"}}],
        [{"_id": "id", "sku": "APPLE"}] * 201,
    ],
)
def test_unusable_records(rows):
    with pytest.raises(Inconclusive):
        records({"data": rows}, load_profiles(["catalog-operator"])[0])


def test_typed_record_ids_and_order_independence():
    profile = load_profiles(["catalog-operator"])[0]
    values = [{"_id": 1, "sku": "APPLE"}, {"_id": "1", "sku": "APPLE"}]
    assert records({"data": values}, profile) == records(
        {"data": values[::-1]}, profile
    )
    assert len(records({"data": values}, profile)) == 2
    base = {("str", "1"): "APPLE"}
    assert compare(base, {("str", "2"): "BANANA"}, {}, base, "APPLE") == "not_detected"


@pytest.mark.parametrize(
    "variant,total,status",
    [
        ("positive", 1, "completed"),
        ("safe", 0, "completed"),
        ("http500", 0, "completed_with_warnings"),
    ],
)
def test_service_report_and_repository(tmp_path, monkeypatch, variant, total, status):
    transport, calls = responder(variant)
    monkeypatch.setattr(
        "app.service.Settings.from_env", lambda: Settings(llm_brief_enabled=False)
    )
    monkeypatch.setattr(
        "app.agent.tools.scan_profiles",
        lambda target, profiles, raw: scan_profiles(
            target, profiles, raw, transport=transport
        ),
    )
    nuclei = Mock(
        side_effect=AssertionError("Profile benchmarks use the JSON comparator")
    )
    monkeypatch.setattr("app.agent.tools.run_nuclei", nuclei)
    factory = Mock(side_effect=AssertionError("LLM disabled"))
    result = RunService(
        tmp_path / "runs", client_factory=factory, preflight=Mock()
    ).run(
        RunRequest(
            benchmark_id="nosqli-profile-catalog", mode="dast", llm_enabled=False
        )
    )
    repository = RunRepository(tmp_path / "runs")
    summary = repository.summary(result.run_id)
    assert result.status == status
    assert summary["total"] == total
    assert summary["status"] == status
    assert summary["nosqli_profiles"] == ["catalog-operator"]
    assert bool(summary["warnings"]) == (variant == "http500")
    assert summary["llm_usage"]["total"]["requests"] == 0
    report = repository.text(result.run_id, "report.md")
    findings = repository.json(result.run_id, "findings.json")
    assert len(findings) == total
    if total:
        from benchmark.verify_nosqli_portable import verify

        assert verify("nosqli-profile-catalog", tmp_path / "runs")["findings"] == 1
        raw_path = tmp_path / "runs" / result.run_id / "logs" / "raw_nosqli.json"
        raw_data = json.loads(raw_path.read_text())
        raw_data["profiles"][0]["record_counts"] = [0, 0, 0, 0]
        raw_path.write_text(json.dumps(raw_data))
        with pytest.raises(AssertionError):
            verify("nosqli-profile-catalog", tmp_path / "runs")
        assert "nosqli-http" in report
        assert findings[0]["evidence"]
    assert len(calls) <= 4
    nuclei.assert_not_called()
    factory.assert_not_called()


def test_benchmark_profiles_require_dast():
    data = BenchmarkRegistry.load().get("sample-sast").model_dump()
    with pytest.raises(ValidationError):
        Benchmark.model_validate({**data, "nosqli_profiles": ["catalog-operator"]})


def test_partial_profile_failure_preserves_confirmed_findings(tmp_path):
    good, _ = responder()
    bad, _ = responder("http500", inventory=True)
    transport = httpx.MockTransport(
        lambda request: (
            bad.handle_request(request)
            if request.url.path.startswith("/v2/")
            else good.handle_request(request)
        )
    )
    result = scan_profiles(
        "http://localhost",
        ["catalog-operator", "inventory-post"],
        tmp_path / "raw.json",
        transport=transport,
    )
    assert len(result.findings) == 1
    assert len(result.warnings) == 1
    assert [entry["status"] for entry in result.outcomes] == [
        "confirmed",
        "inconclusive",
    ]
    from app.agent.models import Action, AgentState, Status, ToolResult
    from app.agent.tools import apply_result
    from app.agent.validator import ActionValidator

    state = AgentState(run_id="test", sast_status=Status.SKIPPED)
    apply_result(
        state,
        ToolResult(
            tool=Action.RUN_DAST,
            success=True,
            status=Status.COMPLETED_WITH_FAILURES,
            findings=result.findings,
            findings_added=1,
            warnings=result.warnings,
        ),
    )
    assert state.findings == result.findings and state.warnings == result.warnings
    # Partial scanner success must not deadlock the optional enrichment stage.
    ActionValidator().validate(Action.ENRICH_FINDINGS, state)


def test_profile_results_available_through_web_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.chat import ChatLLM
    from app.web import create_app

    transport, _ = responder()
    monkeypatch.setattr(
        "app.service.Settings.from_env", lambda: Settings(llm_brief_enabled=False)
    )
    monkeypatch.setattr(
        "app.agent.tools.scan_profiles",
        lambda target, profiles, raw: scan_profiles(
            target, profiles, raw, transport=transport
        ),
    )
    factory = Mock(side_effect=AssertionError("No provider requests"))
    service = RunService(tmp_path / "runs", client_factory=factory, preflight=Mock())
    result = service.run(
        RunRequest(
            benchmark_id="nosqli-profile-catalog", mode="dast", llm_enabled=False
        )
    )
    with TestClient(
        create_app(
            runs_dir=service.runs_dir, service=service, llm=ChatLLM(factory=factory)
        ),
        base_url="http://localhost",
    ) as client:
        entries = client.get("/api/benchmarks").json()
        assert any(entry["id"] == "nosqli-profile-inventory" for entry in entries)
        prefix = "/api/runs/" + result.run_id
        assert client.get(prefix).json()["total"] == 1
        findings = client.get(prefix + "/findings?source=DAST").json()
        assert findings[0]["tool"] == "nosqli-http"
        assert "nosqli-http" in client.get(prefix + "/artifacts/report.md").text
    factory.assert_not_called()
