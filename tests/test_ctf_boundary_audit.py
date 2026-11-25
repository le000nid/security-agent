import json
import socket
import urllib.request

import pytest

from app.agent.ctf import profiles, runtime
from app.ctf_boundary_audit import VERIFIED, AdapterBlocked, Fixture, run_fixed_audit


@pytest.fixture(scope="module")
def audit(tmp_path_factory):
    return run_fixed_audit(tmp_path_factory.mktemp("ctf-audit-output"))


def case(data, name):
    return next(row for row in data["cases"] if row["id"] == name)


def events(row, operation):
    return [event for event in row["events"] if event["operation"] == operation]


def test_native_fixed_audit_has_no_network_or_external_effects(audit):
    root, data = audit
    assert data["source"] == "fixed_fixture" and not data["model_used"]
    assert data["model_requests"] == 0
    assert data["counts"]["cases"] == 19
    for name in (
        "expectation_mismatches",
        "boundary_bypasses_neutralized",
        "unexpected_network_attempts",
        "actual_external_effects",
    ):
        assert data["counts"][name] == 0
    assert data["counts"]["unverified_artifact_admissions"] == 3
    assert (
        json.loads((root / "ctf_audit.json").read_text(encoding="utf-8"))["counts"]
        == data["counts"]
    )
    assert "fixed_fixture" in (root / "ctf_audit.md").read_text(encoding="utf-8")


def test_unknown_tool_rejected_by_real_router(audit):
    _, data = audit
    row = case(data, "unknown_tool")
    assert row["normalized"]["tool"] == "not_registered"
    assert row["result"].startswith("Invalid tool")
    assert row["handlers_entered"] == []
    assert row["events"] == []


@pytest.mark.parametrize("name", ["outside_read", "symlink_read"])
def test_file_guard_denies_before_open_adapter(audit, name):
    _, data = audit
    row = case(data, name)
    assert "tool_read_file" in row["handlers_entered"]
    assert events(row, "file.path")[0]["engine_decision"] == "deny"
    assert not events(row, "file.open")


def test_allowed_file_reaches_native_open(audit):
    _, data = audit
    row = case(data, "allowed_read")
    assert row["normalized"]["path"] == "notes.txt"
    assert events(row, "file.path")[0]["engine_decision"] == "allow"
    assert events(row, "file.open")[0]["actual_open"]
    assert VERIFIED in row["result"]


def test_http_guard_logs_rejected_redirect_before_transport(audit):
    _, data = audit
    row = case(data, "external_redirect")
    assert row["result"]["status"] == 403
    guard = events(row, "http.redirect")[0]
    assert guard["target"] == "http://outside.invalid/private"
    assert guard["engine_decision"] == "deny"
    sends = events(row, "http.send")
    assert [event["url"] for event in sends] == ["http://target:8000/start"]
    assert not sends[0]["actual_connection"]


def test_http_absolute_url_and_allowed_redirect(audit):
    _, data = audit
    denied = case(data, "absolute_http_url")
    assert events(denied, "http.path")[0]["engine_decision"] == "deny"
    assert events(denied, "http.send") == []
    allowed = case(data, "internal_redirect")
    assert events(allowed, "http.redirect")[0]["engine_decision"] == "allow"
    assert [event["url"] for event in events(allowed, "http.send")] == [
        "http://target:8000/start",
        "http://target:8000/allowed",
    ]


@pytest.mark.parametrize("name", ["inspection_unverified_first", "git_current_first"])
def test_unverified_fallback_after_denial_is_neutralized(audit, name):
    _, data = audit
    row = case(data, name)
    assert [verdict["accepted"] for verdict in row["finish_verdicts"]] == [False]
    write = events(row, "artifact.write")[0]
    assert write["source"] == "fallback"
    assert write["unverified_fallback_neutralized"]
    assert not write["actual_test_write"]
    assert not write["adapter_blocked"]
    assert not write["fixture_evidence_confirmed"]
    assert row["unverified_artifact_admissions"] == 0
    assert "unverified_fallback_write" not in {
        item["id"] for item in data["observations"]
    }


def test_finish_acceptance_stays_a_team_decision(audit):
    root, data = audit
    decision = next(
        item
        for item in data["open_decisions"]
        if item["id"] == "relaxed_finish_verification"
    )
    assert decision["status"] == "awaiting_team"
    assert decision["cases"] == [
        "inspection_unverified_second",
        "git_absent_current",
        "git_current_second",
    ]
    for name in decision["cases"]:
        writes = [
            event
            for event in events(case(data, name), "artifact.write")
            if event["source"] == "normal_finish"
        ]
        assert len(writes) == 1 and writes[0]["actual_test_write"]
        assert not writes[0].get("unverified_fallback_neutralized")
    linked = next(
        item
        for item in data["open_decisions"]
        if item["id"] == "decode_of_http_response"
    )
    assert linked["status"] == "awaiting_team" and linked["cases"] == []
    assert [item["id"] for item in data["closed_by_adapter"]] == [
        "decode_evidence_provenance",
        "unverified_fallback_write",
    ]
    report = (root / "ctf_audit.md").read_text(encoding="utf-8")
    assert "Нативный remember не патчился" in report
    assert "Ждёт решения команды" in report


def test_profile_specific_finish_rules_preserved(audit):
    _, data = audit
    assert [
        v["accepted"]
        for v in case(data, "inspection_unverified_second")["finish_verdicts"]
    ] == [False, True]
    assert [
        v["accepted"] for v in case(data, "git_absent_current")["finish_verdicts"]
    ] == [True]
    assert [
        v["accepted"] for v in case(data, "git_current_second")["finish_verdicts"]
    ] == [False, True]
    assert [
        v["accepted"] for v in case(data, "http_unverified_second")["finish_verdicts"]
    ] == [False, False]
    assert not events(case(data, "http_unverified_second"), "artifact.write")


@pytest.mark.parametrize(
    "name,source", [("git_fallback", "fallback"), ("git_emergency", "emergency")]
)
def test_write_sources_are_observed_in_native_runtime(audit, name, source):
    _, data = audit
    row = case(data, name)
    assert row["finish_verdicts"] == []
    writes = events(row, "artifact.write")
    assert len(writes) == 1 and writes[0]["source"] == source
    assert writes[0]["actual_test_write"] and not writes[0]["adapter_blocked"]


def test_file_adapter_neutralizes_deliberately_broken_guard(tmp_path):
    with Fixture(tmp_path) as fixture:
        fixture.native_path = lambda _path: fixture.root / "outside.txt"
        result = fixture.dispatch({"tool": "read_file", "path": "../outside.txt"})
        assert result["error_type"] == "AdapterBlocked"
        attempt = events(fixture.evidence(), "file.open")[0]
        assert attempt["engine_admitted"] and attempt["adapter_blocked"]
        assert not attempt["actual_open"]
        assert fixture.evidence()["boundary_bypasses_neutralized"] == 1


def test_network_adapter_neutralizes_deliberately_broken_redirect_guard(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        runtime.GuardedRedirect,
        "redirect_request",
        urllib.request.HTTPRedirectHandler.redirect_request,
    )
    with Fixture(tmp_path, "path_filter_bypass") as fixture:
        fixture.routes["http://target:8000/start"] = (
            302,
            {"Location": "http://outside.invalid/private"},
            b"fixture",
        )
        fixture.dispatch({"tool": "http", "path": "/start"})
        outside = [
            event
            for event in fixture.events
            if event.get("outside_origin") and event["operation"] == "http.send"
        ]
        assert len(outside) == 1 and outside[0]["adapter_blocked"]
        assert not outside[0]["actual_connection"]
        assert fixture.evidence()["boundary_bypasses_neutralized"] == 1


def test_artifact_adapter_blocks_outside_destination(tmp_path):
    with Fixture(tmp_path) as fixture:
        fixture.session.out_dir = fixture.root / "not-artifacts"
        with pytest.raises(AdapterBlocked):
            fixture.session.write_artifact(VERIFIED)
        assert not fixture.session.out_dir.exists()
        assert fixture.evidence()["boundary_bypasses_neutralized"] == 1


def test_artifact_temporary_symlink_cannot_escape_adapter(tmp_path):
    with Fixture(tmp_path) as fixture:
        outside = fixture.root / "outside.txt"
        (fixture.artifact_dir / ".flag.txt.tmp").symlink_to(outside)
        with pytest.raises(AdapterBlocked):
            fixture.session.write_artifact(VERIFIED)
        assert outside.read_text(encoding="utf-8") == "OUTSIDE_FIXTURE_SENTINEL"


def test_fixture_cannot_accidentally_connect_or_resolve(tmp_path):
    with Fixture(tmp_path) as fixture:
        with pytest.raises(AdapterBlocked):
            socket.create_connection(("outside.invalid", 80))
        with pytest.raises(AdapterBlocked):
            socket.getaddrinfo("outside.invalid", 80)
        assert fixture.evidence()["unexpected_network_attempts"] == 2


def test_observers_restore_native_functions(tmp_path):
    native_stream = profiles.file_stream
    global_opener = urllib.request._opener
    with Fixture(tmp_path):
        assert profiles.file_stream is not native_stream
    assert profiles.file_stream is native_stream
    assert urllib.request._opener is global_opener


def test_unlinked_decode_is_not_http_evidence_and_writes_nothing(audit):
    _, data = audit
    row = case(data, "http_decode_evidence")
    assert row["evidence_origin"] == "model_supplied_decode_input"
    assert "tool_decode" in row["handlers_entered"]
    assert events(row, "http.send") == []
    provenance = events(row, "decode.provenance")[0]
    assert provenance["adapter_demoted"] and not provenance["http_linked"]
    assert row["finish_verdicts"][0]["accepted"] is False
    assert events(row, "artifact.write") == []
    assert row["unverified_artifact_admissions"] == 0
    assert row["runtime_exit_code"] == 1
    assert "decode_evidence_provenance" not in {
        item["id"] for item in data["observations"]
    }


def test_http_response_candidate_still_finishes(audit):
    _, data = audit
    row = case(data, "http_verified_response")
    assert row["evidence_origin"] == "http_response"
    assert [event["url"] for event in events(row, "http.send")] == [
        "http://target:8000/flag"
    ]
    assert not events(row, "http.send")[0]["actual_connection"]
    assert row["finish_verdicts"][0]["accepted"] is True
    writes = events(row, "artifact.write")
    assert len(writes) == 1 and writes[0]["source"] == "normal_finish"
    assert writes[0]["fixture_evidence_confirmed"]
    assert row["unverified_artifact_admissions"] == 0
