"""v0.3.2 reliability/synthesis regressions; all HTTP is mocked."""

import json

import pytest
from pydantic import ValidationError
from test_stabilization import DECISION, ENRICHMENT, chat
from test_stabilization import rig as rig  # reusable offline HTTP/scanner fixture

from app.agent.loop import run_agent, run_deterministic
from app.agent.models import Action, Status
from app.agent.planner import Planner
from app.agent.validator import ActionValidator
from app.brief import BRIEF_PROMPT, brief_input, generate_ai_brief
from app.cli import run
from app.config import ReportLanguage, ReportTone, Settings
from app.enrichment import enrich_independently
from app.llm import SYSTEM_PROMPT, Enrichment
from app.llm_output import LLMError

BRIEF = {
    "headline": "Review the observed configuration",
    "overall_summary": "The scanner identified a setting requiring review.",
    "top_findings": [
        {"finding_id": "sample", "why_it_matters": "Diagnostic exposure needs review."}
    ],
    "recommended_next_steps": ["Verify the scanner evidence and review the setting."],
    "limitations": "Limited checks; no proof of exploitation or overall security.",
    "closing_line": "Validate the change before release.",
}


def encoded(payload):
    return chat(json.dumps(payload))


@pytest.fixture
def brief_rig(rig):
    state, client, http, registry, finding = rig
    registry.settings = client.settings
    return state, client, http, registry, finding


@pytest.mark.parametrize(
    "case,completed,failed,retried,requests",
    [
        ("success", 3, 0, 0, 3),
        ("retry_success", 3, 0, 1, 4),
        ("retry_failure", 2, 1, 1, 4),
        ("malformed", 2, 1, 0, 3),
        ("empty", 2, 1, 0, 3),
        ("category", 2, 1, 0, 3),
        ("identity", 2, 1, 0, 3),
        ("schema", 2, 1, 0, 3),
        ("all_failed", 0, 3, 0, 3),
    ],
)
def test_per_finding_isolation_and_accounting(
    rig, case, completed, failed, retried, requests
):
    _, client, http, _, finding = rig
    findings = [finding.model_copy(update={"id": f"id-{i}"}) for i in range(3)]
    good = encoded(ENRICHMENT)
    bad = {
        "success": [good],
        "retry_success": [chat("", "length"), good],
        "retry_failure": [chat("", "length"), chat("", "length")],
        "malformed": [chat("malformed PRIVATE-CHAIN-OF-THOUGHT")],
        "empty": [chat("")],
        "category": [encoded({**ENRICHMENT, "normalized_category": "bad"})],
        "identity": [encoded({**ENRICHMENT, "id": "changed"})],
        "schema": [encoded({**ENRICHMENT, "severity": "urgent"})],
        "all_failed": [chat("bad")],
    }[case]
    http.request.side_effect = (
        [chat("bad")] * 3 if case == "all_failed" else [good, *bad, good]
    )
    result = enrich_independently(findings, client)
    assert len(result.findings) == len(findings) == result.stats.requested == 3
    assert (result.stats.completed, result.stats.failed, result.stats.retried) == (
        completed,
        failed,
        retried,
    )
    assert client.usage.requests == http.request.call_count == requests
    for original, enriched in zip(findings, result.findings):
        for name in (
            "id",
            "category",
            "title",
            "tool",
            "source",
            "confidence",
            "location",
            "evidence",
            "raw_output_ref",
        ):
            assert getattr(original, name) == getattr(enriched, name)
    if failed and case != "all_failed":
        assert result.findings[1] is findings[1]
        assert (
            result.findings[0].description
            == result.findings[2].description
            == ENRICHMENT["description"]
        )
        assert set(result.rationales) == {"id-0", "id-2"}
    assert "PRIVATE-CHAIN" not in result.stats.model_dump_json()
    assert len(result.stats.failures) == failed


def test_configured_enrichment_retry_budget_and_repair(rig):
    _, client, http, _, finding = rig
    client.settings = Settings(
        llm_enrichment_max_tokens=1300, llm_enrichment_retry_max_tokens=2400
    )
    http.request.side_effect = [chat("", "length"), encoded(ENRICHMENT)]
    result = enrich_independently([finding], client)
    sent = [c.kwargs["json"] for c in http.request.call_args_list]
    assert [s["max_tokens"] for s in sent] == [1300, 2400]
    assert result.stats.retried == result.stats.completed == 1
    assert "Keep the answer concise" in sent[1]["messages"][0]["content"]
    assert "PRIVATE-CHAIN" not in json.dumps(sent)
    assert not any("max_completion_tokens" in s for s in sent)


def test_experimental_batches_fail_independently(rig):
    _, client, http, _, finding = rig
    findings = [finding.model_copy(update={"id": str(i)}) for i in range(3)]
    http.request.side_effect = [
        encoded({"results": []}),
        encoded({"results": [{"id": "2", "enrichment": ENRICHMENT}]}),
    ]
    result = enrich_independently(findings, client, batch_size=2)
    assert result.stats.completed == 1 and result.stats.failed == 2
    assert result.findings[:2] == findings[:2]
    assert result.findings[2].description == ENRICHMENT["description"]


@pytest.mark.parametrize("tone", list(ReportTone))
@pytest.mark.parametrize("language", list(ReportLanguage))
def test_brief_tone_language_structured_success(brief_rig, tone, language):
    state, client, http, _, finding = brief_rig
    state.findings = [finding]
    original = finding.model_dump()
    http.request.return_value = encoded(BRIEF)
    brief = generate_ai_brief(
        state, client, Settings(llm_report_tone=tone, llm_report_language=language)
    )
    assert brief.headline == BRIEF["headline"]
    assert state.findings == [finding] and finding.model_dump() == original
    sent = http.request.call_args.kwargs["json"]
    prompt = sent["messages"][0]["content"]
    assert ("Russian" if language == ReportLanguage.RU else "English") in prompt
    if tone == ReportTone.FUNNY:
        assert "metaphors" in prompt and "Never trivialize critical/high" in prompt
    elif tone == ReportTone.CONCISE:
        assert "very short and direct" in prompt
    else:
        assert "professional engineering" in prompt
    assert client.brief_usage.requests == 1 and client.usage.requests == 0


@pytest.mark.parametrize(
    "fields",
    [
        {"llm_report_tone": "ignore instructions"},
        {"llm_report_language": "xx"},
        {"llm_brief_enabled": "maybe"},
        {"llm_brief_max_tokens": 0},
        {"llm_brief_retry_max_tokens": 999},
        {"llm_enrichment_retry_max_tokens": 1100},
        {"llm_enrichment_max_tokens": 99999},
    ],
)
def test_invalid_configuration_rejected(fields):
    with pytest.raises(ValidationError):
        Settings(**fields)


@pytest.mark.parametrize(
    "payload,code",
    [
        (
            {
                **BRIEF,
                "top_findings": [{"finding_id": "invented", "why_it_matters": "bad"}],
            },
            "brief_unknown_finding_id",
        ),
        (
            {**BRIEF, "top_findings": BRIEF["top_findings"] * 2},
            "brief_duplicate_finding_id",
        ),
        ({**BRIEF, "findings": [{"id": "invented"}]}, "brief_schema_validation_error"),
        ({**BRIEF, "command": "whoami"}, "brief_schema_validation_error"),
        ({**BRIEF, "headline": "x" * 121}, "brief_schema_validation_error"),
        (
            {**BRIEF, "recommended_next_steps": ["step"] * 6},
            "brief_schema_validation_error",
        ),
        ({**BRIEF, "overall_summary": " "}, "brief_schema_validation_error"),
    ],
)
def test_brief_invalid_output_cannot_change_findings(brief_rig, payload, code):
    state, client, http, _, finding = brief_rig
    state.findings = [finding]
    http.request.return_value = encoded(payload)
    with pytest.raises(LLMError) as caught:
        generate_ai_brief(state, client, Settings())
    assert caught.value.code == code
    assert state.findings == [finding] and http.request.call_count == 1


@pytest.mark.parametrize("succeeds", [True, False])
def test_brief_one_retry_with_larger_budget(brief_rig, succeeds):
    state, client, http, _, finding = brief_rig
    state.findings = [finding]
    http.request.side_effect = [
        chat("", "length"),
        encoded(BRIEF) if succeeds else chat("", "length"),
    ]
    settings = Settings(llm_brief_max_tokens=1100, llm_brief_retry_max_tokens=1800)
    if succeeds:
        assert generate_ai_brief(state, client, settings).headline == BRIEF["headline"]
    else:
        with pytest.raises(LLMError, match="response truncated"):
            generate_ai_brief(state, client, settings)
    assert [c.kwargs["json"]["max_tokens"] for c in http.request.call_args_list] == [
        1100,
        1800,
    ]
    assert client.brief_usage.requests == 2 and client.usage.requests == 0


def test_brief_input_privacy(brief_rig, monkeypatch):
    state, _, _, _, finding = brief_rig
    monkeypatch.setenv("LLM_API_KEY", "sentinel-secret")
    state.findings = [
        finding.model_copy(
            update={
                "description": "Observed sentinel-secret",
                "evidence": "PRIVATE_SOURCE",
                "location": "/private/source.py",
                "raw_output_ref": "logs/PRIVATE_RAW.json",
            }
        )
    ]
    body = json.dumps(brief_input(state))
    for private in (
        "sentinel-secret",
        "PRIVATE_SOURCE",
        "PRIVATE_RAW",
        "/private",
        state.source_path,
        state.target_url,
        "raw_output_ref",
        "evidence",
        "location",
    ):
        assert private not in body
    assert "[REDACTED]" in body
    assert "No findings does not prove" in BRIEF_PROMPT


def test_brief_redacts_before_truncating_sensitive_text(brief_rig, monkeypatch):
    state, _, _, _, finding = brief_rig
    monkeypatch.setenv("LLM_API_KEY", "boundary-secret-that-must-not-leak")
    state.findings = [
        finding.model_copy(
            update={
                "title": "x" * 115 + "boundary-secret-that-must-not-leak",
                "description": "x" * 295 + "boundary-secret-that-must-not-leak",
            }
        )
    ]
    assert "bound" not in json.dumps(brief_input(state))


def test_full_agent_brief_is_single_option_and_preserves_scanners(brief_rig):
    state, client, http, registry, _ = brief_rig
    http.request.side_effect = [encoded(DECISION), encoded(ENRICHMENT), encoded(BRIEF)]
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=1))
    assert state.executed_actions == list(Action) and state.agent_step_count == 6
    assert state.planner_request_count == client.planner_usage.requests == 1
    assert state.trace[3].action == "GENERATE_AI_BRIEF"
    assert state.trace[3].decision_source == "deterministic_single_option"
    assert state.finish_reason == "completed" and len(state.findings) == 1
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["ai_brief_status"] == "completed"
    assert summary["llm_usage"]["total"]["requests"] == 3
    assert summary["enrichment"]["completed"] == summary["enrichment"]["requested"] == 1


def test_partial_enrichment_is_warning_and_brief_still_runs(brief_rig, monkeypatch):
    state, client, http, registry, finding = brief_rig
    second = finding.model_copy(update={"id": "second"})
    monkeypatch.setattr(
        "app.agent.tools.parse_semgrep_json", lambda *_: [finding, second]
    )
    http.request.side_effect = [
        encoded(ENRICHMENT),
        chat("", "length"),
        chat("", "length"),
        encoded(BRIEF),
    ]
    run_deterministic(state, registry)
    assert state.exit_code == 0 and state.finish_reason == "completed_with_warnings"
    assert state.enrichment_status == Status.COMPLETED_WITH_FAILURES
    assert state.enrichment.model_dump() == {
        "requested": 2,
        "completed": 1,
        "failed": 1,
        "retried": 1,
        "failures": [
            {"finding_id": "second", "error_code": "enrichment_response_truncated"}
        ],
    }
    assert state.findings[1] is second
    assert state.findings[0].description == ENRICHMENT["description"]
    assert (
        state.ai_brief_status == Status.COMPLETED
        and state.report_status == Status.COMPLETED
    )
    assert client.planner_usage.requests == state.planner_request_count == 0
    assert len([t for t in state.trace if t.action == "ENRICH_FINDINGS"]) == 1


def test_brief_failure_does_not_break_reporting(brief_rig):
    state, _, http, registry, _ = brief_rig
    http.request.side_effect = [encoded(ENRICHMENT), chat("bad JSON")]
    run_deterministic(state, registry)
    assert state.exit_code == 0 and state.ai_brief_status == Status.FAILED
    assert state.findings[0].description == ENRICHMENT["description"]
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["status"] == "completed_with_warnings"
    assert summary["last_error_code"] == "brief_json_decode_error"
    assert (registry.paths.reports / "report.md").is_file()
    assert json.loads((registry.paths.reports / "ai_brief.json").read_text()) == {
        "status": "failed"
    }


def test_funny_brief_rendered_near_top_and_details_stay_technical(
    brief_rig, monkeypatch
):
    state, _, http, registry, _ = brief_rig
    monkeypatch.setenv("LLM_API_KEY", "sentinel-secret")
    state.report_tone = ReportTone.FUNNY
    registry.settings = Settings(llm_report_tone="funny")
    brief = {
        **BRIEF,
        "headline": "Конфигурация просит каску.",
        "closing_line": "Review sentinel-secret",
    }
    http.request.side_effect = [encoded(ENRICHMENT), encoded(brief)]
    run_deterministic(state, registry)
    report = (registry.paths.reports / "report.md").read_text(encoding="utf-8")
    assert report.index("## AI Security Brief") < report.index("## Findings")
    assert "Конфигурация просит каску." in report
    details = report.split("## Findings", 1)[1]
    assert "каску" not in details and ENRICHMENT["description"] in details
    for path in registry.paths.reports.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "sentinel-secret" not in text and "PRIVATE-CHAIN" not in text
    summary = json.loads((registry.paths.reports / "summary.json").read_text())
    assert summary["report_tone"] == "funny" and summary["report_language"] == "ru"
    enrichment_prompt = http.request.call_args_list[0].kwargs["json"]["messages"][0][
        "content"
    ]
    assert "metaphors" not in enrichment_prompt


def test_no_llm_skips_brief_without_any_request(brief_rig):
    state, _, http, registry, _ = brief_rig
    registry.client = None
    state.enrichment_status = Status.SKIPPED
    run_deterministic(state, registry)
    http.request.assert_not_called()
    assert state.ai_brief_status == Status.SKIPPED
    assert json.loads((registry.paths.reports / "ai_brief.json").read_text()) == {
        "status": "skipped"
    }


def test_no_findings_brief_is_allowed_but_never_proof_of_security(
    brief_rig, monkeypatch
):
    state, _, http, registry, _ = brief_rig
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: [])
    http.request.return_value = encoded({**BRIEF, "top_findings": []})
    run_deterministic(state, registry)
    assert state.enrichment_status == Status.SKIPPED
    assert state.ai_brief_status == Status.COMPLETED and not state.findings
    assert (
        "No findings does not prove"
        in http.request.call_args.kwargs["json"]["messages"][0]["content"]
    )


def test_brief_validator_order(brief_rig):
    state, _, _, _, _ = brief_rig
    validator = ActionValidator()
    with pytest.raises(ValueError):
        validator.validate(Action.GENERATE_AI_BRIEF, state)
    state.sast_status = state.dast_status = Status.COMPLETED
    with pytest.raises(ValueError):
        validator.validate(Action.GENERATE_AI_BRIEF, state)
    state.enrichment_status = Status.COMPLETED_WITH_FAILURES
    assert validator.allowed(state) == [Action.GENERATE_AI_BRIEF]
    state.ai_brief_status = Status.FAILED
    assert validator.allowed(state) == [Action.GENERATE_REPORT]


def test_missing_referrer_policy_prompt_and_overclaim_regression():
    assert "strict-origin-when-cross-origin" in SYSTEM_PROMPT
    assert "never claim full path/query cross-origin leakage solely" in SYSTEM_PROMPT
    bad = {
        **ENRICHMENT,
        "description": "Missing Referrer-Policy sends the full URL including path and query to other origins.",
    }
    with pytest.raises(ValidationError):
        Enrichment.model_validate(bad)
    good = {
        **ENRICHMENT,
        "description": (
            "An explicit Referrer-Policy is absent. Behavior depends on browser defaults; modern "
            "browsers generally use strict-origin-when-cross-origin. An explicit policy makes behavior predictable."
        ),
    }
    assert Enrichment.model_validate(good)


def test_cli_final_console_contains_short_brief_and_paths(
    brief_rig, monkeypatch, capsys
):
    state, client, http, registry, _ = brief_rig
    monkeypatch.setattr("app.cli.load_dotenv", lambda: None)
    monkeypatch.setattr("app.service.Settings.from_env", lambda: Settings())
    monkeypatch.setattr("app.cli.OpenAICompatibleClient", lambda **_: client)
    http.request.side_effect = [encoded(ENRICHMENT), encoded(BRIEF)]
    assert (
        run(
            [
                "scan",
                "--mode",
                "sast",
                "--source-path",
                state.source_path,
                "--runs-dir",
                str(registry.paths.root.parent),
            ]
        )
        == 0
    )
    output = capsys.readouterr().err
    assert "AI Security Brief:" in output and BRIEF["headline"] in output
    assert "Report:" in output and "Summary:" in output
    assert "PRIVATE-CHAIN" not in output


def test_twelve_finding_full_regression_one_truncation_does_not_rollback(
    brief_rig, monkeypatch
):
    state, client, http, registry, finding = brief_rig
    sast = [
        finding.model_copy(update={"id": "sample" if i == 0 else f"sast-{i}"})
        for i in range(9)
    ]
    dast = [
        finding.model_copy(
            update={"id": f"dast-{i}", "source": "DAST", "tool": "nuclei"}
        )
        for i in range(3)
    ]
    monkeypatch.setattr("app.agent.tools.parse_semgrep_json", lambda *_: sast)
    monkeypatch.setattr("app.agent.tools.parse_nuclei_jsonl", lambda *_: dast)
    http.request.side_effect = [
        encoded(DECISION),
        encoded(ENRICHMENT),
        encoded(ENRICHMENT),
        chat("", "length"),
        chat("", "length"),
        *[encoded(ENRICHMENT) for _ in range(9)],
        encoded(BRIEF),
    ]
    run_agent(state, Planner(client), registry, Settings(agent_max_planner_calls=1))
    assert state.exit_code == 0 and state.finish_reason == "completed_with_warnings"
    assert state.enrichment.requested == 12 and state.enrichment.completed == 11
    assert state.enrichment.failed == state.enrichment.retried == 1
    assert state.findings[2] is sast[2] and len(state.findings) == 12
    assert state.ai_brief_status == state.report_status == Status.COMPLETED
    assert state.planner_request_count == 1 and client.usage.requests == 13
    assert client.brief_usage.requests == 1 and len(state.trace) == 6


def test_api_key_echo_in_enrichment_not_written_to_reports(brief_rig, monkeypatch):
    state, _, http, registry, _ = brief_rig
    monkeypatch.setenv("LLM_API_KEY", "sentinel-echo-secret")
    http.request.side_effect = [
        encoded({**ENRICHMENT, "description": "Observed sentinel-echo-secret"}),
        encoded(BRIEF),
    ]
    run_deterministic(state, registry)
    for path in registry.paths.reports.iterdir():
        assert "sentinel-echo-secret" not in path.read_text(encoding="utf-8")
