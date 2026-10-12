import json
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app import main
from app.llm import Enrichment, LLMFindingInput, enrich_findings
from app.models import Finding
from app.preflight import check_target_reachable
from app.semgrep import parse_semgrep_json, run_semgrep
from app.validation import validate_source_path


@pytest.fixture
def finding():
    return Finding(
        id="fixed",
        title="debug",
        source="SAST",
        tool="semgrep",
        location="app.py:1",
        raw_output_ref="logs/raw_semgrep.json#/results/0",
    )


@pytest.fixture
def semgrep_record():
    return {
        "check_id": "debug",
        "path": "app.py",
        "start": {"line": 1, "col": 1},
        "extra": {
            "severity": "WARNING",
            "message": "Debug enabled",
            "lines": "debug=True",
            "metadata": {"confidence": "HIGH", "category": "configuration"},
        },
    }


def test_semgrep_parser(tmp_path, semgrep_record):
    semgrep_record["check_id"] = "agent.config.debug"
    path = tmp_path / "raw_semgrep.json"
    path.write_text(json.dumps({"results": [semgrep_record], "errors": []}))
    result = parse_semgrep_json(path)[0]
    assert (result.source, result.severity, result.confidence) == (
        "SAST",
        "medium",
        "high",
    )
    assert result.location == "app.py:1"
    assert result.title == "debug"
    assert result.evidence == "debug=True"
    assert result.raw_output_ref.endswith("#/results/0")
    assert "extra" not in result.model_dump() and "raw" not in result.model_dump()


@pytest.mark.parametrize(
    "rule_id",
    [
        "python-unsafe-pickle-deserialization",
        "python-debug-enabled",
        "python-subprocess-shell-true",
        "javascript-eval-usage",
    ],
)
def test_semgrep_evidence_never_uses_requires_login(tmp_path, semgrep_record, rule_id):
    semgrep_record["check_id"] = f"agent.config.{rule_id}"
    semgrep_record["extra"]["lines"] = "requires login"
    semgrep_record["extra"]["message"] = f"Scanner message for {rule_id}"
    path = tmp_path / f"{rule_id}.json"
    path.write_text(
        json.dumps({"results": [semgrep_record], "errors": []}), encoding="utf-8"
    )
    finding = parse_semgrep_json(path)[0]
    assert finding.evidence == f"Scanner message for {rule_id}"
    assert finding.evidence != "requires login"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"results": None},
        {"results": [{}]},
        {"results": [], "errors": [{"message": "failure"}]},
    ],
)
def test_semgrep_invalid(tmp_path, payload):
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        parse_semgrep_json(path)


@pytest.mark.parametrize(
    "severity", ["info", "low", "medium", "high", "critical", "unknown"]
)
def test_severity(finding, severity):
    assert (
        Finding.model_validate({**finding.model_dump(), "severity": severity}).severity
        == severity
    )


@pytest.mark.parametrize("severity", ["HIGH", "urgent", 5, None])
def test_invalid_severity(finding, severity):
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding.model_dump(), "severity": severity})


def test_reachability_no_redirects(monkeypatch):
    connection = Mock()
    connection.getresponse.return_value.status = 302
    connection.getresponse.return_value.headers = {"Location": "https://example.com"}
    factory = Mock(return_value=connection)
    monkeypatch.setattr("app.preflight.http.client.HTTPConnection", factory)
    check_target_reachable("http://localhost:3000")
    factory.assert_called_once_with("localhost", 3000, timeout=5)
    connection.request.assert_called_once_with("HEAD", "/")
    connection.close.assert_called_once()


def test_reachability_failure(monkeypatch):
    connection = Mock()
    connection.request.side_effect = OSError("refused")
    monkeypatch.setattr(
        "app.preflight.http.client.HTTPConnection", Mock(return_value=connection)
    )
    with pytest.raises(ValueError, match="unreachable"):
        check_target_reachable("http://localhost:3000")
    connection.close.assert_called_once()


def test_source_path(tmp_path):
    assert validate_source_path(str(tmp_path)) == tmp_path.resolve()
    file = tmp_path / "example.py"
    file.write_text("pass")
    assert validate_source_path(str(file)) == file
    for value in [
        "https://example.com/code",
        "//server/share",
        str(tmp_path / "absent"),
        tmp_path.anchor,
    ]:
        with pytest.raises((ValueError, OSError)):
            validate_source_path(value)


@pytest.fixture
def enrichment():
    return {
        "description": "Debug configuration",
        "normalized_category": "debug_configuration",
        "severity": "low",
        "recommendation": "Disable debug mode.",
        "reasoning_short": "Local development setting.",
    }


def test_llm_validation_and_identity(finding, enrichment):
    client = Mock()
    client.enrich.return_value = Enrichment.model_validate(enrichment)
    results, reasons = enrich_findings([finding], client)
    assert len(results) == 1
    for field in [
        "id",
        "title",
        "source",
        "tool",
        "category",
        "location",
        "evidence",
        "confidence",
        "raw_output_ref",
    ]:
        assert getattr(results[0], field) == getattr(finding, field)
    assert results[0].severity == "low" and reasons == {
        "fixed": enrichment["reasoning_short"]
    }
    assert results[0].normalized_category == "debug_configuration"
    assert finding.severity == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        {"command": "echo unsafe"},
        {"findings": []},
        {"target_url": "https://example.com"},
        {"severity": "urgent"},
        {"recommendation": None},
    ],
)
def test_llm_rejects_invalid_fields(enrichment, extra):
    with pytest.raises(ValidationError):
        Enrichment.model_validate_json(json.dumps({**enrichment, **extra}))


def test_llm_missing_field(enrichment):
    del enrichment["reasoning_short"]
    with pytest.raises(ValidationError):
        Enrichment.model_validate(enrichment)


def test_llm_accepts_plain_technical_prose(enrichment):
    payload = {
        **enrichment,
        "recommendation": "Disable debug mode in the Python application and Docker configuration.",
    }
    assert (
        Enrichment.model_validate(payload).recommendation == payload["recommendation"]
    )


@pytest.mark.parametrize("text", ["   ", "\n\t"])
def test_llm_rejects_blank_text(enrichment, text):
    with pytest.raises(ValidationError):
        Enrichment.model_validate({**enrichment, "recommendation": text})


@pytest.mark.parametrize(
    "text",
    [
        "Set the `X-Content-Type-Options` header to `nosniff`.",
        "Disable `debug=True` outside the development environment.",
        "Review `app/config.py`.",
    ],
)
def test_llm_accepts_legitimate_technical_syntax(enrichment, text):
    result = Enrichment.model_validate({**enrichment, "recommendation": text})
    assert result.recommendation == text


@pytest.mark.parametrize(
    "category",
    [
        "security_headers",
        "cors",
        "secrets",
        "code_execution",
        "unsafe_deserialization",
        "tls_configuration",
        "debug_configuration",
        "injection",
        "authentication",
        "authorization",
        "information_exposure",
        "other",
    ],
)
def test_normalized_category_controlled_vocabulary(enrichment, category):
    result = Enrichment.model_validate({**enrichment, "normalized_category": category})
    assert result.normalized_category == category


@pytest.mark.parametrize("category", ["configuration", "CORS", ""])
def test_malformed_normalized_category_is_rejected(enrichment, category):
    with pytest.raises(ValidationError):
        Enrichment.model_validate({**enrichment, "normalized_category": category})


def test_normalized_category_is_optional(enrichment):
    enrichment.pop("normalized_category")
    assert Enrichment.model_validate(enrichment).normalized_category is None


def test_enrichment_schema_has_only_allowed_fields():
    assert set(Enrichment.model_fields) == {
        "description",
        "normalized_category",
        "severity",
        "recommendation",
        "reasoning_short",
    }


@pytest.mark.parametrize(
    ("field", "length"),
    [("description", 801), ("recommendation", 801), ("reasoning_short", 401)],
)
def test_concise_field_length_limits(enrichment, field, length):
    with pytest.raises(ValidationError):
        Enrichment.model_validate({**enrichment, field: "x" * length})


def test_wildcard_cors_overclaim_is_rejected(enrichment):
    incorrect = (
        "Access-Control-Allow-Origin: * combined with "
        "Access-Control-Allow-Credentials: true allows credentialed cross-origin reads."
    )
    with pytest.raises(ValidationError, match="Wildcard Access-Control-Allow-Origin"):
        Enrichment.model_validate(
            {
                **enrichment,
                "description": incorrect,
                "normalized_category": "cors",
            }
        )

    correct = Enrichment.model_validate(
        {
            **enrichment,
            "description": (
                "Access-Control-Allow-Origin: * permits cross-origin reads of "
                "resources available without credentials. Browsers reject wildcard "
                "origins for credentialed CORS requests."
            ),
            "normalized_category": "cors",
        }
    )
    assert "reject wildcard" in correct.description


def test_empty_enrichment_does_not_call_provider():
    client = Mock()
    assert enrich_findings([], client) == ([], {})
    client.ensure_model_available.assert_called_once_with()
    client.enrich.assert_not_called()


def test_scanner_env_excludes_credentials_and_proxies(monkeypatch, tmp_path):
    from app.scanner_env import scanner_environment

    monkeypatch.setenv("LLM_API_KEY", "secret")
    monkeypatch.setenv("HTTP_PROXY", "http://example.com")
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "secret")
    result = scanner_environment(str(tmp_path))
    assert not {"LLM_API_KEY", "HTTP_PROXY", "SEMGREP_APP_TOKEN"} & result.keys()
    assert result["HOME"] == str(tmp_path)


@pytest.mark.parametrize(
    "mode,args",
    [("sast", []), ("dast", []), ("full", ["--target-url", "http://localhost:3000"])],
)
def test_required_mode_arguments(mode, args):
    assert main.run(["--mode", mode, "--no-llm", *args]) == 1


def test_llm_evidence_is_explicit_opt_in(finding):
    finding = Finding.model_validate(
        {**finding.model_dump(), "evidence": "short normalized evidence"}
    )
    default = LLMFindingInput.from_finding(finding).model_dump(exclude_none=True)
    opted_in = LLMFindingInput.from_finding(finding, include_evidence=True).model_dump(
        exclude_none=True
    )
    assert "evidence" not in default
    assert opted_in["evidence"] == "short normalized evidence"
    assert "raw_output_ref" not in opted_in


def test_full_orchestration(monkeypatch, tmp_path, semgrep_record):
    monkeypatch.chdir(tmp_path)
    events = []

    def sast(source, output):
        events.append("sast")
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps({"results": [semgrep_record]}))

    def dast(target, output):
        events.append("dast")
        output.write_text(
            json.dumps(
                {
                    "template-id": "headers",
                    "info": {"name": "Headers", "severity": "info"},
                }
            )
        )

    monkeypatch.setattr(
        main, "check_target_reachable", lambda _: events.append("preflight")
    )
    monkeypatch.setattr(main, "run_semgrep", sast)
    monkeypatch.setattr(main, "run_nuclei", dast)
    monkeypatch.setattr(
        main,
        "OpenAICompatibleClient",
        Mock(side_effect=AssertionError("LLM must not run")),
    )
    assert (
        main.run(
            [
                "--mode",
                "full",
                "--target-url",
                "http://localhost:3000",
                "--source-path",
                str(tmp_path),
                "--no-llm",
            ]
        )
        == 0
    )
    assert events == ["preflight", "sast", "dast"]
    results = json.loads((tmp_path / "reports/findings.json").read_text())
    assert [r["source"] for r in results] == ["SAST", "DAST"]
    assert all("raw" not in r for r in results)
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert summary["total"] == 2 and summary["by_source"] == {"SAST": 1, "DAST": 1}


def test_unreachable_stops_scanners(monkeypatch, tmp_path):
    monkeypatch.setattr(
        main, "check_target_reachable", Mock(side_effect=ValueError("unreachable"))
    )
    scanner = Mock(side_effect=AssertionError("must not scan"))
    monkeypatch.setattr(main, "run_semgrep", scanner)
    monkeypatch.setattr(main, "run_nuclei", scanner)
    assert (
        main.run(
            [
                "--mode",
                "full",
                "--target-url",
                "http://localhost:3000",
                "--source-path",
                str(tmp_path),
                "--no-llm",
            ]
        )
        == 1
    )
    scanner.assert_not_called()


def test_semgrep_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("app.semgrep.shutil.which", lambda _: "semgrep")
    runner = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr("app.semgrep.subprocess.run", runner)
    run_semgrep(tmp_path, tmp_path / "logs/raw.json")
    command = runner.call_args.args[0]
    assert "--metrics=off" in command and "--json" in command
    assert command[-1] == str(tmp_path.resolve())
    assert "--autofix" not in command
