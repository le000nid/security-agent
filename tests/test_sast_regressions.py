"""The combined acceptance command must not hide failed or incomplete checks."""

import json

import pytest

from benchmark import verify_sast_regressions as runner


@pytest.fixture
def fake_checks(monkeypatch):
    monkeypatch.setattr(runner, "check_baseline", lambda *_: {"detected_rule_ids": 6})
    calls = []

    def variants(_targets, _output, name, _count, _verifier):
        calls.append(name)
        return {"findings": 14}

    monkeypatch.setattr(runner, "check_variants", variants)
    monkeypatch.setattr(
        runner.verify_sast_contract, "verify", lambda: {"no_code_scan": "rejected"}
    )
    return calls


def test_all_six_checks_are_recorded(tmp_path, fake_checks):
    report = runner.run_all(tmp_path, tmp_path / "output")
    assert report["status"] == "passed"
    assert set(report["checks"]) == {
        "sast-contours",
        "sast-sqli-hardening",
        "sast-sqli-variants",
        "sast-lfi-variants",
        "sast-rfi-variants",
        "scanner-contract",
    }
    assert fake_checks == [name for name, _, _ in runner.SUITES]
    assert json.loads((tmp_path / "output/summary.json").read_text()) == report


@pytest.mark.parametrize("failure", ["baseline", "variants", "contract"])
def test_failure_is_saved_and_other_checks_continue(
    tmp_path, monkeypatch, fake_checks, failure
):
    def broken(*_args):
        raise ValueError("injected acceptance failure")

    if failure == "baseline":
        monkeypatch.setattr(runner, "check_baseline", broken)
    elif failure == "variants":
        monkeypatch.setattr(runner, "check_variants", broken)
    else:
        monkeypatch.setattr(runner.verify_sast_contract, "verify", broken)
    output = tmp_path / "output"
    output.mkdir()
    (output / "summary.json").write_text('{"status":"passed"}')
    report = runner.run_all(tmp_path, output)
    assert report["status"] == "failed"
    assert len(report["checks"]) == 6
    assert any(check["status"] == "passed" for check in report["checks"].values())
    assert any(
        check.get("error") == "injected acceptance failure"
        for check in report["checks"].values()
    )
    assert json.loads((output / "summary.json").read_text())["status"] == "failed"


def test_scan_failure_never_parses_a_stale_report(tmp_path, monkeypatch):
    raw = tmp_path / "raw.json"
    raw.write_text('{"results":[],"errors":[]}')

    def broken(*_args):
        raise ValueError("scanner failed")

    def must_not_parse(*_args):
        pytest.fail("A stale report was read after the scanner failed")

    monkeypatch.setattr(runner, "run_semgrep", broken)
    monkeypatch.setattr(runner, "parse_semgrep_json", must_not_parse)
    with pytest.raises(ValueError, match="scanner failed"):
        runner.scan(tmp_path, raw)


def test_cli_exits_nonzero_for_failed_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(
        runner,
        "run_all",
        lambda *_: {
            "status": "failed",
            "checks": {"scanner-contract": {"status": "failed", "error": "failure"}},
        },
    )
    monkeypatch.setattr(
        "sys.argv", ["verify_sast_regressions", "--output-dir", str(tmp_path)]
    )
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 1
