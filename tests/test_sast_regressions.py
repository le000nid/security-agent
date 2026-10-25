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
        runner.verify_sast_contract, "verify", lambda: {"empty_scan": "rejected"}
    )
    return calls


def test_all_seven_checks_are_recorded(tmp_path, fake_checks):
    report = runner.run_all(tmp_path, tmp_path / "output")
    assert report["status"] == "passed"
    assert set(report["checks"]) == {
        "sast-contours",
        "sast-secrets",
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
    assert len(report["checks"]) == 7
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


@pytest.fixture
def baseline_scan(tmp_path):
    source = tmp_path / "sast-contours"
    source.mkdir()
    for name in runner.BASELINE_FILES:
        (source / name).touch()
    return source, {
        "paths": {"scanned": [str(source / n) for n in sorted(runner.BASELINE_FILES)]}
    }


def test_baseline_requires_all_twelve_files(baseline_scan):
    source, payload = baseline_scan
    assert runner.check_baseline_coverage(source, payload) == 12


@pytest.mark.parametrize(
    "damage",
    ["missing-safe", "duplicate", "foreign-path", "missing-fixture", "extra-fixture"],
)
def test_baseline_rejects_incomplete_or_wrong_inventory(baseline_scan, damage):
    source, payload = baseline_scan
    scanned = payload["paths"]["scanned"]
    if damage == "missing-safe":
        scanned.remove(str(source / "benign.js"))
    elif damage == "duplicate":
        scanned.append(scanned[0])
    elif damage == "foreign-path":
        scanned[0] = str(source.parent / "other" / "benign.js")
    elif damage == "missing-fixture":
        (source / "benign.js").unlink()
    else:
        (source / "extra.py").touch()
    with pytest.raises(ValueError):
        runner.check_baseline_coverage(source, payload)


def test_interrupt_replaces_old_success_with_current_progress(
    tmp_path, monkeypatch, fake_checks
):
    output = tmp_path / "output"
    output.mkdir()
    (output / "summary.json").write_text('{"status":"passed"}')

    def interrupted(*_args):
        report = json.loads((output / "summary.json").read_text())
        assert report["status"] == "running"
        assert report["checks"]["sast-contours"]["status"] == "passed"
        assert report["checks"]["sast-secrets"]["status"] == "running"
        assert report["checks"]["scanner-contract"]["status"] == "pending"
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "check_variants", interrupted)
    with pytest.raises(KeyboardInterrupt):
        runner.run_all(tmp_path, output)
    assert json.loads((output / "summary.json").read_text())["status"] == "running"
    assert list(output.glob(".summary-*.tmp")) == []


def test_atomic_report_failure_keeps_valid_previous_json(tmp_path, monkeypatch):
    destination = tmp_path / "summary.json"
    destination.write_text('{"status":"running"}')

    def broken_replace(*_args):
        raise OSError("injected replace failure")

    monkeypatch.setattr(runner.Path, "replace", broken_replace)
    with pytest.raises(OSError, match="injected replace failure"):
        runner.save_report(tmp_path, {"status": "passed"})
    assert json.loads(destination.read_text()) == {"status": "running"}
    assert list(tmp_path.glob(".summary-*.tmp")) == []
