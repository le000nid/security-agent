"""Scanner failures must remain failures in the final SAST report."""

import json
import subprocess
from functools import partial
from tempfile import TemporaryDirectory
from unittest.mock import Mock

import pytest

from app import semgrep
from app.agent.loop import run_deterministic
from app.agent.models import Action, AgentState, Status
from app.agent.tools import ToolRegistry
from app.runs import RunPaths


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_executable",
        "timeout",
        "os_error",
        "nonzero_exit",
        "broken_json",
        "scan_errors",
        "invalid_results",
        "malformed_finding",
        "missing_errors",
        "empty_scan",
        "skipped_rules",
        "duplicate_results_key",
    ],
)
def test_scanner_failure_is_not_a_clean_report(monkeypatch, tmp_path, scenario):
    source = tmp_path / "source.py"
    source.write_text("pass\n", encoding="utf-8")
    paths = RunPaths.create(tmp_path / "runs")
    state = AgentState(
        run_id=paths.run_id,
        mode="sast",
        source_path=str(source),
        source_available=True,
        source_validated=True,
        dast_status=Status.SKIPPED,
    )
    monkeypatch.setattr(
        semgrep.shutil,
        "which",
        lambda _: None if scenario == "missing_executable" else "semgrep",
    )
    monkeypatch.setattr(
        semgrep,
        "TemporaryDirectory",
        partial(TemporaryDirectory, dir=tmp_path),
    )

    def fake_run(command, **kwargs):
        assert 0 < kwargs["timeout"] <= 900
        if scenario == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if scenario == "os_error":
            raise OSError("injected scanner launch failure")
        payload = {"results": [], "errors": [], "paths": {"scanned": [str(source)]}}
        if scenario == "scan_errors":
            payload["errors"] = [{"message": "injected parse error"}]
        elif scenario == "invalid_results":
            payload["results"] = None
        elif scenario == "malformed_finding":
            payload["results"] = [{}]
        elif scenario == "missing_errors":
            payload.pop("errors")
        elif scenario == "empty_scan":
            payload["paths"]["scanned"] = []
        elif scenario == "skipped_rules":
            payload["skipped_rules"] = [{"rule_id": "example"}]
        text = "{broken JSON" if scenario == "broken_json" else json.dumps(payload)
        if scenario == "duplicate_results_key":
            text = text[:-1] + ', "results": []}'
        kwargs["stdout"].write(text)
        return subprocess.CompletedProcess(
            command, 2 if scenario == "nonzero_exit" else 0
        )

    runner = Mock(side_effect=fake_run)
    monkeypatch.setattr(semgrep.subprocess, "run", runner)
    run_deterministic(state, ToolRegistry(paths, None))

    summary = json.loads((paths.reports / "summary.json").read_text(encoding="utf-8"))
    assert state.finished
    assert state.exit_code != 0
    assert state.sast_status == Status.FAILED
    assert state.findings == []
    assert summary["status"] == "failed"
    assert summary["stages"]["sast"] == "failed"
    assert (paths.reports / "report.md").is_file()
    assert any(
        entry.action == Action.RUN_SAST.value and entry.status == "failed"
        for entry in state.trace
    )
    assert runner.call_count == (0 if scenario == "missing_executable" else 1)


def test_valid_empty_scanner_report_is_accepted(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text(
        '{"results": [], "errors": [], "paths": {"scanned": ["source.py"]}}',
        encoding="utf-8",
    )
    assert semgrep.parse_semgrep_json(raw) == []
