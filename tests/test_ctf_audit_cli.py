import json
from pathlib import Path

import pytest

from app import main as project_main


@pytest.mark.parametrize("default_encoding", ["utf-8", "cp1252"])
def test_project_cli_runs_audit_without_dotenv_or_model(
    tmp_path, monkeypatch, capsys, default_encoding
):
    from app import cli

    native_open = Path.open

    def open_with_default(
        path, mode="r", buffering=-1, encoding=None, errors=None, newline=None
    ):
        if "b" not in mode and encoding in (None, "locale"):
            encoding = default_encoding
        return native_open(path, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", open_with_default)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Офлайн-аудит не должен читать .env или создавать LLM-клиент")

    monkeypatch.setattr(cli, "load_dotenv", forbidden)
    monkeypatch.setattr(cli, "OpenAICompatibleClient", forbidden)
    assert project_main.run(["ctf-audit", "--reports-dir", str(tmp_path)]) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["cases"] == 28
    assert summary["status"] == "completed_with_observations"
    reports = list(tmp_path.glob("*/ctf_audit.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["source"] == "fixed_fixture"
    assert report["model_requests"] == 0


def test_cli_strict_mode_fails_on_observations_and_preserves_report(tmp_path, capsys):
    assert (
        project_main.run(
            ["ctf-audit", "--reports-dir", str(tmp_path), "--fail-on-observations"]
        )
        == 1
    )
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["unverified_artifact_admissions"] == 3
    assert len(list(tmp_path.glob("*/ctf_audit.md"))) == 1


def test_audit_help_exposes_offline_command(capsys):
    with pytest.raises(SystemExit) as exc:
        project_main.run(["ctf-audit", "--help"])
    assert exc.value.code == 0
    assert "--fail-on-observations" in capsys.readouterr().out
