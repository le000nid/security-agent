import json

import pytest

from app import main as project_main


def test_project_cli_runs_audit_without_dotenv_or_model(tmp_path, monkeypatch, capsys):
    from app import cli

    def forbidden(*_args, **_kwargs):
        pytest.fail("Офлайн-аудит не должен читать .env или создавать LLM-клиент")

    monkeypatch.setattr(cli, "load_dotenv", forbidden)
    monkeypatch.setattr(cli, "OpenAICompatibleClient", forbidden)
    assert project_main.run(["ctf-audit", "--reports-dir", str(tmp_path)]) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["cases"] == 18
    assert summary["status"] == "completed_with_observations"
    reports = list(tmp_path.glob("*/ctf_audit.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
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
    assert summary["unverified_artifact_admissions"] == 6
    assert len(list(tmp_path.glob("*/ctf_audit.md"))) == 1


def test_audit_help_exposes_offline_command(capsys):
    with pytest.raises(SystemExit) as exc:
        project_main.run(["ctf-audit", "--help"])
    assert exc.value.code == 0
    assert "--fail-on-observations" in capsys.readouterr().out
