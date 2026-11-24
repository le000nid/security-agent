"""CLI contract for the ``ctf`` subcommand and the profile registry."""

from __future__ import annotations

import json
import zipfile

import pytest

from app.cli import run as run_cli


def test_ctf_list_profiles_prints_functional_names(capsys):
    assert run_cli(["ctf", "--list-profiles"]) == 0
    out = capsys.readouterr().out
    for name in (
        "evidence",
        "file_inspection",
        "git_history_recovery",
        "path_filter_bypass",
        "path_assembly_bypass",
        "sqli_login_bypass",
        "sqli_admin_bypass",
        "sqli_auth_inversion",
    ):
        assert name in out


def test_ctf_list_profiles_mentions_no_external_ids(capsys):
    run_cli(["ctf", "--list-profiles"]) == 0
    out = capsys.readouterr().out.lower()
    for forbidden in ("p1z1", "p2z3", "p3z2", "p3z3", "p4z2", "p4z4", "p4z8", "vega"):
        assert forbidden not in out


def test_ctf_requires_profile_or_list(capsys):
    assert run_cli(["ctf"]) == 2
    assert "--profile" in capsys.readouterr().err


def test_ctf_unknown_profile_is_rejected(capsys):
    assert run_cli(["ctf", "--profile", "nope"]) == 2
    assert "unknown profile" in capsys.readouterr().err


def test_ctf_rejects_legacy_task_ids(capsys):
    """External task identifiers are not profile names anymore."""
    assert run_cli(["ctf", "--profile", "p3z2"]) == 2
    assert "unknown profile" in capsys.readouterr().err


def test_ctf_package_builds_four_file_zip(tmp_path, capsys):
    target = tmp_path / "agent.zip"
    assert (
        run_cli(["ctf", "--profile", "path_filter_bypass", "--package", str(target)])
        == 0
    )
    with zipfile.ZipFile(target) as archive:
        assert tuple(archive.namelist()) == (
            "run.sh",
            "agent.json",
            "agent.py",
            "strategy.md",
        )
        manifest = json.loads(archive.read("agent.json"))
    assert manifest["entrypoint"] == "run.sh"


def test_legacy_cli_spelling_is_gone(monkeypatch):
    """The pre-v5 CLI spelling must be rejected, not silently routed."""
    from app import main as project_main

    with pytest.raises(SystemExit) as excinfo:
        project_main.run(["vega-p1z1", "--package", "x.zip"])
    assert excinfo.value.code == 2
