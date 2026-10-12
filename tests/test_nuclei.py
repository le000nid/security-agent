from pathlib import Path
from unittest.mock import Mock

import pytest

from app.nuclei import TEMPLATE_DIRECTORY, NucleiError, run_nuclei


def test_run_nuclei_uses_argument_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("app.nuclei.shutil.which", lambda _: "/usr/bin/nuclei")
    completed = Mock(returncode=0, stdout="", stderr="")
    runner = Mock(return_value=completed)
    monkeypatch.setattr("app.nuclei.subprocess.run", runner)
    output = tmp_path / "logs" / "raw.jsonl"

    run_nuclei("http://localhost:3000", output)

    command = runner.call_args.args[0]
    assert command[:3] == ["/usr/bin/nuclei", "-u", "http://localhost:3000"]
    assert command[command.index("-o") + 1] == str(output)
    assert runner.call_args.kwargs["check"] is False
    assert output.exists()
    assert command[command.index("-type") + 1] == "http"
    assert "-t" in command and "-disable-redirects" in command
    assert Path(command[command.index("-t") + 1]).resolve() == TEMPLATE_DIRECTORY
    assert TEMPLATE_DIRECTORY.name == "nuclei"
    assert "-no-interactsh" in command and "-disable-update-check" in command
    assert "LLM_API_KEY" not in runner.call_args.kwargs["env"]


def test_run_nuclei_fails_when_binary_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("app.nuclei.shutil.which", lambda _: None)

    with pytest.raises(NucleiError, match="not found"):
        run_nuclei("http://localhost:3000", tmp_path / "raw.jsonl")


def test_all_curated_templates_are_local_http_gets() -> None:
    templates = sorted(TEMPLATE_DIRECTORY.glob("*.yaml"))
    assert 5 <= len(templates) <= 10
    for template in templates:
        text = template.read_text(encoding="utf-8")
        assert "http:" in text
        assert "method: GET" in text
        assert "{{BaseURL}}" in text
        assert "redirects: false" in text
        assert not any(
            forbidden in text
            for forbidden in ("interactsh", "headless:", "dns:", "tcp:", "payloads:")
        )
