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


def test_curated_templates_use_reviewed_http_requests() -> None:
    import yaml

    post_templates = {
        "nosqli-mongo-scalar-operator": "operator",
        "nosqli-mongo-whole-filter": "filter",
        "nosqli-mongo-scope-overwrite": "scope",
    }
    templates = sorted(TEMPLATE_DIRECTORY.glob("*.yaml"))
    assert len(templates) >= 5
    ids = []
    for template in templates:
        text = template.read_text(encoding="utf-8")
        config = yaml.safe_load(text)
        ids.append(config["id"])
        assert set(config) <= {"id", "info", "variables", "http"}
        for request in config["http"]:
            assert request["redirects"] is False
            if config["id"] in post_templates:
                route = post_templates[config["id"]]
                assert config["variables"] == {"route_prefix": "vulnerable"}
                assert request["req-condition"] is True
                assert len(request["raw"]) == 3
                for raw in request["raw"]:
                    assert raw.startswith(
                        f"POST /{{{{route_prefix}}}}/{route} HTTP/1.1\n"
                    )
                    assert "Host: {{Hostname}}\n" in raw
                    assert "Content-Type: application/json\n" in raw
                assert "raw" in request and "path" not in request
            else:
                assert request["method"] == "GET"
                assert "{{BaseURL}}" in text
        assert not any(
            forbidden in text
            for forbidden in ("interactsh", "headless:", "dns:", "tcp:", "payloads:")
        )
    assert len(ids) == len(set(ids))
    assert set(post_templates) <= set(ids)
