"""P1Z1 protocol, source grounding, failures and standalone ZIP contract."""

import ast
import io
import json
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from app import main as project
from app.vega_p1z1 import agent
from app.vega_p1z1.package import FILES, build_archive


@pytest.fixture
def sources():
    return [
        agent.Source("f001", "random-name.data", "Заметка: точный ключ — Ёж-123:a+B="),
        agent.Source("f002", "recipe.txt", "shopping list and ordinary notes"),
    ]


def test_selection_preserves_exact_unicode_and_punctuation(sources):
    response = json.dumps({"file_id": "f001", "value": "Ёж-123:a+B="})
    assert agent.select_value(response, sources) == "Ёж-123:a+B="
    assert (
        agent.select_value("```json\n" + response + "\n```", sources) == "Ёж-123:a+B="
    )


@pytest.mark.parametrize(
    "response",
    [
        "",
        "plain text",
        "[]",
        '{"file_id":"f001","value":"invented"}',
        '{"file_id":"../../outside","value":"Ёж-123:a+B="}',
        '{"file_id":"f002","value":"Ёж-123:a+B="}',
        '{"file_id":"f001","value":""}',
        '{"file_id":"f001","value":null}',
        '{"file_id":"f001","value":" \\n "}',
        '{"file_id":"f001","value":"Ёж-123:a+B=","shell":"echo"}',
        '{"file_id":"f001","file_id":"f002","value":"notes"}',
        'Commentary: {"file_id":"f001","value":"Ёж-123:a+B="}',
        '```json\n{"file_id":"f001","value":"Ёж-123:a+B="}',
    ],
)
def test_invalid_or_ungrounded_selection_is_rejected(sources, response):
    with pytest.raises(agent.AgentError):
        agent.select_value(response, sources)


def test_materials_walk_has_no_filename_or_flag_prefix_assumption(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/случайное.data").write_bytes(
        "Секрет: ТочныйКлюч123".encode("cp1251")
    )
    (tmp_path / "note").write_bytes(b"\xef\xbb\xbfjust a household note")
    (tmp_path / "binary").write_bytes(b"a\x00b")
    (tmp_path / "empty").touch()
    result = agent.read_materials(tmp_path, time.monotonic() + 5)
    assert {item.path for item in result} == {"note", "nested/случайное.data"}
    assert any("ТочныйКлюч123" in item.text for item in result)


def test_symlinks_cannot_import_outside_materials(tmp_path):
    materials = tmp_path / "materials"
    materials.mkdir()
    (materials / "note.txt").write_text("ordinary note")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not reach the model")
    try:
        (materials / "link").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    result = agent.read_materials(materials, time.monotonic() + 5)
    assert [item.path for item in result] == ["note.txt"]


def test_oversized_input_fails_instead_of_silently_truncating(tmp_path):
    (tmp_path / "oversize").write_bytes(b"a" * (agent.MAX_FILE_BYTES + 1))
    with pytest.raises(agent.AgentError, match="too_large"):
        agent.read_materials(tmp_path, time.monotonic() + 5)


def test_expired_deadline_never_calls_gateway(monkeypatch, sources):
    ask = Mock()
    monkeypatch.setattr(agent, "ask_model", ask)
    with pytest.raises(agent.AgentError, match="time_limit"):
        agent.solve(sources, {}, time.monotonic() - 1)
    ask.assert_not_called()


def test_retry_requires_successful_grounded_model_response(monkeypatch, sources):
    ask = Mock(
        side_effect=[
            agent.AgentError("gateway_request_failed"),
            '{"file_id":"f001","value":"hallucinated"}',
            '{"file_id":"f001","value":"Ёж-123:a+B="}',
        ]
    )
    monkeypatch.setattr(agent, "ask_model", ask)
    assert agent.solve(sources, {}, time.monotonic() + 5) == "Ёж-123:a+B="
    assert ask.call_count == 3
    context = json.loads(ask.call_args_list[0].args[0][1]["content"])
    assert len(context["files"]) == 2
    assert "untrusted data" in ask.call_args_list[0].args[0][0]["content"]


def test_gateway_protocol_uses_runtime_settings_and_session_header(monkeypatch):
    env = {
        "OPENAI_BASE_URL": "http://gateway.invalid/v1/",
        "OPENAI_API_KEY": "private-runtime-credential",
        "LOCAL_AGENT_MODEL": "runtime-model",
        "VEGA_AGENT_SESSION_ID": "runtime-session",
    }
    response = io.BytesIO(
        json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
    )
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(agent.urllib.request, "build_opener", Mock(return_value=opener))
    assert (
        agent.ask_model([{"role": "user", "content": "assigned data"}], env, 3) == "{}"
    )
    request = opener.open.call_args.args[0]
    assert request.full_url == "http://gateway.invalid/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer private-runtime-credential"
    assert request.get_header("X-vega-agent-session") == "runtime-session"
    assert json.loads(request.data)["model"] == "runtime-model"
    assert b"private-runtime-credential" not in request.data
    assert opener.open.call_args.kwargs["timeout"] == 3
    assert (
        agent.NoRedirect().redirect_request(None, None, 302, "", {}, "http://elsewhere")
        is None
    )


@pytest.mark.parametrize("content", [None, "", "  "])
def test_empty_gateway_content_is_not_a_success(monkeypatch, content):
    env = dict.fromkeys(
        ["OPENAI_API_KEY", "LOCAL_AGENT_MODEL", "VEGA_AGENT_SESSION_ID"], "runtime"
    )
    env["OPENAI_BASE_URL"] = "http://gateway.invalid"
    response = io.BytesIO(
        json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    )
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(agent.urllib.request, "build_opener", Mock(return_value=opener))
    with pytest.raises(agent.AgentError, match="empty_model_response"):
        agent.ask_model([], env, 1)


@pytest.mark.parametrize(
    "base",
    [
        "file:///etc/passwd",
        "https://user:pass@example.test",
        "https://example.test?q=key",
    ],
)
def test_invalid_gateway_addresses_never_send_credentials(monkeypatch, base):
    opener = Mock()
    monkeypatch.setattr(agent.urllib.request, "build_opener", opener)
    with pytest.raises(agent.AgentError, match="invalid_gateway_url"):
        agent.ask_model([], {"OPENAI_BASE_URL": base}, 1)
    opener.assert_not_called()


def test_artifact_path_inside_input_does_not_delete_input(monkeypatch, tmp_path):
    materials = tmp_path / "materials"
    materials.mkdir()
    original = materials / "flag.txt"
    original.write_text("assigned input, not a previous output")
    monkeypatch.setenv("VEGA_TASK_DIR", str(tmp_path))
    monkeypatch.setenv("VEGA_CTF_ARTIFACT_DIR", str(materials))
    assert agent.main() == 1
    assert original.read_text() == "assigned input, not a previous output"


def test_failure_removes_stale_flag_without_logging_secret(
    monkeypatch, tmp_path, capsys
):
    materials, artifact = tmp_path / "task/materials", tmp_path / "output"
    materials.mkdir(parents=True)
    artifact.mkdir()
    (materials / "file.txt").write_text("actual data")
    (artifact / "flag.txt").write_text("stale flag")
    monkeypatch.setenv("VEGA_TASK_DIR", str(materials.parent))
    monkeypatch.setenv("VEGA_CTF_ARTIFACT_DIR", str(artifact))
    monkeypatch.setenv("OPENAI_API_KEY", "private-runtime-credential")
    ask = Mock(side_effect=agent.AgentError("gateway_request_failed"))
    monkeypatch.setattr(agent, "ask_model", ask)
    assert agent.main() == 1
    assert ask.call_count == 3
    assert not (artifact / "flag.txt").exists()
    assert "private-runtime-credential" not in capsys.readouterr().err


def test_success_writes_no_added_whitespace(monkeypatch, tmp_path):
    materials, artifact = tmp_path / "task/materials", tmp_path / "output"
    materials.mkdir(parents=True)
    value = "точный: A+b/="
    (materials / "unknown-name.txt").write_text("ключ = " + value, encoding="utf-8")
    monkeypatch.setenv("VEGA_TASK_DIR", str(materials.parent))
    monkeypatch.setenv("VEGA_CTF_ARTIFACT_DIR", str(artifact))
    ask = Mock(return_value=json.dumps({"file_id": "f001", "value": value}))
    monkeypatch.setattr(agent, "ask_model", ask)
    assert agent.main() == 0
    assert ask.call_count == 1
    assert (artifact / "flag.txt").read_bytes() == value.encode("utf-8")
    assert not list(artifact.glob(".flag-*"))


def test_archive_has_exactly_four_root_files_and_only_standard_library(tmp_path):
    destination = build_archive(tmp_path / "submission.zip")
    with zipfile.ZipFile(destination) as archive:
        assert tuple(archive.namelist()) == FILES
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o777 == 0o755
        assert b"\r" not in archive.read("run.sh")
        code = archive.read("agent.py").decode()
        tree = ast.parse(code)
        imported = {
            item.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for item in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert imported <= sys.stdlib_module_names
    other = build_archive(tmp_path / "repeated.zip")
    assert destination.read_bytes() == other.read_bytes()


def test_project_cli_packages_the_same_standalone_agent(tmp_path):
    destination = tmp_path / "cli.zip"
    assert project.run(["vega-p1z1", "--package", str(destination)]) == 0
    with zipfile.ZipFile(destination) as archive:
        source = Path(agent.__file__).read_bytes()
        assert archive.read("agent.py") == source


def test_vega_command_does_not_load_project_dotenv(monkeypatch, tmp_path):
    from app import cli

    dotenv = Mock(side_effect=AssertionError("P1Z1 must use runtime environment only"))
    monkeypatch.setattr(cli, "load_dotenv", dotenv)
    assert project.run(["vega-p1z1", "--package", str(tmp_path / "agent.zip")]) == 0
    dotenv.assert_not_called()
