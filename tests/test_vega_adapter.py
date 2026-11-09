"""Offline security and packaging contracts for the standalone VEGA export."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from urllib.request import Request

import pytest

from scripts.build_vega import REQUIRED, build
from vega.agent import (
    NoRedirect,
    OpenAIClient,
    Runtime,
    VegaError,
    plan,
    validate_action,
)


class Response(io.BytesIO):
    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def getcode(self):
        return self.status


def runtime(tmp_path: Path, **kwargs) -> Runtime:
    task = tmp_path / "task"
    materials = task / "materials"
    artifact = tmp_path / "artifact"
    materials.mkdir(parents=True)
    return Runtime(task, artifact, **kwargs)


def test_package_contains_exact_root_files_and_valid_manifest(tmp_path):
    archive_path = build(tmp_path / "security-agent-vega.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        assert isinstance(json.loads(archive.read("agent.json")), dict)
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111


def test_llm_request_contract_and_secret_safe_error(monkeypatch):
    secret = "do-not-print-this-key"
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("LOCAL_AGENT_MODEL", "local-model")
    monkeypatch.setenv("VEGA_AGENT_SESSION_ID", "session-7")
    captured = {}

    def transport(request: Request, timeout: int):
        captured.update(request=request, timeout=timeout)
        body = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": json.dumps(
                            {"action": "FINISH", "arguments": {}, "reason": "done"}
                        )
                    },
                }
            ]
        }
        return Response(json.dumps(body).encode())

    client = OpenAIClient(transport=transport)
    client.complete([{"role": "user", "content": "next"}])
    request = captured["request"]
    payload = json.loads(request.data)
    assert request.full_url == "https://gateway.example/v1/chat/completions"
    assert payload["model"] == "local-model"
    assert payload["response_format"] == {"type": "json_object"}
    assert request.get_header("Authorization") == f"Bearer {secret}"
    assert request.get_header("X-vega-agent-session") == "session-7"

    def broken(_request, timeout):
        raise OSError(secret)

    with pytest.raises(VegaError) as caught:
        OpenAIClient(transport=broken).complete([])
    assert secret not in str(caught.value)


def test_files_are_bounded_and_symlink_escape_is_rejected(tmp_path):
    engine = runtime(tmp_path)
    safe = engine.task_root / "materials" / "note.txt"
    safe.write_text("confirmed value", encoding="utf-8")
    assert engine.read_file("materials/note.txt", 0, 100) == "confirmed value"
    with pytest.raises(VegaError, match="path_outside_task|path"):
        engine.read_file("../../outside.txt", 0, 100)

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = engine.task_root / "materials" / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this platform")
    with pytest.raises(VegaError, match="path_outside_task"):
        engine.read_file("materials/escape.txt", 0, 100)


@pytest.mark.parametrize(
    "url",
    [
        "https://target:8000/foo",
        "http://example.com:8000/foo",
        "http://target:9000/foo",
        "file:///etc/passwd",
        "http://localhost:8000/foo",
    ],
)
def test_http_origin_rejects_everything_except_exact_target(url):
    with pytest.raises(VegaError, match="http_origin_not_allowed|invalid_http_path"):
        Runtime.validate_http_url(url)
    assert Runtime.validate_http_url("http://target:8000/foo?a=1") == (
        "http://target:8000/foo?a=1"
    )
    assert Runtime.validate_http_url("/../../encoded%2fpath") == (
        "http://target:8000/../../encoded%2fpath"
    )


def test_redirect_handler_never_follows_redirects():
    handler = NoRedirect()
    request = Request("http://target:8000/start")
    assert (
        handler.redirect_request(
            request, None, 302, "Found", {}, "http://localhost:8000/escape"
        )
        is None
    )


def test_action_contract_has_no_shell_and_rejects_wrong_arguments(tmp_path):
    assert "SHELL" not in {
        "LIST_FILES",
        "READ_FILE",
        "SEARCH_FILES",
        "GIT_LOG",
        "GIT_SHOW",
        "HTTP_REQUEST",
        "WRITE_FLAG",
        "FINISH",
    }
    with pytest.raises(VegaError, match="unknown_action"):
        validate_action({"action": "SHELL", "arguments": {}, "reason": "run it"})
    with pytest.raises(VegaError, match="invalid_arguments"):
        validate_action(
            {
                "action": "READ_FILE",
                "arguments": {"path": "x", "command": "whoami"},
                "reason": "read",
            }
        )
    engine = runtime(tmp_path)
    (engine.task_root / "materials" / "ok.txt").write_text("ok", encoding="utf-8")
    action = validate_action(
        {
            "action": "READ_FILE",
            "arguments": {"path": "materials/ok.txt"},
            "reason": "collect evidence",
        }
    )
    assert engine.execute(action) == "ok"


def test_malformed_planner_output_gets_one_safe_repair():
    class Client:
        def __init__(self):
            self.calls = []
            self.responses = [
                "malformed PRIVATE-PROVIDER-CONTENT",
                json.dumps(
                    {"action": "FINISH", "arguments": {}, "reason": "artifact ready"}
                ),
            ]

        def complete(self, messages):
            self.calls.append(messages)
            return self.responses.pop(0)

    client = Client()
    assert plan(client, [{"role": "user", "content": "next"}])["action"] == "FINISH"
    assert len(client.calls) == 2
    repair = client.calls[1][-1]["content"]
    assert "planner_json_invalid" in repair
    assert "PRIVATE-PROVIDER-CONTENT" not in repair


def test_write_flag_uses_only_artifact_path_and_rejects_empty(tmp_path, capsys):
    engine = runtime(tmp_path)
    with pytest.raises(VegaError, match="invalid_flag"):
        validate_action(
            {"action": "WRITE_FLAG", "arguments": {"value": ""}, "reason": "done"}
        )
    action = validate_action(
        {
            "action": "WRITE_FLAG",
            "arguments": {"value": "FLAG{confirmed}"},
            "reason": "confirmed by evidence",
        }
    )
    assert "verified" in engine.execute(action)
    assert engine.flag_path.read_bytes() == b"FLAG{confirmed}"
    assert list(engine.artifact_dir.iterdir()) == [engine.flag_path]
    assert "FLAG{confirmed}" not in capsys.readouterr().out
