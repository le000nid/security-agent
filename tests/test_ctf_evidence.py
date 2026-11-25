"""Offline security and packaging contracts for the bounded evidence agent."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from urllib.request import Request

import pytest

from app.agent.ctf.evidence import (
    CtfError,
    NoRedirect,
    OpenAIClient,
    Runtime,
    plan,
    validate_action,
)
from app.agent.ctf.package import build_archive


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
    archive_path = build_archive("evidence", tmp_path / "security-agent-evidence.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == (
            "run.sh",
            "agent.json",
            "agent.py",
            "strategy.md",
        )
        assert all("/" not in name for name in archive.namelist())
        assert isinstance(json.loads(archive.read("agent.json")), dict)
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111


def test_llm_request_contract_and_secret_safe_error(monkeypatch):
    secret = "do-not-print-this-key"
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("LOCAL_AGENT_MODEL", "local-model")
    monkeypatch.setenv("CTF_AGENT_SESSION_ID", "session-7")
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
    assert request.get_header("X-agent-session") == "session-7"

    def broken(_request, timeout):
        raise OSError(secret)

    client._transport = broken
    with pytest.raises(CtfError) as excinfo:
        client.complete([{"role": "user", "content": "next"}])
    assert secret not in str(excinfo.value)


def test_files_are_bounded_and_symlink_escape_is_rejected(tmp_path):
    rt = runtime(tmp_path)
    (rt.materials_root / "note.txt").write_text("confirmed value")
    assert rt.read_file("materials/note.txt", 0, 100) == "confirmed value"
    (rt.materials_root / "big.txt").write_text("x" * 10_000_001)
    with pytest.raises(CtfError, match="file_too_large"):
        rt.read_file("materials/big.txt", 0, 8000)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = rt.materials_root / "escape.txt"
    link.symlink_to(outside)
    with pytest.raises(CtfError, match="path_outside_task"):
        rt.read_file("materials/escape.txt", 0, 100)


@pytest.mark.parametrize(
    "url",
    [
        "https://target:8000/",
        "http://target:8001/",
        "http://user:pass@target:8000/",
        "http://other:8000/",
    ],
)
def test_http_origin_rejects_everything_except_exact_target(url):
    with pytest.raises(CtfError):
        Runtime.validate_http_url(url)


def test_redirect_handler_never_follows_redirects():
    assert NoRedirect().redirect_request(None, None, 302, "x", {}, "http://x") is None


def test_action_contract_has_no_shell_and_rejects_wrong_arguments(tmp_path):
    rt = runtime(tmp_path)
    (rt.materials_root / "note.txt").write_text("confirmed value")
    good = validate_action(
        {
            "action": "READ_FILE",
            "arguments": {"path": "materials/note.txt", "offset": 0, "max_chars": 8000},
            "reason": "inspect the file",
        }
    )
    assert rt.execute(good) == "confirmed value"
    with pytest.raises(CtfError):
        validate_action(
            {
                "action": "RUN_SHELL",
                "arguments": {"command": "ls"},
                "reason": "no shell exists",
            }
        )
    with pytest.raises(CtfError):
        validate_action(
            {
                "action": "READ_FILE",
                "arguments": {"path": "materials/file", "extra": 1},
                "reason": "unknown fields rejected",
            }
        )


def test_malformed_planner_output_gets_one_safe_repair():
    class OnceBroken:
        def __init__(self):
            self.calls = 0

        def __call__(self, request, timeout=45):
            self.calls += 1
            if self.calls == 1:
                content = "not json at all"
            else:
                content = json.dumps(
                    {"action": "FINISH", "arguments": {}, "reason": "done"}
                )
            packet = {
                "choices": [{"finish_reason": "stop", "message": {"content": content}}]
            }
            return Response(json.dumps(packet).encode())

    class FakeClient(OpenAIClient):
        def __init__(self, transport):
            self._transport = transport
            self.model = "m"
            self.url = "http://x"
            self._key = "k"
            self._session = "s"

    client = FakeClient(OnceBroken())
    action = plan(client, [{"role": "user", "content": "go"}])
    assert action["action"] == "FINISH"


def test_write_flag_uses_only_artifact_path_and_rejects_empty(tmp_path):
    rt = runtime(tmp_path)
    assert "verified" in rt.write_flag("FLAG_test{ok}")
    assert rt.flag_path.read_text(encoding="utf-8") == "FLAG_test{ok}"
    with pytest.raises(CtfError):
        rt.write_flag("   ")
