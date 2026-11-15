"""Offline contracts and end-to-end loop for the standalone VEGA P3Z3 export.

No sockets are used: the HTTP layer is replaced by an in-memory vulnerable
file service with check-before-assembly semantics and the model is scripted,
matching the no-network rule from tests/conftest.py.
"""

from __future__ import annotations

import base64
import collections
import io
import json
import os
import time
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path

import pytest

from scripts.build_vega import REQUIRED, build, build_p3z3
from vega_p3z3 import agent as p3z3

FLAG = "VEGA_training{p3z3_offline_e2e_flag}"


@pytest.fixture()
def p3(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p3z3, "TASK_DIR", str(task))
    monkeypatch.setattr(p3z3, "MATERIALS", str(materials))
    monkeypatch.setattr(p3z3, "OUT_DIR", str(artifact))
    monkeypatch.setattr(p3z3, "TARGET", "http://target:8000")
    monkeypatch.setattr(p3z3, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p3z3, "MAX_STEPS", 12)
    monkeypatch.setattr(
        p3z3,
        "EVIDENCE",
        {"http": collections.deque(maxlen=80), "file": collections.deque(maxlen=80)},
    )
    monkeypatch.setattr(p3z3, "HTTP_CACHE", collections.OrderedDict())
    monkeypatch.setattr(p3z3, "ROUTE", "")
    monkeypatch.setattr(p3z3, "ROUTES", [])
    return p3z3


# --- in-memory vulnerable target and scripted model -------------------------


class FakeResponse(io.BytesIO):
    headers = {"Content-Type": "text/plain"}
    status = 200
    url = ""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeOpener:
    """Serves urllib requests from VulnerableFileService without sockets."""

    def __init__(self, service):
        self.service = service

    def open(self, request, timeout=10):
        status, body = self.service.handle(request.full_url)
        if status >= 400:
            raise urllib.error.HTTPError(
                request.full_url, status, "error", {}, io.BytesIO(body)
            )
        response = FakeResponse(body)
        response.status = status
        response.url = request.full_url
        return response


class VulnerableFileService:
    """Check-before-assembly file service.

    The filter inspects ONLY the first value of the canonical ``file`` param
    before the final path is assembled. The server then assembles the real
    path from the last ``file`` value (HPP), the ``path`` param (multi-param),
    decodes a second time (double-decode) and appends ``.txt`` to extensionless
    basenames (suffix-concat).
    """

    def __init__(self, files, homepage, double_decode):
        self.files = files
        self.homepage = homepage
        self.double_decode = double_decode

    def handle(self, url):
        parts = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        if parts.path == "/":
            return 200, self.homepage
        if parts.path == "/download" and "file" in params:
            checked = params["file"][0]  # filter sees the FIRST value only
            lowered = checked.lower()
            if "../" in checked or any(
                word in lowered for word in ("secret", "flag", "proc")
            ):
                return 403, b"filtered"
            if "path" in params:  # multi-param: server trusts the alt param
                name = params["path"][0]
            else:  # HPP: server reads the LAST value
                name = params["file"][-1]
            if self.double_decode and "%" in name:
                name = urllib.parse.unquote(name)  # the second decode
            virtual = urllib.parse.urljoin("http://x/srv/public/", name)
            virtual = virtual[len("http://x") :]
            if "." not in name.rsplit("/", 1)[-1]:
                virtual += ".txt"  # suffix-concat at assembly time
            if virtual in self.files:
                return 200, self.files[virtual]
            return 404, b"Not Found"
        return 404, b"Not Found"


class ScriptedModel:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, messages):
        # snapshot: main() keeps mutating the same list after the model returns
        self.calls.append([dict(m) for m in messages])
        if not self.replies:
            raise AssertionError("scripted model ran out of replies")
        return self.replies.pop(0)


HOMEPAGE = (
    "<html><body>File service: "
    "<a href='/download?file=notes.txt'>notes.txt</a></body></html>"
).encode()


def make_service(scenario):
    if scenario == "dd-wins":
        # secret one level above public/: only the double-decode bypass reaches it
        return VulnerableFileService(
            files={
                "/srv/public/notes.txt": b"public notes for reconnaissance",
                "/srv/treasure.txt": FLAG.encode(),
                "/etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
            },
            homepage=HOMEPAGE,
            double_decode=True,
        )
    # hpp-wins: secret under secret/: only HPP/multi-param with traversal reach it
    return VulnerableFileService(
        files={
            "/srv/public/notes.txt": b"public notes for reconnaissance",
            "/srv/secret/treasure.txt": FLAG.encode(),
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
        },
        homepage=HOMEPAGE,
        double_decode=False,
    )


SCENARIOS = [
    ("dd-wins", ["treasure.txt"], "DOUBLE-DECODE BYPASS CONFIRMED"),
    (
        "hpp-wins",
        ["secret/treasure.txt"],
        "check-before-assembly BYPASS CONFIRMED via HPP/multi-param",
    ),
]


# --- packaging ---------------------------------------------------------------


def test_p3z3_package_contains_exact_root_files_and_executable_run_sh(tmp_path):
    archive_path = build_p3z3(tmp_path / "security-agent-p3z3.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111
        assert "http_traverse" in archive.read("agent.py").decode()
        assert "double_decode_hits" in archive.read("agent.py").decode()


def test_profiles_stay_distinct(tmp_path):
    with (
        zipfile.ZipFile(build(tmp_path / "vega.zip")) as vega,
        zipfile.ZipFile(build_p3z3(tmp_path / "p3z3.zip")) as p3z3_archive,
    ):
        vega_manifest = json.loads(vega.read("agent.json"))
        p3z3_manifest = json.loads(p3z3_archive.read("agent.json"))
        assert vega_manifest != p3z3_manifest
        assert "http_traverse" not in vega.read("agent.py").decode()
        assert "hpp_jobs" in p3z3_archive.read("agent.py").decode()


# --- path guard --------------------------------------------------------------


def test_safe_material_path_rejects_escape_sibling_and_symlink(p3, tmp_path):
    base = Path(p3.MATERIALS)
    (base / "ok.txt").write_text("ok", encoding="utf-8")
    evil = tmp_path / "materials_evil"
    evil.mkdir()
    (evil / "secret.txt").write_text("nope", encoding="utf-8")
    assert p3.safe_material_path("ok.txt") == str((base / "ok.txt").resolve())
    with pytest.raises(ValueError, match="outside materials"):
        p3.safe_material_path("../outside.txt")
    with pytest.raises(ValueError, match="outside materials"):
        p3.safe_material_path("sub/../../outside.txt")
    # regression guard for the sibling-directory escape fixed during integration
    with pytest.raises(ValueError, match="outside materials"):
        p3.safe_material_path("../materials_evil/secret.txt")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = base / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this platform")
    with pytest.raises(ValueError, match="outside materials"):
        p3.safe_material_path("escape.txt")


# --- request and response contracts -----------------------------------------


def test_valid_http_path_contract(p3):
    assert p3.valid_http_path("/a b") == "/a%20b"
    assert p3.valid_http_path("/a#frag") == "/a"
    assert p3.valid_http_path("?q=1") == "?q=1"
    with pytest.raises(ValueError):
        p3.valid_http_path("relative/path")
    with pytest.raises(ValueError):
        p3.valid_http_path("/bad\x01char")
    with pytest.raises(ValueError):
        p3.valid_http_path("/" + "x" * 1400)


def test_unwrap_body_prefers_content_key_and_decodes_pre(p3):
    assert p3.unwrap_body('{"file":"vault_key.dat","content":"VEGA{x}"}') == "VEGA{x}"
    assert p3.unwrap_body('{"anything":"only string"}') == "only string"
    assert p3.unwrap_body("<pre>VEGA{a&lt;b}</pre>") == "VEGA{a<b}"
    assert p3.unwrap_body("plain page") == ""


def test_flag_rx_accepts_only_flag_shaped_values(p3):
    assert p3.FLAG_RX.findall("VEGA_training{a-b_c}") == ["VEGA_training{a-b_c}"]
    assert p3.FLAG_RX.findall("flag{one} and ctf{two}") == ["flag{one}", "ctf{two}"]
    assert p3.FLAG_RX.findall("password123") == []


def test_action_from_text_normalizes_every_planner_shape(p3):
    assert p3.action_from_text('{"tool":"http","path":"/"}') == {
        "tool": "http",
        "path": "/",
    }
    assert p3.action_from_text('```json\n{"tool":"inventory"}\n```') == {
        "tool": "inventory"
    }
    assert p3.action_from_text('<think>plan</think>{"tool":"decode"}') == {
        "tool": "decode"
    }
    # the last complete JSON object in prose wins
    assert p3.action_from_text('first {"tool":"http"} then {"tool":"finish"}') == {
        "tool": "finish"
    }
    assert p3.action_from_text('{"action":"inventory","arguments":{"x":1}}') == {
        "action": "inventory",
        "x": 1,
        "tool": "inventory",
    }
    assert p3.action_from_text("Сдаю VEGA_training{p3z3_x}") == {
        "tool": "finish",
        "flag": "VEGA_training{p3z3_x}",
    }
    assert p3.action_from_text("no json here")["tool"] == "invalid"


def test_guarded_redirect_blocks_offsite_and_keeps_target(p3):
    request = urllib.request.Request("http://target:8000/start")
    with pytest.raises(urllib.error.HTTPError):
        p3.GuardedRedirect().redirect_request(
            request, None, 302, "Found", {}, "http://evil.example/escape"
        )
    assert (
        p3.GuardedRedirect().redirect_request(
            request, None, 302, "Found", {}, "http://target:8000/next"
        )
        is not None
    )


def test_model_missing_configuration_raises_safe_error(p3, monkeypatch):
    for name in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "LOCAL_AGENT_MODEL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="not configured.*OPENAI_BASE_URL"):
        p3.model([{"role": "user", "content": "hi"}])


def test_http_get_stores_evidence_and_cache(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service("hpp-wins")))
    result = p3.http_get("/download?file=notes.txt")
    assert result["status"] == 200
    assert result["flag_shaped_values"] == []
    assert list(p3.EVIDENCE["http"]) == ["public notes for reconnaissance"]
    assert "/download?file=notes.txt" in p3.HTTP_CACHE
    # HPP: filter sees the safe first value, the server reads the last one
    secret = p3.http_get("/download?file=notes.txt&file=../secret/treasure.txt")
    assert secret["status"] == 200
    assert secret["flag_shaped_values"] == [FLAG]
    assert p3.verified_flag(FLAG)
    assert not p3.verified_flag("VEGA{never_seen}")


def test_http_get_blocks_gross_names_before_assembly(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service("hpp-wins")))
    blocked = p3.http_get("/download?file=../secret/treasure.txt")
    assert blocked["status"] == 403
    assert blocked["preview"] == "filtered"


def test_http_batch_filters_invalid_paths_and_summarizes(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service("hpp-wins")))
    result = p3.http_batch(
        {
            "paths": [
                "junk-without-slash",
                "/download?file=notes.txt",
                "/download?file=missing.txt",
            ]
        }
    )
    assert result["checked"] == 2
    assert result["status_counts"] == {"200": 1, "404": 1}
    assert len(result["non_404"]) == 1
    assert result["non_404"][0]["path"] == "/download?file=notes.txt"


def test_decode_value_supports_all_encodings(p3):
    encoded = base64.b64encode("VEGA{b64}".encode()).decode()
    assert p3.decode_value({"value": encoded})["decoded"] == "VEGA{b64}"
    assert (
        p3.decode_value({"value": "%2e%2e%2f", "encoding": "url"})["decoded"] == "../"
    )
    assert p3.decode_value({"value": "4142", "encoding": "hex"})["decoded"] == "AB"
    assert (
        p3.decode_value({"value": "x", "encoding": "rot13"}) == "Unsupported encoding"
    )


# --- end-to-end agent loop ----------------------------------------------------


@pytest.mark.parametrize(("scenario", "names", "expected_hint"), SCENARIOS)
def test_e2e_check_before_assembly_bypass(
    p3, monkeypatch, capsys, scenario, names, expected_hint
):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service(scenario)))
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "http_discover"}),
            json.dumps({"tool": "http_traverse", "names": names, "max_depth": 2}),
            json.dumps({"tool": "finish", "flag": FLAG}),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(p3, "model", scripted)

    assert p3.main() == 0

    assert len(scripted.calls) == 3
    discover_feedback = scripted.calls[1][-1]["content"]
    assert '"route": "/download?file="' in discover_feedback
    traverse_feedback = scripted.calls[2][-1]["content"]
    assert expected_hint in traverse_feedback
    assert FLAG in traverse_feedback
    assert os.listdir(p3.OUT_DIR) == ["flag.txt"]
    with open(p3.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG
    # stderr must stay free of flag content and transcript bodies
    assert FLAG not in capsys.readouterr().err


def test_e2e_rejects_fabricated_flag_then_accepts_live_value(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service("hpp-wins")))
    fabricated = "VEGA{made_up_without_evidence}"
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "finish", "flag": fabricated}),
            json.dumps(
                {
                    "tool": "http_traverse",
                    "names": ["secret/treasure.txt"],
                    "max_depth": 2,
                }
            ),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(p3, "model", scripted)

    assert p3.main() == 0

    rejection = scripted.calls[1][-1]["content"]
    assert "НЕ найден" in rejection
    with open(p3.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG


def test_e2e_last_flag_fallback_writes_last_attempt(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(make_service("hpp-wins")))
    fabricated = "VEGA{pure_fabrication}"
    monkeypatch.setattr(p3, "MAX_STEPS", 3)
    scripted = ScriptedModel(
        [json.dumps({"tool": "finish", "flag": fabricated}) for _ in range(3)]
    )
    monkeypatch.setattr(p3, "model", scripted)

    # documented P3Z3 fallback: the last well-formed finish attempt is written
    # even when never verified, so the platform checker always gets a candidate
    assert p3.main() == 0

    with open(p3.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == fabricated
