"""Offline contracts and end-to-end loop for the standalone VEGA P3Z2 export.

No sockets are used: the HTTP layer is replaced by an in-memory vulnerable
file service and the model is scripted, matching the no-network rule from
tests/conftest.py.
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

from scripts.build_vega import REQUIRED, build, build_p3z2
from vega_p3z2 import agent as p3z2

FLAG = "VEGA_training{p3z2_offline_e2e_flag}"


@pytest.fixture()
def p3(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p3z2, "TASK_DIR", str(task))
    monkeypatch.setattr(p3z2, "MATERIALS", str(materials))
    monkeypatch.setattr(p3z2, "OUT_DIR", str(artifact))
    monkeypatch.setattr(p3z2, "TARGET", "http://target:8000")
    monkeypatch.setattr(p3z2, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p3z2, "MAX_STEPS", 12)
    monkeypatch.setattr(
        p3z2,
        "EVIDENCE",
        {"http": collections.deque(maxlen=80), "file": collections.deque(maxlen=80)},
    )
    monkeypatch.setattr(p3z2, "HTTP_CACHE", collections.OrderedDict())
    monkeypatch.setattr(p3z2, "ROUTE", "")
    monkeypatch.setattr(p3z2, "ROUTES", [])
    return p3z2


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
    """Naive file service: url-decodes once, blacklists words, strips '../'."""

    def __init__(self, files, homepage, block_proc=True):
        self.files = files
        self.homepage = homepage
        # block_proc=False emulates a filter that lets /proc/self/environ
        # probes through (Phase A2 coverage)
        self.block_proc = block_proc

    def handle(self, url):
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parts.query)
        if parts.path == "/":
            return 200, self.homepage
        if parts.path == "/download" and "file" in query:
            name = query["file"][0]
            lowered = name.lower()
            blocked = (
                ("secret", "flag", "proc") if self.block_proc else ("secret", "flag")
            )
            if any(word in lowered for word in blocked):
                return 403, b"filtered"
            cleaned = name.replace("../", "")  # one naive sanitizing pass
            virtual = urllib.parse.urljoin("http://x/srv/public/", cleaned)
            virtual = virtual[len("http://x") :]
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


def install_target(p3, monkeypatch):
    service = VulnerableFileService(
        files={
            "/srv/public/notes.txt": b"public notes for reconnaissance",
            "/srv/public/treasure.txt": FLAG.encode(),
            "/srv/etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
        },
        homepage=(
            "<html><body>File service: "
            "<a href='/download?file=notes.txt'>notes.txt</a></body></html>"
        ).encode(),
    )
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(service))
    return service


# --- packaging ---------------------------------------------------------------


def test_p3z2_package_contains_exact_root_files_and_executable_run_sh(tmp_path):
    archive_path = build_p3z2(tmp_path / "security-agent-p3z2.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111
        assert "http_traverse" in archive.read("agent.py").decode()


def test_build_keeps_profiles_distinct(tmp_path):
    with (
        zipfile.ZipFile(build(tmp_path / "vega.zip")) as vega,
        zipfile.ZipFile(build_p3z2(tmp_path / "p3z2.zip")) as p3z2_archive,
    ):
        vega_manifest = json.loads(vega.read("agent.json"))
        p3z2_manifest = json.loads(p3z2_archive.read("agent.json"))
        assert vega_manifest != p3z2_manifest
        assert vega_manifest["entrypoint"] == "run.sh"
        assert "http_traverse" not in vega.read("agent.py").decode()
        assert "http_traverse" in p3z2_archive.read("agent.py").decode()


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
    assert p3.action_from_text("Сдаю VEGA_training{p3z2_x}") == {
        "tool": "finish",
        "flag": "VEGA_training{p3z2_x}",
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
    install_target(p3, monkeypatch)
    result = p3.http_get("/download?file=notes.txt")
    assert result["status"] == 200
    assert result["flag_shaped_values"] == []
    assert list(p3.EVIDENCE["http"]) == ["public notes for reconnaissance"]
    assert "/download?file=notes.txt" in p3.HTTP_CACHE
    secret = p3.http_get("/download?file=treasure.txt")
    assert secret["flag_shaped_values"] == [FLAG]
    assert p3.verified_flag(FLAG)
    assert not p3.verified_flag("VEGA{never_seen}")


def test_http_batch_filters_invalid_paths_and_summarizes(p3, monkeypatch):
    install_target(p3, monkeypatch)
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


def test_e2e_discover_traverse_finish_writes_verified_flag(p3, monkeypatch, capsys):
    install_target(p3, monkeypatch)
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "http_discover"}),
            json.dumps(
                {"tool": "http_traverse", "names": ["treasure.txt"], "max_depth": 2}
            ),
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
    assert FLAG in traverse_feedback
    assert os.listdir(p3.OUT_DIR) == ["flag.txt"]
    with open(p3.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG
    # stderr must stay free of flag content and transcript bodies
    assert FLAG not in capsys.readouterr().err


def test_e2e_rejects_fabricated_flag_then_accepts_live_value(p3, monkeypatch):
    install_target(p3, monkeypatch)
    fabricated = "VEGA{made_up_without_evidence}"
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "finish", "flag": fabricated}),
            json.dumps(
                {"tool": "http_traverse", "names": ["treasure.txt"], "max_depth": 2}
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
    install_target(p3, monkeypatch)
    fabricated = "VEGA{pure_fabrication}"
    monkeypatch.setattr(p3, "MAX_STEPS", 3)
    scripted = ScriptedModel(
        [json.dumps({"tool": "finish", "flag": fabricated}) for _ in range(3)]
    )
    monkeypatch.setattr(p3, "model", scripted)

    # documented P3Z2 fallback: the last well-formed finish attempt is written
    # even when never verified, so the platform checker always gets a candidate
    assert p3.main() == 0

    with open(p3.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == fabricated


# --- v2 engine extensions: deeper vectors, recon and hidden secrets ----------


class StaticPageService:
    """Route table keyed by 'path?query'; for response-parsing contracts."""

    def __init__(self, routes, homepage=b"<html><body>index</body></html>"):
        self.routes = routes
        self.homepage = homepage

    def handle(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/":
            return 200, self.homepage
        key = parts.path + ("?" + parts.query if parts.query else "")
        if key in self.routes:
            return 200, self.routes[key]
        return 404, b"Not Found"


class RawFilterService:
    """Filter inspects the RAW url-encoded value; the server decodes once."""

    def __init__(self, files, homepage):
        self.files = files
        self.homepage = homepage

    def handle(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/":
            return 200, self.homepage
        if parts.path != "/download":
            return 404, b"Not Found"
        raw = dict(kv.split("=", 1) for kv in parts.query.split("&") if "=" in kv)
        if "file" not in raw:
            return 404, b"Not Found"
        checked = raw["file"].lower()
        if "../" in checked or any(
            word in checked for word in ("secret", "flag", "proc")
        ):
            return 403, b"filtered"
        name = urllib.parse.unquote(raw["file"])  # the server decodes once
        virtual = urllib.parse.urljoin("http://x/srv/public/", name)
        virtual = virtual[len("http://x") :]
        if virtual in self.files:
            return 200, self.files[virtual]
        return 404, b"Not Found"


class RoutedService:
    """Query route referenced by homepage href plus plain path-segment files."""

    def __init__(self):
        self.body = b"public notes for reconnaissance"
        self.homepage = (
            "<html><body>Docs: <a href='/getfile?doc=notes.txt'>notes</a></body></html>"
        ).encode()

    def handle(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/":
            return 200, self.homepage
        if parts.path == "/getfile" and "doc" in urllib.parse.parse_qs(parts.query):
            return 200, self.body
        if parts.path == "/files/notes.txt":
            return 200, self.body
        return 404, b"Not Found"


def test_path_byp_covers_extended_vectors(p3):
    assert {
        "..\\",
        "..\\/",
        "%2e%2e/",
        "%2e%2e%5c",
        "..%e0%80%af",
        "..%u2215",
    }.issubset(set(p3.PATH_BYP))


def test_decode_b64_flags_decodes_and_remembers(p3):
    blob = base64.b64encode(("prefix " + FLAG).encode()).decode()
    assert p3.decode_b64_flags("noise %s tail" % blob) == [FLAG]
    assert p3.verified_flag(FLAG)
    # too short to be a blob, and plain text without base64 at all
    assert p3.decode_b64_flags("short %s" % base64.b64encode(b"ab").decode()) == []
    assert p3.decode_b64_flags("no blobs here") == []


def test_http_get_surfaces_base64_hidden_flag(p3, monkeypatch):
    blob = base64.b64encode(FLAG.encode()).decode()
    page = ('{"status":"ok","content":"%s"}' % blob).encode()
    monkeypatch.setattr(
        p3,
        "HTTP_OPENER",
        FakeOpener(StaticPageService({"/download?file=notes.txt": page})),
    )
    result = p3.http_get("/download?file=notes.txt")
    assert FLAG in result["flag_shaped_values"]
    assert p3.verified_flag(FLAG)


def test_traverse_phase_a2_reads_environ_without_guessing_names(p3, monkeypatch):
    service = VulnerableFileService(
        files={
            "/srv/public/notes.txt": b"public notes for reconnaissance",
            "/proc/self/environ": ("APP_ENV=prod\n" + FLAG + "\n").encode(),
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
        },
        homepage=b"<html><body>index</body></html>",
        block_proc=False,
    )
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(service))
    out = p3.http_traverse({"names": ["treasure.txt"], "max_depth": 2})
    assert "proc/self/environ" in json.dumps(out["abs_proc_hits"], ensure_ascii=False)
    assert FLAG in json.dumps(out, ensure_ascii=False)
    assert p3.verified_flag(FLAG)


def test_traverse_name_variants_reach_hidden_dotfile(p3, monkeypatch):
    service = RawFilterService(
        files={
            "/srv/public/notes.txt": b"public notes for reconnaissance",
            "/srv/.flag.txt": FLAG.encode(),
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
        },
        homepage=b"<html><body>index</body></html>",
    )
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(service))
    # "flag.txt" is blocked raw and the dotfile lives one level above base:
    # only the new dotfile-hex variant (..%2f + .f%6cag.txt) decodes to it
    out = p3.http_traverse({"names": ["flag.txt"], "max_depth": 2})
    assert FLAG in json.dumps(out, ensure_ascii=False)
    assert p3.verified_flag(FLAG)


def test_discover_finds_href_and_plain_path_routes(p3, monkeypatch):
    monkeypatch.setattr(p3, "HTTP_OPENER", FakeOpener(RoutedService()))
    out = p3.http_discover()
    assert out["route"] == "/getfile?doc="
    assert [h["path"] for h in out["href_routes"]] == ["/getfile?doc=notes.txt"]
    assert "/files/notes.txt" in [h["path"] for h in out["plain_path_hits"]]
