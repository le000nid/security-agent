"""Offline contracts and end-to-end loop for the integrated VEGA P4Z2 agent.

No sockets are used: the login service is an in-memory object backed by a
real sqlite3 database with a vulnerable string-concat query (so quote,
comment and OR injections behave authentically), and the model is scripted,
matching the no-network rule from tests/conftest.py.
"""

from __future__ import annotations

import base64
import collections
import io
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import pytest

from scripts.build_vega import REQUIRED, build_p4z2
from vega_p4z2 import agent as p4z2

FLAG = "VEGA_training{p4z2_offline_e2e_flag}"
HOMEPAGE = "<html><body>Welcome. <a href='/login'>login</a></body></html>"


@pytest.fixture()
def p4(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p4z2, "TASK_DIR", str(task))
    monkeypatch.setattr(p4z2, "MATERIALS", str(materials))
    monkeypatch.setattr(p4z2, "OUT_DIR", str(artifact))
    monkeypatch.setattr(p4z2, "TARGET", "http://target:8000")
    monkeypatch.setattr(p4z2, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p4z2, "MAX_STEPS", 12)
    monkeypatch.setattr(p4z2, "EVIDENCE", {"http": collections.deque(maxlen=80)})
    monkeypatch.setattr(p4z2, "HTTP_CACHE", collections.OrderedDict())
    monkeypatch.setattr(p4z2, "SESSION_COOKIE", "")
    return p4z2


# --- in-memory vulnerable target and scripted model --------------------------


class FakeResponse(io.BytesIO):
    headers = {"Content-Type": "text/html"}
    status = 200
    url = ""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeOpener:
    """Serves urllib requests from an in-memory service without sockets.

    Passes the request body and Cookie header to the service so POST forms
    and session semantics work; records every request for assertions.
    """

    def __init__(self, service):
        self.service = service
        self.requests = []

    def open(self, request, timeout=10):
        cookie = request.get_header("Cookie") or ""
        status, body, headers = self.service.handle(
            request.full_url, request.data, cookie
        )
        merged = dict(headers)
        merged.setdefault("Content-Type", "text/html")
        self.requests.append((request.full_url, cookie, (request.data or b"")[:200]))
        if status >= 400:
            raise urllib.error.HTTPError(
                request.full_url, status, "error", merged, io.BytesIO(body)
            )
        response = FakeResponse(body)
        response.status = status
        response.url = request.full_url
        response.headers = merged
        return response


class SqliteLoginService:
    """Login service on a real sqlite3 DB with a vulnerable concat query.

    handle() returns (status, body, headers). The SQL is built by string
    concatenation exactly like the vulnerable target, so quote escapes,
    comments and OR tautologies behave authentically.
    """

    def __init__(
        self,
        homepage=HOMEPAGE,
        filter_spaces_or=False,
        method="POST",
        flag_direct=False,
        two_hop=False,
    ):
        self.homepage = homepage.encode()
        self.filter_spaces_or = filter_spaces_or
        self.form_method = method
        self.flag_direct = flag_direct
        self.two_hop = two_hop
        self.sessions = {}
        self.counter = 0
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        self.conn.execute("INSERT INTO users VALUES ('admin', 'S3cureP4ss')")
        self.conn.commit()
        self.fail_page = "Неверный логин или пароль".encode()
        self.form_page = (
            "<html><body><form action='/login' method='%s'>"
            "<input name='username'><input name='password'></form></body></html>"
            % self.form_method
        ).encode()

    def handle(self, url, data=None, cookie=""):
        parts = urllib.parse.urlsplit(url)
        params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        if data:
            params.update(
                urllib.parse.parse_qsl(
                    data.decode("utf-8", "replace"), keep_blank_values=True
                )
            )
        sid = cookie.split(";")[0].strip() if cookie else ""
        if parts.path == "/":
            return 200, self.homepage, {}
        if parts.path == "/login":
            if "username" not in params:
                return 200, self.form_page, {}
            username = params.get("username", "")
            password = params.get("password", "")
            if self.filter_spaces_or and (" " in username or "or" in username.lower()):
                return 400, b"filtered", {}
            sql = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (
                username,
                password,
            )
            try:
                row = self.conn.execute(sql).fetchone()
            except sqlite3.OperationalError:
                return 200, b"Login error: bad sql", {}
            if not row:
                return 200, self.fail_page, {}
            self.counter += 1
            sid = "sid%d" % self.counter
            self.sessions[sid] = row[0]
            if self.flag_direct:
                return 200, ("Welcome %s. Flag: %s" % (row[0], FLAG)).encode(), {}
            return 302, b"", {"Location": "/dashboard", "Set-Cookie": sid + "; Path=/"}
        if parts.path == "/dashboard":
            if sid not in self.sessions:
                return 302, b"", {"Location": "/login"}
            if self.two_hop:
                page = (
                    "Личный кабинет %s. <a href='/admin/flag'>reports</a>"
                    % (self.sessions[sid])
                )
                return 200, page.encode(), {}
            return (
                200,
                ("Личный кабинет %s. Flag: %s" % (self.sessions[sid], FLAG)).encode(),
                {},
            )
        if parts.path == "/admin/flag":
            if sid not in self.sessions:
                return 302, b"", {"Location": "/login"}
            return 200, ("Reports: Flag: %s" % FLAG).encode(), {}
        return 404, b"Not Found", {}


class StaticService:
    """Fixed route table keyed by path; POST and GET both served."""

    def __init__(self, routes, homepage="<html><body>index</body></html>"):
        self.routes = routes
        self.homepage = homepage.encode()

    def handle(self, url, data=None, cookie=""):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/":
            return 200, self.homepage, {}
        if parts.path in self.routes:
            return 200, self.routes[parts.path], {}
        return 404, b"Not Found", {}


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


def mount(p4, monkeypatch, service):
    opener = FakeOpener(service)
    monkeypatch.setattr(p4, "HTTP_OPENER", opener)
    monkeypatch.setattr(p4, "POST_OPENER", opener)
    return opener


# --- packaging ---------------------------------------------------------------


def test_p4z2_package_contains_exact_root_files_and_manifest(tmp_path):
    archive_path = build_p4z2(tmp_path / "security-agent-p4z2.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        source = archive.read("agent.py").decode("utf-8")
        assert "def login_probe" in source
        assert "def http_post" in source
        assert "os.replace" in source  # atomic artifact write
        assert "realpath" in source  # hardened path guard


# --- path guard --------------------------------------------------------------


def test_path_guard_rejects_escape_and_sibling(p4):
    with pytest.raises(ValueError):
        p4.safe_material_path("../secret.txt")
    sibling = Path(p4.MATERIALS).parent / "materials2"
    sibling.mkdir()
    (sibling / "x.txt").write_text("sibling", encoding="utf-8")
    with pytest.raises(ValueError):
        p4.safe_material_path("../materials2/x.txt")


def test_path_guard_rejects_symlink_escape(p4):
    outside = Path(p4.OUT_DIR)
    outside.mkdir(parents=True)
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    os.symlink(outside / "secret.txt", Path(p4.MATERIALS) / "link.txt")
    with pytest.raises(ValueError):
        p4.safe_material_path("link.txt")
    inside = Path(p4.MATERIALS) / "app.py"
    inside.write_text("query = 1", encoding="utf-8")
    assert p4.safe_material_path("app.py") == str(inside)


# --- reply parsing contracts -------------------------------------------------


def test_action_from_text_formats(p4):
    assert p4.action_from_text('{"tool":"login_probe"}') == {"tool": "login_probe"}
    assert p4.action_from_text('```json\n{"tool":"http","path":"/login"}\n```') == {
        "tool": "http",
        "path": "/login",
    }
    assert p4.action_from_text('noise {"tool":"finish","flag":"x"} tail') == {
        "tool": "finish",
        "flag": "x",
    }
    assert (
        p4.action_from_text('{"tool":"read_file","arguments":{"path":"app.py"}}')[
            "path"
        ]
        == "app.py"
    )
    assert p4.action_from_text('{"action":"inventory"}')["tool"] == "inventory"
    plain = p4.action_from_text("VEGA_training{plain_text_flag}")
    assert (
        plain["tool"] == "finish" and plain["flag"] == "VEGA_training{plain_text_flag}"
    )
    assert p4.action_from_text("no json here")["tool"] == "invalid"


def test_unwrap_body_contract(p4):
    assert p4.unwrap_body('{"content":"inner text"}') == "inner text"
    assert p4.unwrap_body("<pre>VEGA_training{a}</pre>") == "VEGA_training{a}"
    assert p4.unwrap_body("plain body") == ""


def test_flag_rx_shapes(p4):
    assert p4.FLAG_RX.search(FLAG)
    assert p4.FLAG_RX.search("flag{abc}")
    assert not p4.FLAG_RX.search("VEGA_training{\nbroken}")


# --- http layer contracts ----------------------------------------------------


def test_redirect_guard_blocks_off_target_and_allows_same(p4):
    handler = p4.GuardedRedirect()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            None, None, 302, "found", {}, "http://evil.example.com/dashboard"
        )
    allowed = handler.redirect_request(
        urllib.request.Request(p4.TARGET + "/login"),
        None,
        302,
        "found",
        {},
        p4.TARGET + "/dashboard",
    )
    assert isinstance(allowed, urllib.request.Request)


def test_no_redirect_handler_returns_none(p4):
    assert (
        p4.NoRedirect().redirect_request(
            None, None, 302, "found", {}, p4.TARGET + "/dashboard"
        )
        is None
    )


def test_safe_config_error_without_gateway(p4, monkeypatch):
    for var in ("OPENAI_BASE_URL", "LOCAL_AGENT_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        p4.model([{"role": "user", "content": "hi"}])
    assert "not configured" in str(excinfo.value)


def test_http_get_stores_evidence_and_cache(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService())
    rec = p4.http_get("/login")
    assert rec["status"] == 200
    assert list(p4.EVIDENCE["http"]) and "form" in list(p4.EVIDENCE["http"])[-1]
    assert rec["path"] in p4.HTTP_CACHE
    p4.http_get("/missing")
    assert not any("Not Found" in s for s in p4.EVIDENCE["http"])


def test_http_batch_dedups_and_returns_records(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService())
    results = p4.http_batch({"paths": ["/login", "/login", "/dashboard", "/missing"]})
    assert len(results) == 3  # duplicate /login removed
    statuses = {r["path"]: r["status"] for r in results}
    assert statuses["/login"] == 200
    assert statuses["/dashboard"] == 302  # no session yet
    assert statuses["/missing"] == 404


def test_http_post_captures_cookie_without_following(p4, monkeypatch):
    opener = mount(p4, monkeypatch, SqliteLoginService())
    rec = p4.http_post(
        {"path": "/login", "fields": {"username": "' OR 1=1 -- ", "password": "x"}}
    )
    assert rec["status"] == 302
    assert rec["location"] == "/dashboard"
    assert rec["set_cookie"].startswith("sid")
    assert p4.SESSION_COOKIE.startswith("sid")
    # redirect was NOT followed by the POST itself
    assert not any(url.endswith("/dashboard") for url, _, _ in opener.requests)
    # captured cookie is auto-attached to the next GET
    page = p4.http_get("/dashboard")
    assert page["status"] == 200
    assert any(cookie.startswith("sid") for _, cookie, _ in opener.requests if cookie)


def test_decode_value_contract(p4):
    blob = base64.b64encode("VEGA_training{seen}".encode()).decode()
    p4.EVIDENCE["http"].append("response body containing " + blob)
    out = p4.decode_value({"value": blob})
    assert "VEGA_training{seen}" in out["decoded"]
    # the decoded text is remembered only when the blob was seen in evidence
    assert any("VEGA_training{seen}" in s for s in p4.EVIDENCE["http"])
    unseen = base64.b64encode("never seen here".encode()).decode()
    p4.decode_value({"value": unseen})
    assert not any("never seen here" in s for s in p4.EVIDENCE["http"])
    assert p4.decode_value({"value": "414243", "encoding": "hex"})["decoded"] == "ABC"
    assert p4.decode_value({"value": "x", "encoding": "nope"}) == "Unsupported encoding"


# --- v2 platform extension ---------------------------------------------------


def test_decode_b64_flags_decodes_and_remembers(p4):
    blob = base64.b64encode(("prefix " + FLAG).encode()).decode()
    assert p4.decode_b64_flags("noise %s tail" % blob) == [FLAG]
    assert p4.verified_flag(FLAG)
    # too short to be a blob, and plain text without base64 at all
    assert p4.decode_b64_flags("short %s" % base64.b64encode(b"ab").decode()) == []
    assert p4.decode_b64_flags("no blobs here") == []


def test_http_post_surfaces_base64_hidden_flag(p4, monkeypatch):
    blob = base64.b64encode(FLAG.encode()).decode()
    mount(
        p4,
        monkeypatch,
        StaticService({"/login": ('{"status":"ok","content":"%s"}' % blob).encode()}),
    )
    rec = p4.http_post(
        {"path": "/login", "fields": {"username": "admin", "password": "x"}}
    )
    assert FLAG in rec["flag_shaped_values"]
    assert p4.verified_flag(FLAG)


# --- login form parsing ------------------------------------------------------


def test_parse_form_extracts_action_method_fields(p4):
    html_text = (
        "<html><body><form action='/auth/login' method='post'>"
        "<input name='user_name'><input name='pass_word'>"
        "<input name='csrf_token' type='hidden'></form></body></html>"
    )
    info = p4.parse_form(html_text, "/login")
    assert info["path"] == "/auth/login"
    assert info["method"] == "POST"
    assert info["fields"] == ["user_name", "pass_word"]  # csrf filtered


def test_form_field_pair_selection(p4):
    assert p4.form_field_pair(["user_name", "pass_word"]) == ("user_name", "pass_word")
    assert p4.form_field_pair(["login", "password"]) == ("login", "password")
    assert p4.form_field_pair(["a", "b"]) == ("a", "b")  # positional fallback


def test_grep_files_finds_query_construction(p4):
    (Path(p4.MATERIALS) / "app.py").write_text(
        "query = \"SELECT * FROM users WHERE username='%s'\"\n", encoding="utf-8"
    )
    out = p4.grep_files({"pattern": "SELECT"})
    assert "app.py" in out and "SELECT" in out


# --- login_probe scenarios m1-m5 ---------------------------------------------


def test_m1_login_probe_direct_flag_response(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService(flag_direct=True))
    out = p4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert out["params"]["method"] == "POST"
    assert p4.verified_flag(FLAG)


def test_m2_login_probe_session_follow_to_dashboard(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService())
    out = p4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert out["session_followed"]
    assert p4.verified_flag(FLAG)


def test_m3_login_probe_space_or_filter_bypassed_by_comment(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService(flag_direct=True, filter_spaces_or=True))
    out = p4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert any(h["sent"]["username"] == "admin'--" for h in out["hits"] if "sent" in h)


def test_m4_login_probe_get_form(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService(method="GET", flag_direct=True))
    out = p4.login_probe({})
    assert out["params"]["method"] == "GET"
    assert out["FLAG_SHAPED"] == [FLAG]
    assert p4.verified_flag(FLAG)


def test_m5_login_probe_two_hop_link_follow(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService(two_hop=True))
    out = p4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert p4.verified_flag(FLAG)


def test_login_probe_no_success_reports_baseline_and_hits(p4, monkeypatch):
    mount(p4, monkeypatch, StaticService({"/login": b"login page"}))
    out = p4.login_probe({})
    assert out["FLAG_SHAPED"] == []
    assert out["baseline"]["status"] == 200
    assert out["hint"]


# --- end-to-end loop ---------------------------------------------------------


def test_e2e_login_probe_then_verified_finish(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService())
    monkeypatch.setattr(
        p4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4.main() == 0
    with open(p4.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG


def test_e2e_rejects_fabricated_flag_then_accepts_verified(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService())
    monkeypatch.setattr(
        p4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": "VEGA_training{fabricated}"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4.main() == 0
    with open(p4.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG


def test_main_fallback_writes_best_evidence_value(p4, monkeypatch):
    mount(p4, monkeypatch, SqliteLoginService(flag_direct=True))
    monkeypatch.setattr(p4, "MAX_STEPS", 2)
    monkeypatch.setattr(
        p4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "http", "path": "/login"}),
            ]
        ),
    )
    assert p4.main() == 0  # graceful fallback: best flag-shaped value from evidence
    with open(p4.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        assert handle.read() == FLAG
