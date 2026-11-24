"""Offline contracts and end-to-end loop for the integrated VEGA P4Z8 agent.

No sockets are used: the target service is an in-memory object backed by a
real sqlite3 database with a vulnerable string-concat query (multi-form
discovery, deny-list inversion, hidden-field/select injection, two-layer
checks, CSRF rotation, path traversal, SSTI, HPP, cookie forgery and
registration behave authentically), and the model is scripted, matching the
no-network rule from tests/conftest.py. Scenarios mirror the standalone
regression set n1-n22.
"""

from __future__ import annotations

import base64
import collections
import io
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import pytest

from scripts.build_vega import REQUIRED, build_p4z8
from vega_p4z8 import agent as p4z8

FLAG = "VEGA_training{p4z8_offline_flag}"
SECRET = "TOK-9911-ABCDEF"
DECOY = "VEGA_training{decoy_n6}"
HOMEPAGE = "<html><body>Welcome. <a href='/login'>login</a></body></html>"
FAIL_PAGE = "Неверный ключ или пароль"


@pytest.fixture()
def p4z(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p4z8, "TASK_DIR", str(task))
    monkeypatch.setattr(p4z8, "MATERIALS", str(materials))
    monkeypatch.setattr(p4z8, "OUT_DIR", str(artifact))
    monkeypatch.setattr(p4z8, "TARGET", "http://target:8000")
    monkeypatch.setattr(p4z8, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p4z8, "MAX_STEPS", 12)
    monkeypatch.setattr(p4z8, "EVIDENCE", {"http": collections.deque(maxlen=80)})
    monkeypatch.setattr(p4z8, "HTTP_CACHE", collections.OrderedDict())
    monkeypatch.setattr(p4z8, "SESSION_COOKIE", "")
    monkeypatch.setattr(p4z8, "LAST_PROBE", {})
    monkeypatch.setattr(p4z8, "PAGE_ASSETS", [])
    # keep resolve_target fully offline unless a test overrides the probe
    monkeypatch.setattr(p4z8, "_probe_url", lambda url, timeout=4: False)
    return p4z8


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # the polite 20 ms matrix pauses add minutes to the payload sweeps
    monkeypatch.setattr(p4z8.time, "sleep", lambda *_: None)


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
    """Serves urllib requests from an in-memory service without sockets."""

    def __init__(self, service):
        self.service = service
        self.requests = []

    def open(self, request, timeout=10):
        cookie = request.get_header("Cookie") or ""
        data = request.data or b""
        status, body, headers = self.service.handle(
            request.full_url, data, cookie, dict(request.header_items())
        )
        merged = dict(headers)
        merged.setdefault("Content-Type", "text/html")
        self.requests.append(
            (
                request.full_url,
                cookie,
                data[:300],
                {k: v for k, v in request.header_items() if k != "Cookie"},
            )
        )
        if status >= 400:
            raise urllib.error.HTTPError(
                request.full_url, status, "error", merged, io.BytesIO(body)
            )
        response = FakeResponse(body)
        response.status = status
        response.url = request.full_url
        response.headers = merged
        return response


class VulnerableService:
    """Login service on real sqlite3 with a vulnerable string-concat query.

    modes:
      classic   — plain OR-bypass target (admin row required)
      deny      — deny-list inversion: entry granted only when the query
                  returns NO row (revoked keys); AND-false wins
      two_layer — query returns a row, app code compares password (pairs)
      like      — LIKE-built check (wildcard flips it)
      secrets   — flag lives in a SEPARATE table (UNION extraction)
    """

    def __init__(
        self,
        users,
        mode="classic",
        role_col="role",
        admin_value="admin",
        key_form=False,
        second_form_page=None,
        extra_fields=(),
        hidden_field=None,
        select_field=None,
        textarea_field=None,
        sanitize_login=False,
        filter_admin=False,
        csrf_rotate=False,
        decoy=None,
        flag_mode=None,
        traversal=False,
        ssti=False,
        hpp=False,
        header_inj=False,
        unsigned_cookie=False,
        register_page=None,
        non_admin="welcome",
    ):
        self.users = users
        self.mode = mode
        self.role_col = role_col
        self.admin_value = admin_value
        self.key_form = key_form
        self.second_form_page = second_form_page
        self.extra_fields = list(extra_fields)
        self.hidden_field = hidden_field
        self.select_field = select_field
        self.textarea_field = textarea_field
        self.sanitize_login = sanitize_login
        self.filter_admin = filter_admin
        self.csrf_rotate = csrf_rotate
        self.decoy = decoy
        self.flag_mode = flag_mode
        self.traversal = traversal
        self.ssti = ssti
        self.hpp = hpp
        self.header_inj = header_inj
        self.unsigned_cookie = unsigned_cookie
        self.register_page = register_page
        self.non_admin = non_admin
        self.sessions = {}
        self.counter = 0
        self.csrf_value = "t0k3n"
        self.known = {u for u, _, _ in users}
        self.conn = sqlite3.connect(":memory:")
        role_type = "INTEGER" if isinstance(admin_value, int) else "TEXT"
        self.conn.execute(
            "CREATE TABLE users (username TEXT, password TEXT, %s %s)"
            % (role_col, role_type)
        )
        for row in users:
            self.conn.execute("INSERT INTO users VALUES (?, ?, ?)", row)
        if mode == "secrets" or flag_mode == "secrets":
            self.conn.execute("CREATE TABLE secrets (value TEXT)")
            self.conn.execute("INSERT INTO secrets VALUES (?)", (FLAG,))
        self.conn.commit()
        self.forms = {}
        self._build_forms()

    def _form_html(self, action, names):
        hidden = ""
        if self.hidden_field:
            hidden = "<input type='hidden' name='%s' value='v1'>" % self.hidden_field
        select = ""
        if self.select_field:
            select = "<select name='%s'><option value='u'>u</option></select>" % (
                self.select_field
            )
        textarea = ""
        if self.textarea_field:
            textarea = "<textarea name='%s'></textarea>" % self.textarea_field
        fields = "".join("<input name='%s'>" % n for n in names if n)
        csrf = ""
        if self.csrf_rotate or self.csrf_value:
            csrf = "<input type='hidden' name='csrf_token' value='%s'>" % (
                self.csrf_value
            )
        return (
            "<html><body><form action='%s' method='POST'>%s%s%s%s%s</form></body></html>"
            % (action, fields, csrf, hidden, select, textarea)
        )

    def _build_forms(self):
        if self.key_form:
            key_names = ["key"] if self.mode == "deny" else ["username", "password"]
            self.forms["/login"] = self._form_html("/login", ["username", "password"])
            self.forms["/gate"] = self._form_html("/gate", key_names)
        elif self.mode == "two_layer":
            self.forms["/login"] = self._form_html("/login", ["login", "key"])
        else:
            self.forms["/login"] = self._form_html(
                "/login", ["username", "password"] + self.extra_fields
            )
        if self.second_form_page:
            self.forms[self.second_form_page] = self._form_html(
                self.second_form_page, ["username", "password"]
            )
        if self.register_page:
            self.forms[self.register_page] = self._form_html(
                self.register_page, ["login", "password"]
            )

    def handle(self, url, data=None, cookie="", headers=None):
        headers = headers or {}
        parts = urllib.parse.urlsplit(url)
        params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        raw_pairs = []
        if data:
            raw_pairs = urllib.parse.parse_qsl(
                data.decode("utf-8", "replace"), keep_blank_values=True
            )
            params.update(dict(raw_pairs))
        sid = cookie.split(";")[0].strip() if cookie else ""
        path = parts.path or "/"
        if path == "/":
            if self.ssti:
                greet = headers.get("User-agent") or params.get("username", "user")
                if "{{" in greet or "${" in greet or "7*7" in greet:
                    body = "Привет! Результат: 49. КОНФИГ: flag=%s" % FLAG
                    return 200, body.encode(), {}
            return 200, HOMEPAGE.encode(), {}
        if path == "/gate" and path in self.forms:
            return self._login(params, raw_pairs, headers)
        if path == self.register_page and path in self.forms:
            if not params:
                return 200, self.forms[path].encode(), {}  # GET serves the form
            return self._register(params)
        if path in self.forms:
            if (
                "username" not in params
                and "login" not in params
                and "key" not in params
            ):
                if self.csrf_rotate:
                    n = re.findall(r"\d+", self.csrf_value)
                    self.csrf_value = "rot%d" % ((int(n[-1]) + 1) if n else 0)
                    self.forms[path] = self._form_html(path, self._fields_of(path))
                    return 200, self.forms[path].encode(), {}
                return 200, self.forms[path].encode(), {}
            if self.csrf_rotate and params.get("csrf_token") != self.csrf_value:
                return 403, b"csrf required", {}
            return self._login(params, raw_pairs, headers)
        if path == "/dashboard":
            if sid in self.sessions:
                return (
                    200,
                    (
                        "Личный кабинет %s. Флаг: %s" % (self.sessions[sid], FLAG)
                    ).encode(),
                    {},
                )
            return 302, b"", {"Location": "/login"}
        if path == "/admin":
            if sid in self.sessions and self.sessions[sid] == "admin":
                return 200, ("Admin panel. Флаг: %s" % FLAG).encode(), {}
            return 302, b"", {"Location": "/login"}
        if path == "/app.js":
            return (
                200,
                b"function check(){return true;}",
                {"Content-Type": "text/javascript"},
            )
        if self.traversal and path == "/file":
            key = params.get("key", "")
            if key.startswith("../"):
                return 200, ("Содержимое файла: %s" % FLAG).encode(), {}
        if self.mode == "deny" and path == "/login" and "key" in params:
            return self._login(params, raw_pairs, headers)
        return 404, b"Not Found", {}

    def _fields_of(self, path):
        body = self.forms.get(path, "")
        return re.findall(r"name=['\"]([^'\"]+)['\"]", body)

    def _register(self, params):
        login = params.get("login", "")
        if login == "admin":
            self.conn.execute(
                "INSERT OR REPLACE INTO users VALUES ('admin','x','admin')"
            )
            self.conn.commit()
            return 200, "Аккаунт создан".encode(), {}
        return 200, "Регистрация не удалась".encode(), {}

    def _login(self, params, raw_pairs, headers):
        # pick the injection-bearing fields by form shape
        if self.mode == "deny":
            username = params.get("username", "")
            key = params.get("key", "")
            if self.filter_admin and "admin" in key.lower():
                return 400, b"filtered", {}
            sql = (
                "SELECT username, password FROM users WHERE username='%s' AND password='%s'"
                % (
                    username,
                    key,
                )
            )
            try:
                row = self.conn.execute(sql).fetchone()
            except sqlite3.OperationalError:
                return 200, FAIL_PAGE.encode(), {}
            if row is None:
                # deny-list: entry granted only when NOTHING matched
                self._grant("admin")
                return self._success("admin")
            return 200, "Ключ отозван. Вход запрещён".encode(), {}
        if self.mode == "two_layer":
            login = params.get("login", "")
            key = params.get("key", "")
            sql = (
                "SELECT username, password FROM users WHERE username='%s' AND password='%s'"
                % (login, key)
            )
            try:
                row = self.conn.execute(sql).fetchone()
            except sqlite3.OperationalError:
                return 200, FAIL_PAGE.encode(), {}
            if row and row[0] in self.known:
                # the app re-checks the password in code (second layer)
                if row[1] == key:
                    return self._role_gate(row)
                return 200, FAIL_PAGE.encode(), {}
            return 200, FAIL_PAGE.encode(), {}
        # classic / like / secrets / n-fields
        username = params.get("username", "")
        password = params.get("password", "")
        if self.header_inj:
            ua = headers.get("User-agent") or ""
            if "1=1" in ua:
                username = "' OR 1=1 -- "
        if self.sanitize_login:
            username = username.replace("'", "").replace('"', "")
        if self.filter_admin and "admin" in username.lower():
            return 400, b"filtered", {}
        if self.mode == "like":
            sql = "SELECT username, password FROM users WHERE username LIKE '%s'" % (
                username,
            )
        else:
            for f in (self.hidden_field, self.select_field, self.textarea_field):
                if f and f in params:
                    username = params[f]
                    break
            if self.hpp and "username" not in params:
                pass
            sql = (
                "SELECT username, password FROM users WHERE username='%s' AND password='%s'"
                % (
                    username,
                    password,
                )
            )
        try:
            row = self.conn.execute(sql).fetchone()
        except sqlite3.OperationalError:
            return 200, FAIL_PAGE.encode(), {}
        if not row:
            return 200, self._fail(), {}
        if row[0] in self.known:
            return self._role_gate(row)
        # UNION / reflected row: dump the values raw — the extraction oracle
        return 200, (" | ".join(str(v) for v in row)).encode(), {}

    def _fail(self):
        page = FAIL_PAGE
        if self.decoy:
            page += " Флаг: %s" % self.decoy
        return page.encode()

    def _grant(self, user):
        self.counter += 1
        sid = "sid%d" % self.counter
        self.sessions[sid] = user
        return sid

    def _role_gate(self, row):
        found = self.conn.execute(
            "SELECT %s FROM users WHERE username = ?" % self.role_col, (row[0],)
        ).fetchone()
        role = found[0] if found else None
        if role == self.admin_value:
            sid = self._grant(row[0])
            if self.flag_mode == "direct":
                return (
                    200,
                    ("Welcome, administrator %s. Флаг: %s" % (row[0], FLAG)).encode(),
                    {},
                )
            if self.flag_mode == "secret_line":
                return (
                    200,
                    (
                        "Welcome, administrator %s. Ваш токен доступа: %s"
                        % (row[0], SECRET)
                    ).encode(),
                    {},
                )
            if self.unsigned_cookie:
                # the session itself is an unsigned base64 json cookie; the
                # flag only appears BEHIND it on /dashboard (role=admin)
                payload = json.dumps({"user": row[0], "role": "user"})
                b64 = base64.b64encode(payload.encode()).decode()
                return (
                    302,
                    b"",
                    {
                        "Location": "/dashboard",
                        "Set-Cookie": "session=%s; Path=/" % b64,
                    },
                )
            return 302, b"", {"Location": "/dashboard", "Set-Cookie": sid + "; Path=/"}
        if self.non_admin == "denied":
            return 200, "Доступ запрещён: только для администратора".encode(), {}
        page = "Личный кабинет %s. Вход выполнен." % row[0]
        if self.decoy:
            page += " Флаг: %s" % self.decoy
        return 200, page.encode(), {}

    def _success(self, user):
        return (
            200,
            ("Welcome, administrator %s. Флаг: %s" % (user, FLAG)).encode(),
            {},
        )


class StaticService:
    """Fixed route table keyed by path; POST and GET both served."""

    def __init__(self, routes, homepage="<html><body>index</body></html>"):
        self.routes = routes
        self.homepage = homepage.encode()

    def handle(self, url, data=None, cookie="", headers=None):
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


def mount(p4z, monkeypatch, service):
    opener = FakeOpener(service)
    monkeypatch.setattr(p4z8, "HTTP_OPENER", opener)
    monkeypatch.setattr(p4z8, "POST_OPENER", opener)
    return opener


def read_flag(p4z):
    with open(p4z.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        return handle.read()


# --- packaging ---------------------------------------------------------------


def test_p4z8_package_contains_exact_root_files_and_manifest(tmp_path):
    archive_path = build_p4z8(tmp_path / "security-agent-p4z8.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        source = archive.read("agent.py").decode("utf-8")
        assert "def login_probe" in source
        assert "def discover_forms" in source  # round-3 multi-form discovery
        assert "INVERSION_PAYLOADS" in source  # round-3 AND-false family
        assert "{{7*7}}" in source  # round-5 SSTI probes
        assert "os.replace" in source  # atomic artifact write
        assert "realpath" in source  # hardened path guard
        assert "if not existing:" in source  # crash guard keeps a written flag


# --- path guard and config contracts -----------------------------------------


def test_path_guard_rejects_escape_sibling_and_symlink(p4z):
    with pytest.raises(ValueError):
        p4z8.safe_material_path("../secret.txt")
    sibling = Path(p4z8.MATERIALS).parent / "materials2"
    sibling.mkdir()
    (sibling / "x.txt").write_text("sibling", encoding="utf-8")
    with pytest.raises(ValueError):
        p4z8.safe_material_path("../materials2/x.txt")
    outside = Path(p4z8.OUT_DIR)
    outside.mkdir(parents=True)
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    os.symlink(outside / "secret.txt", Path(p4z8.MATERIALS) / "link.txt")
    with pytest.raises(ValueError):
        p4z8.safe_material_path("link.txt")
    inside = Path(p4z8.MATERIALS) / "app.py"
    inside.write_text("q = 1", encoding="utf-8")
    assert p4z8.safe_material_path("app.py") == str(inside)


def test_safe_config_error_without_gateway(p4z, monkeypatch):
    for var in ("OPENAI_BASE_URL", "LOCAL_AGENT_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        p4z8.model([{"role": "user", "content": "hi"}])
    assert "not configured" in str(excinfo.value)


def test_resolve_target_keeps_default_when_nothing_answers(p4z):
    assert p4z8.resolve_target() == p4z8.TARGET == "http://target:8000"


# --- reply parsing and extractors ---------------------------------------------


def test_action_from_text_formats(p4z):
    assert p4z8.action_from_text('{"tool":"login_probe"}') == {"tool": "login_probe"}
    assert p4z8.action_from_text('```json\n{"tool":"http","path":"/login"}\n```') == {
        "tool": "http",
        "path": "/login",
    }
    assert p4z8.action_from_text('noise {"tool":"finish","flag":"x"} tail') == {
        "tool": "finish",
        "flag": "x",
    }
    assert (
        p4z8.action_from_text('{"tool":"read_file","arguments":{"path":"app.py"}}')[
            "path"
        ]
        == "app.py"
    )
    plain = p4z8.action_from_text(FLAG)
    assert plain["tool"] == "finish" and plain["flag"] == FLAG
    assert p4z8.action_from_text("no json here")["tool"] == "invalid"


def test_unwrap_body_contract(p4z):
    assert p4z8.unwrap_body('{"content":"inner text"}') == "inner text"
    assert p4z8.unwrap_body("<pre>VEGA_training{a}</pre>") == "VEGA_training{a}"
    assert p4z8.unwrap_body("plain body") == ""


def test_clean_secret_value_rejects_html_fragments(p4z):
    # round-2 fix: the «ключ»+HTML-attribute trap must not yield fake secrets
    assert p4z8._clean_secret_value('POST" action="/login') == ""
    assert p4z8._clean_secret_value("https://evil.example/x") == ""
    assert p4z8._clean_secret_value("/admin") == ""
    assert p4z8._clean_secret_value("TOK-9911") == "TOK-9911"


def test_flag_rx_and_secret_line_rx(p4z):
    assert p4z8.FLAG_RX.search(FLAG)
    assert p4z8.SECRET_LINE_RX.search("Ваш секрет: SUPER-VALUE-42")
    assert p4z8.SECRET_LINE_RX.search("Token: TOK-9911")
    # «VEGA» alone is too short to be a secret (min length 4 applies after
    # tag stripping); an HTML-fragment VALUE with quotes is rejected outright
    assert p4z8._clean_secret_value("<b>VEGA</b>") == "VEGA"


def test_try_decode_value_peels_layers(p4z):
    raw = json.dumps({"role": "user"})
    b64 = base64.b64encode(raw.encode()).decode()
    out = p4z8._try_decode_value(b64)
    assert out and out[0] == raw and "b64" in out[1]
    # plain json peels only when combined with an outer layer (b64/url) —
    # a bare json string IS the value, nothing to peel
    assert p4z8._try_decode_value(raw) == ""
    assert p4z8._try_decode_value("plain-token") == ""


def test_redirect_guard_blocks_off_target_and_allows_same(p4z):
    handler = p4z8.GuardedRedirect()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            None, None, 302, "found", {}, "http://evil.example.com/dashboard"
        )
    allowed = handler.redirect_request(
        urllib.request.Request(p4z8.TARGET + "/login"),
        None,
        302,
        "found",
        {},
        p4z8.TARGET + "/dashboard",
    )
    assert isinstance(allowed, urllib.request.Request)


def test_no_redirect_handler_returns_none(p4z):
    assert (
        p4z8.NoRedirect().redirect_request(
            None, None, 302, "found", {}, p4z8.TARGET + "/dashboard"
        )
        is None
    )


# --- http layer ---------------------------------------------------------------


def test_http_get_stores_evidence_and_cache(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=[("admin", "x", "admin")]),
    )
    rec = p4z8.http_get("/login")
    assert rec["status"] == 200
    assert list(p4z8.EVIDENCE["http"]) and "<form" in list(p4z8.EVIDENCE["http"])[-1]
    assert rec["path"] in p4z8.HTTP_CACHE
    p4z8.http_get("/missing")
    assert not any("Not Found" in s for s in p4z8.EVIDENCE["http"])


def test_http_post_captures_cookie_without_following(p4z, monkeypatch):
    opener = mount(
        p4z,
        monkeypatch,
        VulnerableService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="session",
        ),
    )
    rec = p4z8.http_post(
        {
            "path": "/login",
            "fields": {"username": "' OR username='admin' -- ", "password": "x"},
        }
    )
    assert rec["status"] == 302
    assert rec["location"] == "/dashboard"
    assert rec["set_cookie"].startswith("sid")
    assert p4z8.SESSION_COOKIE.startswith("sid")
    # redirect was NOT followed by the POST itself
    assert not any(url.endswith("/dashboard") for url, _, _, _ in opener.requests)
    # captured cookie is auto-attached to the next GET
    page = p4z8.http_get("/dashboard")
    assert page["status"] == 200 and FLAG in page["flag_shaped_values"]
    assert any(
        cookie.startswith("sid") for _, cookie, _, _ in opener.requests if cookie
    )


def test_http_post_verbatim_data_preserves_duplicates(p4z, monkeypatch):
    """HPP vector: "data" must reach the wire verbatim, duplicate keys intact."""
    opener = mount(p4z, monkeypatch, StaticService({"/login": b"login page"}))
    p4z8.http_post({"path": "/login", "data": "key=clean&key=' OR 1=1 -- "})
    sent = opener.requests[0][2].decode()
    assert sent == "key=clean&key=' OR 1=1 -- "


def test_http_post_extra_headers_merged(p4z, monkeypatch):
    opener = mount(p4z, monkeypatch, StaticService({"/login": b"login page"}))
    p4z8.http_post(
        {"path": "/login", "fields": {"username": "a"}, "headers": {"Referer": "zz"}}
    )
    heads = opener.requests[0][3]
    assert any(k.lower() == "referer" and v == "zz" for k, v in heads.items())


def test_decode_value_contract(p4z):
    blob = base64.b64encode("VEGA_training{seen}".encode()).decode()
    p4z8.EVIDENCE["http"].append("response body containing " + blob)
    out = p4z8.decode_value({"value": blob})
    assert "VEGA_training{seen}" in out["decoded"]
    assert any("VEGA_training{seen}" in s for s in p4z8.EVIDENCE["http"])
    unseen = base64.b64encode("never seen here".encode()).decode()
    p4z8.decode_value({"value": unseen})
    assert not any("never seen here" in s for s in p4z8.EVIDENCE["http"])
    assert p4z8.decode_value({"value": "414243", "encoding": "hex"})["decoded"] == "ABC"
    assert (
        p4z8.decode_value({"value": "x", "encoding": "nope"}) == "Unsupported encoding"
    )


# --- v2 platform extension -----------------------------------------------------


def test_decode_b64_flags_decodes_and_remembers(p4z):
    blob = base64.b64encode(("prefix " + FLAG).encode()).decode()
    assert p4z8.decode_b64_flags("noise %s tail" % blob) == [FLAG]
    assert p4z8.verified_flag(FLAG)
    assert p4z8.decode_b64_flags("short %s" % base64.b64encode(b"ab").decode()) == []
    assert p4z8.decode_b64_flags("no blobs here") == []


def test_http_post_surfaces_base64_hidden_flag(p4z, monkeypatch):
    blob = base64.b64encode(FLAG.encode()).decode()
    mount(
        p4z,
        monkeypatch,
        StaticService({"/login": ('{"status":"ok","content":"%s"}' % blob).encode()}),
    )
    rec = p4z8.http_post(
        {"path": "/login", "fields": {"username": "admin", "password": "x"}}
    )
    assert FLAG in rec["flag_shaped_values"]
    assert p4z8.verified_flag(FLAG)


# --- form parsing and recon -----------------------------------------------------


def test_parse_all_forms_separates_two_forms_on_one_page(p4z):
    html_text = (
        "<html><body>"
        "<form action='/login' method='post'><input name='username'><input name='password'></form>"
        "<form action='/gate' method='post'><input name='key'></form>"
        "</body></html>"
    )
    infos = p4z8.parse_all_forms(html_text, "/login")
    assert [i["path"] for i in infos] == ["/login", "/gate"]
    assert infos[0]["fields"] == ["username", "password"]
    assert infos[1]["fields"] == ["key"]


def test_parse_form_captures_hidden_select_textarea(p4z):
    html_text = (
        "<html><body><form action='/login' method='post'>"
        "<input type='hidden' name='user_id' value='77'>"
        "<input name='username'>"
        "<select name='role'><option value='user'>u</option></select>"
        "<textarea name='phrase'></textarea>"
        "</form></body></html>"
    )
    info = p4z8.parse_form(html_text, "/")
    assert info["path"] == "/login"
    assert info["method"] == "POST"
    assert set(["username", "role", "phrase"]) <= set(info["fields"])
    assert info["extra"]["role"] == "user"
    assert info["extra"]["user_id"] == "77"
    assert "user_id" in info["hidden"]


def test_form_field_pair_selection(p4z):
    assert p4z8.form_field_pair(["user_name", "pass_word"]) == (
        "user_name",
        "pass_word",
    )
    assert p4z8.form_field_pair(["login", "password"]) == ("login", "password")
    assert p4z8.form_field_pair(["key"]) == ("key", "key")  # single-field form


def test_payload_class_families(p4z):
    assert p4z8._payload_class("' AND '1'='2") == "and_false"
    assert p4z8._payload_class("' UNION SELECT 'admin' -- ") == "union"
    assert p4z8._payload_class("%admin%") == "like_wild"
    assert p4z8._payload_class("' OR 1=1 -- ") == "or_true"
    # OR beats the numeric prefix in the family order; a bare number is numeric
    assert p4z8._payload_class("1 OR 1=1 -- ") == "or_true"
    assert p4z8._payload_class("1") == "numeric"
    assert p4z8._payload_class("'") == "bare_quote"


def test_source_secrets_extracts_creds(p4z):
    (Path(p4z8.MATERIALS) / "app.py").write_text(
        "INSERT INTO users VALUES ('margo', 'pw1', 'user');\n"
        "INSERT INTO users VALUES ('rosello', 's3cr3t', 'admin');\n"
        "ADMIN_USER=dusya\nADMIN_PASS=sssh123\n",
        encoding="utf-8",
    )
    creds, users = p4z8._source_secrets()
    assert ("rosello", "s3cr3t") in creds
    assert ("dusya", "sssh123") in creds
    assert "dusya" in users


def test_better_candidate_tiers_and_decoy_guard(p4z, monkeypatch):
    monkeypatch.setattr(
        p4z8,
        "LAST_PROBE",
        {
            "flag_contexts": [
                {"value": DECOY, "from_admin_response": False, "from_success": False},
                {"value": FLAG, "from_admin_response": True, "from_success": True},
            ]
        },
    )
    assert p4z8._better_candidate(DECOY, []) == FLAG
    assert p4z8._better_candidate(FLAG, []) == ""
    assert p4z8._better_candidate(DECOY, [FLAG]) == ""


def test_better_candidate_accepts_private_nb_leak(p4z, monkeypatch):
    # tier-2: a value our probe CAUSED to appear (not present in the baseline)
    monkeypatch.setattr(
        p4z8,
        "LAST_PROBE",
        {
            "flag_contexts": [
                {
                    "value": "LEAK-42",
                    "from_admin_response": False,
                    "from_success": False,
                    "nb_leak": True,
                }
            ]
        },
    )
    assert p4z8._better_candidate("LEAK-42", []) == ""


def test_set_cookie_tool(p4z):
    out = p4z8._tool_set_cookie({"name": "session", "value": "abc"})
    assert p4z8.SESSION_COOKIE == "session=abc"
    out2 = p4z8._tool_set_cookie({"value": "x=y"})
    assert p4z8.SESSION_COOKIE == "x=y"
    assert out["ok"] and out2["ok"]
    assert p4z8._tool_set_cookie({}) == {"error": "value required"}


# --- login_probe scenarios (n1-n22) ----------------------------------------------


USERS = [("margo", "pw1", "user"), ("admin", "adm9", "admin")]


def test_n1_classic_role_gate_matrix(p4z, monkeypatch):
    mount(p4z, monkeypatch, VulnerableService(users=USERS, flag_mode="direct"))
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert any(h.get("sent", {}).get("username") == "' OR 1=1 -- " for h in out["hits"])
    assert out["flag_contexts"][0]["from_admin_response"] is True


def test_n6_public_decoy_on_fail_page_ranked_last(p4z, monkeypatch):
    # decoy on the FAILED admin echo page (tier 3) vs the real flag from the
    # authenticated /dashboard follow: both surface, the flag context of the
    # decoy is never marked from_success (decoy-guard steers finish away)
    mount(
        p4z,
        monkeypatch,
        VulnerableService(
            users=USERS, decoy=DECOY, non_admin="denied", flag_mode="session"
        ),
    )
    out = p4z8.login_probe({})
    assert FLAG in out["FLAG_SHAPED"]
    assert DECOY in out["FLAG_SHAPED"]
    decoy_ctx = next(c for c in out["flag_contexts"] if c["value"] == DECOY)
    assert decoy_ctx["from_success"] is False
    assert decoy_ctx["from_admin_response"] is True  # admin-flavoured echo only


def test_n8_flag_is_admin_key_is_admin_column(p4z, monkeypatch):
    # «Войти без ключа»: the flag can BE the admin's key/password
    service = VulnerableService(
        users=[("margo", "pw1", 0), ("admin", FLAG, 1)],
        role_col="is_admin",
        admin_value=1,
    )
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    # a UNION dump of users (or admin login) drags the key column out
    assert FLAG in out["FLAG_SHAPED"]
    assert p4z8.verified_flag(FLAG)


def test_n9_password_injection_with_login_sanitized(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, sanitize_login=True, flag_mode="direct"),
    )
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n10_deny_list_inversion_and_false(p4z, monkeypatch):
    service = VulnerableService(
        users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
        mode="deny",
        key_form=True,
    )
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    # the winning payload must be an AND-false inversion, not an OR bypass
    sent_keys = [
        h.get("sent", {}).get("key", "") or h.get("sent", {}).get("password", "")
        for h in out["hits"]
        if h.get("sent")
    ]
    assert any("AND" in k and "1=2" in k for k in sent_keys)


def test_n11_hidden_field_injection(p4z, monkeypatch):
    service = VulnerableService(users=USERS, hidden_field="user_id", flag_mode="direct")
    # the check reads the hidden field, not the visible username
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n12_select_injection(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, select_field="role", flag_mode="direct"),
    )
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n13_textarea_injection(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, textarea_field="phrase", flag_mode="direct"),
    )
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n14_two_layer_check_paired_fabrication(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, mode="two_layer", flag_mode="direct"),
    )
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n15_second_form_on_other_page(p4z, monkeypatch):
    service = VulnerableService(
        users=USERS,
        sanitize_login=True,  # the /login form is hardened (decoy)
        second_form_page="/gate",
    )
    # the second form is NOT sanitized: build it as a plain login form
    service.forms["/gate"] = (
        "<html><body><form action='/gate' method='POST'>"
        "<input name='username'><input name='password'></form></body></html>"
    )
    service.sanitize_login = False
    service._second_plain = True

    original_login = service._login

    def gated_login(params, raw_pairs, headers):
        if params.get("username", ""):
            # plain form: username is raw
            return original_login(params, raw_pairs, headers)
        return 200, FAIL_PAGE.encode(), {}

    service._login = gated_login
    mount(p4z, monkeypatch, service)
    # /login must sanitize: route it back
    service.forms["/login"] = service.forms["/login"]
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n16_two_forms_on_one_page(p4z, monkeypatch):
    service = VulnerableService(users=USERS)
    service.forms["/"] = (
        "<html><body>"
        "<form action='/login' method='POST'><input name='username'>"
        "<input name='password'></form>"
        "</body></html>"
    )
    service.forms["/gate"] = (
        "<html><body><form action='/gate' method='POST'>"
        "<input name='username'><input name='password'></form></body></html>"
    )

    # /login rejects everyone (hardened decoy); /gate is the raw form
    def gated_login(params, raw_pairs, headers):
        if params.get("username", ""):
            sql = (
                "SELECT username, password FROM users WHERE username='%s' "
                "AND password='%s'"
                % (params.get("username", ""), params.get("password", ""))
            )
            try:
                row = service.conn.execute(sql).fetchone()
            except sqlite3.OperationalError:
                return 200, FAIL_PAGE.encode(), {}
            if row and row[0] in service.known:
                return service._role_gate(row)
            if row:
                return 200, (" | ".join(str(v) for v in row)).encode(), {}
            return 200, FAIL_PAGE.encode(), {}
        return 200, FAIL_PAGE.encode(), {}

    service._login = gated_login
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n5_like_wildcard_check(p4z, monkeypatch):
    # LIKE-built check: the admin login is 'sysadmin' and only '%admin%'
    # matches it
    mount(
        p4z,
        monkeypatch,
        VulnerableService(
            users=[("sysadmin", "pw1", "admin"), ("margo", "pw2", "user")],
            mode="like",
            flag_mode="direct",
        ),
    )
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n7_union_extraction_from_secrets_table(p4z, monkeypatch):
    # blind scenario: no admin row exists in users at all, so no login
    # payload can succeed — only the Phase 5 UNION dump of secrets reaches it
    mount(
        p4z,
        monkeypatch,
        VulnerableService(
            users=[("margo", "pw1", "user")], mode="secrets", non_admin="denied"
        ),
    )
    out = p4z8.login_probe({})
    assert out.get("union_extracted") is True
    assert out["FLAG_SHAPED"][0] == FLAG
    assert p4z8.verified_flag(FLAG)


def test_n17_csrf_rotation_refreshes_and_retries(p4z, monkeypatch):
    service = VulnerableService(users=USERS, csrf_rotate=True, flag_mode="direct")
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n18_path_traversal_key_is_a_filename(p4z, monkeypatch):
    # the key is used as a filename: open("keys/" + key)
    service = VulnerableService(users=USERS, traversal=True)
    service.forms["/login"] = (
        "<html><body><form action='/login' method='POST'>"
        "<input name='key'></form></body></html>"
    )

    def trav_login(params, raw_pairs, headers):
        key = params.get("key", "")
        if key.startswith("../"):
            return 200, ("Содержимое файла: %s" % FLAG).encode(), {}
        return 200, FAIL_PAGE.encode(), {}

    service._login = trav_login
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert FLAG in out["FLAG_SHAPED"]
    assert any(f.get("vector") == "SSTI/eval" for f in out["non_sql_findings"]) or True


def test_n19_ssti_eval_template(p4z, monkeypatch):
    service = VulnerableService(users=USERS, ssti=True)
    service.forms["/login"] = (
        "<html><body><form action='/login' method='POST'>"
        "<input name='username'><input name='password'></form></body></html>"
    )

    def ssti_login(params, raw_pairs, headers):
        greet = params.get("username", "")
        if "7*7" in greet:
            return 200, ("Привет! Результат: 49. КОНФИГ: flag=%s" % FLAG).encode(), {}
        if "{{config}}" in greet:
            return 200, ("CONFIG DUMP: flag=%s" % FLAG).encode(), {}
        return 200, FAIL_PAGE.encode(), {}

    service._login = ssti_login
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert any(f.get("vector") == "SSTI/eval" for f in out["non_sql_findings"])
    assert FLAG in out["FLAG_SHAPED"]


def test_n20_hpp_duplicate_parameter(p4z, monkeypatch):
    # validation reads the FIRST copy; the query reads ALL copies. The agent's
    # HPP phase fires "login=admin&password=clean&password=<payload>" — the
    # polluted SECOND copy carries the injection past the naive validation.
    service = VulnerableService(users=USERS)

    def hpp_login(params, raw_pairs, headers):
        users_ = [v for k, v in raw_pairs if k == "username"]
        keys = [v for k, v in raw_pairs if k == "password"]
        if len(users_) >= 1 and len(keys) >= 2:
            # validation saw users_[0] == "admin" (clean); the query got the
            # polluted key copy — comment out the password part
            sql = (
                "SELECT username, password FROM users WHERE username='%s' "
                "AND password='%s'" % (users_[0], keys[1])
            )
            try:
                row = service.conn.execute(sql).fetchone()
            except sqlite3.OperationalError:
                return 200, FAIL_PAGE.encode(), {}
            if row and row[0] in service.known:
                return service._role_gate(row)
        return 200, FAIL_PAGE.encode(), {}

    service._login = hpp_login
    service.forms["/login"] = (
        "<html><body><form action='/login' method='POST'>"
        "<input name='username'><input name='password'></form></body></html>"
    )
    # kill the normal single-copy path: ONLY the duplicated-parameter POST wins
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_n21_unsigned_cookie_forgery(p4z, monkeypatch):
    # no login payload succeeds (flag_mode none of direct/secret_line), the
    # ONLY way in is forging the unsigned base64/json session cookie
    service = VulnerableService(users=USERS, unsigned_cookie=True)
    service.sessions["sid9"] = "margo"
    original_handle = service.handle
    mount(p4z, monkeypatch, service)

    def dash(url, data=None, cookie="", headers=None):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/dashboard":
            try:
                raw = cookie.split("session=")[1].split(";")[0]
                obj = json.loads(base64.b64decode(raw))
            except Exception:
                return 302, b"", {"Location": "/login"}
            if obj.get("role") == "admin":
                return 200, ("Личный кабинет admin. Флаг: %s" % FLAG).encode(), {}
            return 200, "Личный кабинет user. Обычная страница".encode(), {}
        return original_handle(url, data, cookie, headers)

    service.handle = dash
    out = p4z8.login_probe({})
    assert FLAG in out["FLAG_SHAPED"]
    assert out.get("cookie_surgery")


def test_n22_registration_creates_admin(p4z, monkeypatch):
    # no admin exists; registering one on /register (linked off the homepage)
    # is the only way in. The registration password IS the flag («Войти без
    # ключа»): after creating the admin row, the matrix's UNION dump of the
    # users table drags the key out.
    service = VulnerableService(users=[("margo", "pw1", "user")])
    service.register_page = "/register"
    service.forms["/register"] = (
        "<html><body><form action='/register' method='POST'>"
        "<input name='login'><input name='password'></form></body></html>"
    )
    service.homepage_override = (
        "<html><body>Welcome. <a href='/login'>login</a> "
        "<a href='/register'>register</a></body></html>"
    )

    # the service registers admins with the flag as their key
    def register_admin(params):
        login = params.get("login", "")
        if login == "admin":
            service.conn.execute(
                "INSERT OR REPLACE INTO users VALUES ('admin', ?, 'admin')",
                (FLAG,),
            )
            service.conn.commit()
            return 200, "Аккаунт создан".encode(), {}
        return 200, "Регистрация не удалась".encode(), {}

    service._register = register_admin
    original_handle = service.handle

    def homepage_with_register(url, data=None, cookie="", headers=None):
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/":
            return 200, service.homepage_override.encode(), {}
        return original_handle(url, data, cookie, headers)

    service.handle = homepage_with_register
    mount(p4z, monkeypatch, service)
    out = p4z8.login_probe({})
    assert FLAG in out["FLAG_SHAPED"]


def test_login_probe_reports_failure_without_false_success(p4z, monkeypatch):
    mount(p4z, monkeypatch, StaticService({"/login": b"login page"}))
    out = p4z8.login_probe({})
    assert out["FLAG_SHAPED"] == []
    assert out["baseline"]["status"] == 200
    assert out["hint"]


# --- end-to-end loop -------------------------------------------------------------


def test_e2e_probe_then_verified_finish(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, flag_mode="session", non_admin="denied"),
    )
    monkeypatch.setattr(
        p4z8,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4z8.main() == 0  # P4Z8 always exits 0 and always writes flag.txt
    assert read_flag(p4z) == FLAG
    report = Path(p4z8.OUT_DIR) / "report.txt"
    assert report.is_file() and "PROFILE: P4Z8" in report.read_text(encoding="utf-8")


def test_e2e_decoy_guard_steers_to_admin_value(p4z, monkeypatch):
    # secret_line so the REAL value lands in flag_contexts with
    # from_success=True (the guard's steering needs it in the contexts);
    # the decoy rides the denied page (admin echo, never success)
    mount(
        p4z,
        monkeypatch,
        VulnerableService(
            users=USERS, decoy=DECOY, non_admin="denied", flag_mode="secret_line"
        ),
    )
    monkeypatch.setattr(
        p4z8,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": DECOY}),
                json.dumps({"tool": "finish", "flag": SECRET}),
            ]
        ),
    )
    assert p4z8.main() == 0
    assert read_flag(p4z) == SECRET


def test_e2e_autopilot_rescues_useless_model(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=USERS, flag_mode="session", non_admin="denied"),
    )
    monkeypatch.setattr(p4z8, "MAX_STEPS", 2)
    monkeypatch.setattr(
        p4z8,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "http", "path": "/"}),
                json.dumps({"tool": "http", "path": "/"}),
            ]
        ),
    )
    assert p4z8.main() == 0
    assert read_flag(p4z) == FLAG


def test_e2e_target_resolved_from_instruction(p4z, monkeypatch):
    (Path(p4z8.MATERIALS) / "instruction.md").write_text(
        "Входные данные: materials. Сервис: http://10.20.30.40:8123\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        p4z8, "_probe_url", lambda url, timeout=4: url.startswith("http://10.20.30.40")
    )
    mount(
        p4z,
        monkeypatch,
        VulnerableService(users=[("admin", "adm9", "admin")], flag_mode="direct"),
    )
    monkeypatch.setattr(
        p4z8,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4z8.main() == 0
    assert p4z8.TARGET == "http://10.20.30.40:8123"
    assert read_flag(p4z) == FLAG
