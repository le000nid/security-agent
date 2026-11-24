"""Offline contracts and end-to-end loop for the integrated VEGA P4Z4 agent.

No sockets are used: the login service is an in-memory object backed by a
real sqlite3 database with a vulnerable string-concat query (role gate,
UNION reflection, CSRF validation and username sanitization behave
authentically), and the model is scripted, matching the no-network rule from
tests/conftest.py. Scenarios mirror the standalone regression set m1-m16.
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

from scripts.build_vega import REQUIRED, build_p4z4
from vega_p4z4 import agent as p4z4

FLAG = "VEGA_training{p4z4_offline_flag}"
SECRET = "TOK-9911-ABCDEF"
DECOY = "VEGA_training{decoy_m7}"
HOMEPAGE = "<html><body>Welcome. <a href='/login'>login</a></body></html>"


@pytest.fixture()
def p4z(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p4z4, "TASK_DIR", str(task))
    monkeypatch.setattr(p4z4, "MATERIALS", str(materials))
    monkeypatch.setattr(p4z4, "OUT_DIR", str(artifact))
    monkeypatch.setattr(p4z4, "TARGET", "http://target:8000")
    monkeypatch.setattr(p4z4, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p4z4, "MAX_STEPS", 12)
    monkeypatch.setattr(p4z4, "EVIDENCE", {"http": collections.deque(maxlen=80)})
    monkeypatch.setattr(p4z4, "HTTP_CACHE", collections.OrderedDict())
    monkeypatch.setattr(p4z4, "SESSION_COOKIE", "")
    monkeypatch.setattr(p4z4, "LAST_PROBE", {})
    # keep resolve_target fully offline unless a test overrides the probe
    monkeypatch.setattr(p4z4, "_probe_url", lambda url, timeout=4: False)
    return p4z4


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # the polite 20 ms matrix pauses add minutes to the payload sweeps
    monkeypatch.setattr(p4z4.time, "sleep", lambda *_: None)


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


class VulnerableLoginService:
    """Login service on real sqlite3 with a vulnerable string-concat query.

    The outer SELECT exposes 2 columns (username, password) so UNION payloads
    with 1-2 result columns behave exactly like on the real target. Rows
    belonging to known users run through the role gate; any other first row
    (UNION-injected) is reflected raw, which is the extraction oracle.
    """

    def __init__(
        self,
        users,
        role_col="role",
        admin_value="admin",
        form_path="/login",
        form_method="POST",
        csrf=None,
        filter_admin=False,
        filter_space_or=False,
        sanitize_username=False,
        flag_mode="direct",
        decoy=None,
        non_admin="welcome",
        homepage=None,
    ):
        self.users = users
        self.role_col = role_col
        self.admin_value = admin_value
        self.form_path = form_path
        self.form_method = form_method
        self.csrf = csrf
        self.filter_admin = filter_admin
        self.filter_space_or = filter_space_or
        self.sanitize_username = sanitize_username
        self.flag_mode = flag_mode
        self.decoy = decoy
        self.non_admin = non_admin
        self.sessions = {}
        self.counter = 0
        self.conn = sqlite3.connect(":memory:")
        role_type = "INTEGER" if isinstance(admin_value, int) else "TEXT"
        self.conn.execute(
            "CREATE TABLE users (username TEXT, password TEXT, %s %s)"
            % (role_col, role_type)
        )
        for row in users:
            self.conn.execute("INSERT INTO users VALUES (?, ?, ?)", row)
        if flag_mode == "secrets":
            self.conn.execute("CREATE TABLE secrets (value TEXT)")
            self.conn.execute("INSERT INTO secrets VALUES (?)", (FLAG,))
        self.conn.commit()
        hidden = ""
        if self.csrf:
            hidden = "<input type='hidden' name='%s' value='%s'>" % self.csrf
        self.form_page = (
            "<html><body><form action='%s' method='%s'>"
            "<input name='username'><input name='password'>%s</form></body></html>"
            % (self.form_path, self.form_method, hidden)
        ).encode()
        self.homepage = (homepage or HOMEPAGE).encode()
        self.fail_page = "Неверный логин или пароль".encode()

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
        path = parts.path or "/"
        if path == "/":
            if self.form_path == "/":
                # the login form lives on the homepage itself
                if "username" not in params:
                    return 200, self.form_page, {}
                return self._login(params)
            return 200, self.homepage, {}
        if path == self.form_path:
            if "username" not in params:
                return 200, self.form_page, {}
            return self._login(params)
        if path == "/dashboard":
            if sid in self.sessions:
                if self.flag_mode == "session":
                    return (
                        200,
                        (
                            "Личный кабинет %s. Флаг: %s" % (self.sessions[sid], FLAG)
                        ).encode(),
                        {},
                    )
                if self.flag_mode == "two_hop":
                    return (
                        200,
                        (
                            "Личный кабинет %s. <a href='/admin/flag'>reports</a>"
                            % self.sessions[sid]
                        ).encode(),
                        {},
                    )
                return (
                    200,
                    (
                        "Личный кабинет %s. Все системы в порядке." % self.sessions[sid]
                    ).encode(),
                    {},
                )
            return 302, b"", {"Location": self.form_path}
        if path == "/admin/flag":
            if sid in self.sessions:
                return 200, ("Reports: Флаг: %s" % FLAG).encode(), {}
            return 302, b"", {"Location": self.form_path}
        return 404, b"Not Found", {}

    def _login(self, params):
        username = params.get("username", "")
        password = params.get("password", "")
        if self.csrf and params.get(self.csrf[0]) != self.csrf[1]:
            return 403, b"csrf required", {}
        if self.filter_admin and "admin" in username.lower():
            return 400, b"filtered", {}
        if self.filter_space_or and (" " in username or "or" in username.lower()):
            return 400, b"filtered", {}
        if self.sanitize_username:
            username = username.replace("'", "").replace('"', "")
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
            return 200, self.fail_page, {}
        if not row:
            return 200, self.fail_page, {}
        known = {u for u, _, _ in self.users}
        if row[0] in known:
            found = self.conn.execute(
                "SELECT %s FROM users WHERE username = ?" % self.role_col, (row[0],)
            ).fetchone()
            role = found[0] if found else None
            if role == self.admin_value:
                self.counter += 1
                sid = "sid%d" % self.counter
                self.sessions[sid] = row[0]
                if self.flag_mode == "direct":
                    return (
                        200,
                        (
                            "Welcome, administrator %s. Флаг: %s" % (row[0], FLAG)
                        ).encode(),
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
                return (
                    302,
                    b"",
                    {"Location": "/dashboard", "Set-Cookie": sid + "; Path=/"},
                )
            if self.non_admin == "denied":
                return 200, "Доступ запрещён: только для администратора".encode(), {}
            page = "Личный кабинет %s. Вход выполнен." % row[0]
            if self.decoy:
                page += " Флаг: %s" % self.decoy
            return 200, page.encode(), {}
        # UNION / reflected row: dump the values raw — the extraction oracle
        return 200, (" | ".join(str(v) for v in row)).encode(), {}


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


def mount(p4z, monkeypatch, service):
    opener = FakeOpener(service)
    monkeypatch.setattr(p4z, "HTTP_OPENER", opener)
    monkeypatch.setattr(p4z, "POST_OPENER", opener)
    return opener


def read_flag(p4z):
    with open(p4z.OUT_DIR + "/flag.txt", encoding="utf-8") as handle:
        return handle.read()


# --- packaging ---------------------------------------------------------------


def test_p4z4_package_contains_exact_root_files_and_manifest(tmp_path):
    archive_path = build_p4z4(tmp_path / "security-agent-p4z4.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        source = archive.read("agent.py").decode("utf-8")
        assert "def login_probe" in source
        assert "def _union_extract" in source  # round-3 UNION extraction
        assert "os.replace" in source  # atomic artifact write
        assert "realpath" in source  # hardened path guard
        assert "if not existing:" in source  # crash guard keeps a written flag


# --- path guard and config contracts -----------------------------------------


def test_path_guard_rejects_escape_sibling_and_symlink(p4z):
    with pytest.raises(ValueError):
        p4z4.safe_material_path("../secret.txt")
    sibling = Path(p4z.MATERIALS).parent / "materials2"
    sibling.mkdir()
    (sibling / "x.txt").write_text("sibling", encoding="utf-8")
    with pytest.raises(ValueError):
        p4z4.safe_material_path("../materials2/x.txt")
    outside = Path(p4z.OUT_DIR)
    outside.mkdir(parents=True)
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    os.symlink(outside / "secret.txt", Path(p4z.MATERIALS) / "link.txt")
    with pytest.raises(ValueError):
        p4z4.safe_material_path("link.txt")
    inside = Path(p4z.MATERIALS) / "app.py"
    inside.write_text("q = 1", encoding="utf-8")
    assert p4z4.safe_material_path("app.py") == str(inside)


def test_safe_config_error_without_gateway(p4z, monkeypatch):
    for var in ("OPENAI_BASE_URL", "LOCAL_AGENT_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        p4z4.model([{"role": "user", "content": "hi"}])
    assert "not configured" in str(excinfo.value)


def test_resolve_target_keeps_default_when_nothing_answers(p4z):
    assert p4z4.resolve_target() == p4z4.TARGET == "http://target:8000"


# --- reply parsing and extractors ---------------------------------------------


def test_action_from_text_formats(p4z):
    assert p4z4.action_from_text('{"tool":"login_probe"}') == {"tool": "login_probe"}
    assert p4z4.action_from_text('```json\n{"tool":"http","path":"/login"}\n```') == {
        "tool": "http",
        "path": "/login",
    }
    assert p4z4.action_from_text('noise {"tool":"finish","flag":"x"} tail') == {
        "tool": "finish",
        "flag": "x",
    }
    assert (
        p4z4.action_from_text('{"tool":"read_file","arguments":{"path":"app.py"}}')[
            "path"
        ]
        == "app.py"
    )
    plain = p4z4.action_from_text(FLAG)
    assert plain["tool"] == "finish" and plain["flag"] == FLAG
    assert p4z4.action_from_text("no json here")["tool"] == "invalid"


def test_unwrap_body_contract(p4z):
    assert p4z4.unwrap_body('{"content":"inner text"}') == "inner text"
    assert p4z4.unwrap_body("<pre>VEGA_training{a}</pre>") == "VEGA_training{a}"
    assert p4z4.unwrap_body("plain body") == ""


def test_flag_rx_and_secret_line_rx(p4z):
    assert p4z4.FLAG_RX.search(FLAG)
    assert p4z4.SECRET_LINE_RX.search("Ваш секрет: SUPER-VALUE-42")
    assert p4z4.SECRET_LINE_RX.search("Token: TOK-9911")
    assert p4z4._clean_secret_value("<b>VEGA</b>") == "VEGA"


def test_redirect_guard_blocks_off_target_and_allows_same(p4z):
    handler = p4z4.GuardedRedirect()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            None, None, 302, "found", {}, "http://evil.example.com/dashboard"
        )
    allowed = handler.redirect_request(
        urllib.request.Request(p4z4.TARGET + "/login"),
        None,
        302,
        "found",
        {},
        p4z4.TARGET + "/dashboard",
    )
    assert isinstance(allowed, urllib.request.Request)


def test_no_redirect_handler_returns_none(p4z):
    assert (
        p4z4.NoRedirect().redirect_request(
            None, None, 302, "found", {}, p4z4.TARGET + "/dashboard"
        )
        is None
    )


# --- http layer ---------------------------------------------------------------


def test_http_get_stores_evidence_and_cache(p4z, monkeypatch):
    mount(p4z, monkeypatch, VulnerableLoginService(users=[("admin", "x", "admin")]))
    rec = p4z4.http_get("/login")
    assert rec["status"] == 200
    assert list(p4z4.EVIDENCE["http"]) and "<form" in list(p4z4.EVIDENCE["http"])[-1]
    assert rec["path"] in p4z4.HTTP_CACHE
    p4z4.http_get("/missing")
    assert not any("Not Found" in s for s in p4z4.EVIDENCE["http"])


def test_http_post_captures_cookie_without_following(p4z, monkeypatch):
    opener = mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(users=[("admin", "adm9", "admin")], flag_mode="session"),
    )
    rec = p4z4.http_post(
        {
            "path": "/login",
            "fields": {"username": "' OR username='admin' -- ", "password": "x"},
        }
    )
    assert rec["status"] == 302
    assert rec["location"] == "/dashboard"
    assert rec["set_cookie"].startswith("sid")
    assert p4z4.SESSION_COOKIE.startswith("sid")
    # redirect was NOT followed by the POST itself
    assert not any(url.endswith("/dashboard") for url, _, _ in opener.requests)
    # captured cookie is auto-attached to the next GET
    page = p4z4.http_get("/dashboard")
    assert page["status"] == 200 and FLAG in page["flag_shaped_values"]
    assert any(cookie.startswith("sid") for _, cookie, _ in opener.requests if cookie)


def test_decode_value_contract(p4z):
    blob = base64.b64encode("VEGA_training{seen}".encode()).decode()
    p4z4.EVIDENCE["http"].append("response body containing " + blob)
    out = p4z4.decode_value({"value": blob})
    assert "VEGA_training{seen}" in out["decoded"]
    assert any("VEGA_training{seen}" in s for s in p4z4.EVIDENCE["http"])
    unseen = base64.b64encode("never seen here".encode()).decode()
    p4z4.decode_value({"value": unseen})
    assert not any("never seen here" in s for s in p4z4.EVIDENCE["http"])
    assert p4z4.decode_value({"value": "414243", "encoding": "hex"})["decoded"] == "ABC"
    assert (
        p4z4.decode_value({"value": "x", "encoding": "nope"}) == "Unsupported encoding"
    )


# --- v2 platform extension -----------------------------------------------------


def test_decode_b64_flags_decodes_and_remembers(p4z):
    blob = base64.b64encode(("prefix " + FLAG).encode()).decode()
    assert p4z4.decode_b64_flags("noise %s tail" % blob) == [FLAG]
    assert p4z4.verified_flag(FLAG)
    assert p4z4.decode_b64_flags("short %s" % base64.b64encode(b"ab").decode()) == []
    assert p4z4.decode_b64_flags("no blobs here") == []


def test_http_post_surfaces_base64_hidden_flag(p4z, monkeypatch):
    blob = base64.b64encode(FLAG.encode()).decode()
    mount(
        p4z,
        monkeypatch,
        StaticService({"/login": ('{"status":"ok","content":"%s"}' % blob).encode()}),
    )
    rec = p4z4.http_post(
        {"path": "/login", "fields": {"username": "admin", "password": "x"}}
    )
    assert FLAG in rec["flag_shaped_values"]
    assert p4z4.verified_flag(FLAG)


# --- form parsing and recon -----------------------------------------------------


def test_parse_form_captures_hidden_fields(p4z):
    html_text = (
        "<html><body><form action='/login' method='post'>"
        "<input type='hidden' name='csrf_token' value='t0k3n'>"
        "<input name='username'><input name='password'>"
        "<input type='submit' name='go' value='Enter'></form></body></html>"
    )
    info = p4z4.parse_form(html_text, "/")
    assert info["path"] == "/login"
    assert info["method"] == "POST"
    assert info["fields"] == ["username", "password"]
    assert info["extra"] == {"csrf_token": "t0k3n", "go": "Enter"}


def test_form_field_pair_selection(p4z):
    assert p4z4.form_field_pair(["user_name", "pass_word"]) == (
        "user_name",
        "pass_word",
    )
    assert p4z4.form_field_pair(["login", "password"]) == ("login", "password")
    assert p4z4.form_field_pair(["a", "b"]) == ("a", "b")


def test_source_secrets_extracts_creds(p4z):
    (Path(p4z.MATERIALS) / "app.py").write_text(
        "INSERT INTO users VALUES ('margo', 'pw1', 'user');\n"
        "INSERT INTO users VALUES ('rosello', 's3cr3t', 'admin');\n"
        "ADMIN_USER=dusya\nADMIN_PASS=sssh123\n",
        encoding="utf-8",
    )
    creds, users = p4z4._source_secrets()
    assert ("rosello", "s3cr3t") in creds
    assert ("dusya", "sssh123") in creds
    assert "dusya" in users


def test_better_candidate_decoy_guard(p4z, monkeypatch):
    monkeypatch.setattr(
        p4z4,
        "LAST_PROBE",
        {
            "flag_contexts": [
                {"value": DECOY, "from_admin_response": False},
                {"value": FLAG, "from_admin_response": True},
            ]
        },
    )
    assert p4z4._better_candidate(DECOY, []) == FLAG
    assert p4z4._better_candidate(FLAG, []) == ""
    assert p4z4._better_candidate(DECOY, [FLAG]) == ""


# --- login_probe scenarios (m1-m16) ----------------------------------------------


def test_m1_role_gate_matrix_goes_past_first_success(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    # the regular-user success was collected, not treated as final
    assert any(h.get("sent", {}).get("username") == "' OR 1=1 -- " for h in out["hits"])
    assert out["flag_contexts"][0]["from_admin_response"] is True


def test_m2_admin_session_follow_to_dashboard(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="session",
            non_admin="denied",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert out["session_followed"]
    assert p4z4.verified_flag(FLAG)


def test_m3_admin_word_filter_concat_wins(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            filter_admin=True,
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    sent = [h["sent"]["username"] for h in out["hits"] if h.get("sent")]
    assert "' OR username='adm'||'in' -- " in sent


def test_m4_get_only_login(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            form_method="GET",
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert out["params"]["method"] == "GET"
    assert out["FLAG_SHAPED"] == [FLAG]


def test_m5_two_hop_session_links(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="two_hop",
            non_admin="denied",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]
    assert p4z4.verified_flag(FLAG)


def test_m6_secret_line_format(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("admin", "adm9", "admin")], flag_mode="secret_line"
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [SECRET]
    assert p4z4.verified_flag(SECRET)


def test_m7_decoy_ranked_last(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="direct",
            decoy=DECOY,
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"][0] == FLAG
    assert out["FLAG_SHAPED"][1] == DECOY


def test_m8_csrf_hidden_fields_replayed(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            form_path="/",
            csrf=("csrf_token", "t0k3n"),
            flag_mode="direct",
        ),
    )
    # without the hidden field the service rejects the whole matrix
    rec = p4z4.http_post(
        {"path": "/", "fields": {"username": "admin", "password": "x"}}
    )
    assert rec["status"] == 403
    out = p4z4.login_probe({})
    assert out["form"]["extra"] == {"csrf_token": "t0k3n"}
    assert out["FLAG_SHAPED"] == [FLAG]


def test_m9_admin_named_otherwise_source_recon(p4z, monkeypatch):
    (Path(p4z.MATERIALS) / "app.py").write_text(
        "INSERT INTO users VALUES ('rosello', 's3cr3t', 'admin');\n", encoding="utf-8"
    )
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("rosello", "s3cr3t", "admin")],
            filter_admin=True,
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert "rosello" in out.get("source_users_found", [])
    assert out["FLAG_SHAPED"] == [FLAG]


def test_m10_union_extraction_from_secrets_table(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="secrets",
        ),
    )
    out = p4z4.login_probe({})
    assert out.get("union_extracted") is True
    assert out["FLAG_SHAPED"][0] == FLAG
    assert p4z4.verified_flag(FLAG)


def test_m11_union_blind_without_admin_row(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(users=[("margo", "pw1", "user")], flag_mode="secrets"),
    )
    out = p4z4.login_probe({})
    assert out.get("union_extracted") is True
    assert out["FLAG_SHAPED"][0] == FLAG


def test_m15_password_only_injection(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", 0), ("admin", "adm9", 1)],
            role_col="is_admin",
            admin_value=1,
            sanitize_username=True,
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_m16_is_admin_column_admin_last(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", 0), ("petja", "pw2", 0), ("admin", "adm9", 1)],
            role_col="is_admin",
            admin_value=1,
            flag_mode="direct",
        ),
    )
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == [FLAG]


def test_login_probe_reports_failure_without_false_success(p4z, monkeypatch):
    mount(p4z, monkeypatch, StaticService({"/login": b"login page"}))
    out = p4z4.login_probe({})
    assert out["FLAG_SHAPED"] == []
    assert out["baseline"]["status"] == 200
    assert out["hint"]


# --- end-to-end loop -------------------------------------------------------------


def test_e2e_probe_then_verified_finish(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="session",
            non_admin="denied",
        ),
    )
    monkeypatch.setattr(
        p4z4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4z4.main() == 0  # P4Z4 always exits 0 and always writes flag.txt
    assert read_flag(p4z) == FLAG
    report = Path(p4z.OUT_DIR) / "report.txt"
    assert report.is_file() and "PROFILE: P4Z4" in report.read_text(encoding="utf-8")


def test_e2e_decoy_guard_steers_to_admin_value(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="direct",
            decoy=DECOY,
        ),
    )
    monkeypatch.setattr(
        p4z4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": DECOY}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4z4.main() == 0
    assert read_flag(p4z) == FLAG


def test_m12_autopilot_rescues_useless_model(p4z, monkeypatch):
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(
            users=[("margo", "pw1", "user"), ("admin", "adm9", "admin")],
            flag_mode="session",
            non_admin="denied",
        ),
    )
    monkeypatch.setattr(p4z4, "MAX_STEPS", 2)
    monkeypatch.setattr(
        p4z4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "http", "path": "/"}),
                json.dumps({"tool": "http", "path": "/"}),
            ]
        ),
    )
    assert p4z4.main() == 0
    assert read_flag(p4z) == FLAG


def test_m14_target_resolved_from_instruction(p4z, monkeypatch):
    (Path(p4z.MATERIALS) / "instruction.md").write_text(
        "Входные данные: materials. Сервис: http://10.20.30.40:8123\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        p4z4, "_probe_url", lambda url, timeout=4: url.startswith("http://10.20.30.40")
    )
    mount(
        p4z,
        monkeypatch,
        VulnerableLoginService(users=[("admin", "adm9", "admin")], flag_mode="direct"),
    )
    monkeypatch.setattr(
        p4z4,
        "model",
        ScriptedModel(
            [
                json.dumps({"tool": "login_probe"}),
                json.dumps({"tool": "finish", "flag": FLAG}),
            ]
        ),
    )
    assert p4z4.main() == 0
    assert p4z4.TARGET == "http://10.20.30.40:8123"
    assert read_flag(p4z) == FLAG
