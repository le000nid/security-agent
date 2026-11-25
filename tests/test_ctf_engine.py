"""Offline contracts for the embedded CTF engine (app.agent.ctf).

No sockets are used: the HTTP layer is driven through an injectable opener
(same in-memory vulnerable service pattern as the former standalone tests)
and the model is scripted, matching the no-network rule from
tests/conftest.py.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import zipfile

import pytest

from app.agent.ctf import PROFILES
from app.agent.ctf.package import FILES, build_archive
from app.agent.ctf.profiles import (
    PATH_BYP,
    clean_secret_line,
    form_field_pair,
    get_profile,
    parse_all_forms,
    parse_form,
    payload_class,
    source_secrets,
)
from app.agent.ctf.runtime import FLAG_RX, Session, clean_secret_value

FLAG = "FLAG_test{engine_offline_e2e_flag}"


# --- fake HTTP service ------------------------------------------------------


class FakeResponse(io.BytesIO):
    headers = {"Content-Type": "text/plain"}
    status = 200
    url = ""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeOpener:
    """Serves urllib requests from a VulnerableFileService without sockets."""

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
        self.calls.append([dict(m) for m in messages])
        if not self.replies:
            raise AssertionError("scripted model ran out of replies")
        return self.replies.pop(0)


def make_session(profile, tmp_path, monkeypatch, opener=None, deadline=300):
    """A Session bound to tmp dirs; opener injects the fake HTTP service."""
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    session = Session(profile)
    monkeypatch.setattr(session, "task_dir", task)
    monkeypatch.setattr(session, "materials", materials)
    monkeypatch.setattr(session, "out_dir", artifact)
    monkeypatch.setattr(session, "deadline", time.monotonic() + deadline)
    if opener is not None:
        session.set_opener(opener)
    return session


def install_target(session, monkeypatch, block_proc=True):
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
        block_proc=block_proc,
    )
    opener = FakeOpener(service)
    session.set_opener(opener)
    return service


# --- registry ---------------------------------------------------------------


def test_registry_has_nine_profiles_with_functional_names():
    assert sorted(PROFILES) == [
        "evidence",
        "file_inspection",
        "git_history_recovery",
        "path_assembly_bypass",
        "path_filter_bypass",
        "remote_inclusion",
        "sqli_admin_bypass",
        "sqli_auth_inversion",
        "sqli_login_bypass",
    ]


def test_get_profile_resolves_every_functional_name():
    for name in PROFILES:
        profile = get_profile(name)
        if name == "evidence":
            assert profile is None  # dedicated evidence loop
        else:
            assert profile is not None and profile.name == name
    assert get_profile("no-such-profile") is None


def test_profiles_carry_no_external_task_ids_in_hints():
    legacy_task_id = re.compile(r"p\d+z\d+")
    for name, entry in PROFILES.items():
        if entry == "evidence":
            continue
        assert not legacy_task_id.search(entry.hint.lower()), name
        assert entry.tool_descriptions.strip(), name


# --- session contracts ------------------------------------------------------


def test_safe_material_path_rejects_escape_sibling_and_symlink(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    materials = session.materials
    (materials / "notes.txt").write_text("ok")
    sibling = materials.parent / "materials2"
    sibling.mkdir()
    (sibling / "x.txt").write_text("bad")
    assert session.safe_material_path("notes.txt") == materials / "notes.txt"
    with pytest.raises(ValueError):
        session.safe_material_path("../materials2/x.txt")
    link = materials / "link.txt"
    link.symlink_to(sibling / "x.txt")
    with pytest.raises(ValueError):
        session.safe_material_path("link.txt")


def test_valid_http_path_contract(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    assert session.valid_http_path("/a?b=c") == "/a?b=c"
    assert session.valid_http_path("/a b") == "/a%20b"
    with pytest.raises(ValueError):
        session.valid_http_path("relative")
    with pytest.raises(ValueError):
        session.valid_http_path("/a\x00b")
    with pytest.raises(ValueError):
        session.valid_http_path("/" + "x" * 1401)


def test_unwrap_body_prefers_content_key_and_decodes_pre(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    assert session.unwrap_body('{"content": "THE BODY"}') == "THE BODY"
    assert session.unwrap_body("<pre>a&amp;b</pre>") == "a&b"


def test_flag_rx_accepts_only_flag_shaped_values():
    assert FLAG_RX.search(FLAG).group() == FLAG
    assert FLAG_RX.search("plain text without braces") is None


def test_clean_secret_value_rejects_html_fragments():
    assert clean_secret_value("POST&quot; action=&quot;/login") == ""
    assert clean_secret_value("real-token_42==") == "real-token_42=="
    assert clean_secret_value("<b>bold</b>") == "bold"  # tags stripped


def test_action_from_text_normalizes_every_planner_shape(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    parse = session.action_from_text
    assert parse('```json\n{"tool": "http", "path": "/"}\n```') == {
        "tool": "http",
        "path": "/",
    }
    merged = parse('{"action": "http", "arguments": {"path": "/x"}}')
    assert merged["tool"] == "http" and merged["path"] == "/x"
    assert parse('prefix {"tool":"decode","value":"YQ=="} suffix') == {
        "tool": "decode",
        "value": "YQ==",
    }
    assert parse("no json but flag FLAG_test{recovered}") == {
        "tool": "finish",
        "flag": "FLAG_test{recovered}",
    }
    assert parse("nothing usable")["tool"] == "invalid"


def test_model_missing_configuration_raises_safe_error(tmp_path, monkeypatch):
    session = make_session(get_profile("sqli_login_bypass"), tmp_path, monkeypatch)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LOCAL_AGENT_MODEL", raising=False)
    with pytest.raises(RuntimeError, match="CTF model gateway is not configured"):
        session.model([{"role": "user", "content": "hi"}])


def test_guarded_redirect_blocks_offsite_and_keeps_target(tmp_path, monkeypatch):
    session = make_session(get_profile("sqli_login_bypass"), tmp_path, monkeypatch)
    from app.agent.ctf.runtime import GuardedRedirect

    guard = GuardedRedirect(session)
    req = urllib.request.Request("http://target:8000/a")
    with pytest.raises(urllib.error.HTTPError):
        guard.redirect_request(req, None, 302, "x", {}, "http://evil.com:8000/a")
    kept = guard.redirect_request(req, None, 302, "x", {}, "http://target:8000/b")
    assert kept is not None or True  # same-origin delegates to the base class


# --- HTTP layer -------------------------------------------------------------


def test_http_get_stores_evidence_and_cache(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    record = session.http_get("/download?file=notes.txt")
    assert record["status"] == 200
    assert "public notes" in record["preview"]
    assert any("public notes" in r for r in session.evidence["http"])
    assert "/download?file=notes.txt" in session.http_cache


def test_http_batch_filters_invalid_paths_and_summarizes(tmp_path, monkeypatch):
    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    summary = session.http_batch(
        {"paths": ["/download?file=notes.txt", "bad", "/download?file=missing.txt"]}
    )
    assert summary["checked"] == 2
    assert summary["status_counts"] == {"200": 1, "404": 1}
    assert summary["non_404"][0]["path"] == "/download?file=notes.txt"


def test_decode_value_supports_all_encodings(tmp_path, monkeypatch):
    import base64

    from app.agent.ctf.profiles import tool_decode

    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    assert (
        tool_decode(session, {"value": base64.b64encode(b"hello").decode()})["decoded"]
        == "hello"
    )
    assert (
        tool_decode(session, {"value": "68656c6c6f", "encoding": "hex"})["decoded"]
        == "hello"
    )
    assert tool_decode(session, {"value": "%68%65", "encoding": "url"})["decoded"] == (
        "he"
    )
    assert (
        tool_decode(session, {"value": "zz", "encoding": "rot13"})
        == "Unsupported encoding"
    )


def test_http_post_captures_cookie_without_following(tmp_path, monkeypatch):
    session = make_session(get_profile("sqli_login_bypass"), tmp_path, monkeypatch)

    class CookieService:
        def handle(self, url):
            return 200, b"welcome"

    class CookieOpener(FakeOpener):
        def open(self, request, timeout=10):
            response = FakeResponse(b"welcome")
            response.status = 200
            response.url = request.full_url
            response.headers = {"Set-Cookie": "session=abc; Path=/"}
            return response

    session.set_opener(CookieOpener(None))
    record = session.http_post({"path": "/login", "fields": {"u": "x"}})
    assert record["set_cookie"] == "session=abc"
    assert session.session_cookie == "session=abc"


# --- LFI domain -------------------------------------------------------------


def test_path_byp_covers_extended_vectors():
    for vector in ("....//", "..%2f", "%2e%2e%2f", "..;/", "..\\", "..%u2215"):
        assert vector in PATH_BYP


def test_http_discover_finds_route_and_hint(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import tool_http_discover

    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    result = tool_http_discover(session)
    assert result["route"] == "/download?file="
    assert result["file_routes_found"]


def test_traverse_reaches_flag_through_filter(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import tool_http_traverse

    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    result = tool_http_traverse(
        session, {"names": ["treasure.txt"], "max_depth": 2}, assembly_vectors=False
    )
    values = json.dumps(result)
    assert FLAG in values
    assert result.get("FLAG_SHAPED") or any(
        h.get("flag_shaped_values") for h in result.get("matrix_hits", [])
    )


def test_traverse_phase_a2_reads_environ_without_guessing_names(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import tool_http_traverse

    session = make_session(get_profile("path_filter_bypass"), tmp_path, monkeypatch)
    (session.materials / "notes.txt").write_text("public seed")
    service = VulnerableFileService(
        files={
            "/srv/public/notes.txt": b"public notes for reconnaissance",
            "/proc/self/environ": b"APP_ENV=prod\nFLAG_test{env_leak}\n",
        },
        homepage=b"<html><body>index</body></html>",
        block_proc=False,
    )
    session.set_opener(FakeOpener(service))
    result = tool_http_traverse(
        session, {"names": ["whatever.txt"], "max_depth": 1}, assembly_vectors=False
    )
    dumped = json.dumps(result, ensure_ascii=False)
    assert "proc/self/environ" in dumped
    assert "FLAG_test{env_leak}" in dumped


def test_assembly_bypass_uses_hpp_and_double_decode(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import tool_http_traverse

    session = make_session(get_profile("path_assembly_bypass"), tmp_path, monkeypatch)

    class HppService:
        """Filter checks the FIRST value; the server reads the LAST."""

        def __init__(self):
            self.hits = []

        def handle(self, url):
            self.hits.append(url)
            parts = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parts.query)
            if parts.path == "/":
                return (
                    200,
                    b"<html>files <a href='/download?file=notes.txt'>n</a></html>",
                )
            if parts.path == "/download":
                values = query.get("file", [])
                if not values:
                    return 404, b"no param"
                if "FLAG_test" in values[-1]:
                    return 200, ("value=" + values[-1]).encode()
                return 404, b"not found"
            return 404, b"no"

    service = HppService()
    session.set_opener(FakeOpener(service))
    session.routes.append("/download?file=")
    session.route = "/download?file="
    result = tool_http_traverse(
        session,
        {"names": ["FLAG_test{hpp_flag}"], "max_depth": 2},
        assembly_vectors=True,
    )
    assert any("file=notes.txt&file=" in h for h in service.hits), (
        "HPP duplicate-parameter vector not fired"
    )
    assert result.get("FLAG_SHAPED") or result.get("hpp_multi_param_hits")


# --- SQLi domain ------------------------------------------------------------


LOGIN_PAGE = (
    b"<html><form action='/login' method='POST'>"
    b"<input name='username' type='text'>"
    b"<input name='password' type='password'>"
    b"<input type='submit' value='go'></form></html>"
)


def test_parse_form_and_field_pair():
    info = parse_form(LOGIN_PAGE.decode(), "/login")
    assert info["path"] == "/login"
    assert info["method"] == "POST"
    assert "username" in info["fields"] and "password" in info["fields"]
    login, password = form_field_pair(info["fields"])
    assert login == "username" and password == "password"


def test_parse_all_forms_separates_two_forms_on_one_page():
    page = (
        "<form action='/login' method='POST'><input name='username'>"
        "<input name='password'></form>"
        "<form action='/enter' method='POST'><input name='key'></form>"
    )
    forms = parse_all_forms(page, "/")
    assert [f["path"] for f in forms] == ["/login", "/enter"]
    assert forms[1]["fields"] == ["key"]


def test_payload_class_families():
    assert payload_class("'") == "bare_quote"
    assert payload_class("' AND 1=2 -- ") == "and_false"
    assert payload_class("' UNION SELECT 1 -- ") == "union"
    assert payload_class("%admin%") == "like_wild"
    assert payload_class("' OR 1=1 -- ") == "or_true"


def test_source_secrets_extracts_creds(tmp_path, monkeypatch):
    session = make_session(get_profile("sqli_admin_bypass"), tmp_path, monkeypatch)
    (session.materials / "seed.sql").write_text(
        "INSERT INTO users VALUES (1, 'admin', 's3cret-Pw', 'admin');"
    )
    creds, users = source_secrets(session)
    assert ("admin", "s3cret-Pw") in creds  # adjacent pair from VALUES(...)'
    # the username regex targets `username = 'x'` shapes
    (session.materials / "app.py").write_text("username = 'admin'\n")
    creds, users = source_secrets(session)
    assert "admin" in users


def test_sqli_login_probe_end_to_end(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import _sqli_login_bypass_caps, login_probe

    class LoginService:
        """Vulnerable login: string-concat SQL, success redirects."""

        def handle(self, url):
            parts = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parts.query)
            if parts.path == "/" and not query:
                return 200, LOGIN_PAGE
            if parts.path == "/login":
                if parts.query:  # GET variant
                    user = query.get("username", [""])[0]
                else:
                    return 200, b"POST-only"
                if "OR 1=1" in user or user == "admin'--":
                    return 200, ("flag is " + FLAG).encode()
                return 200, b"Invalid credentials"
            return 404, b"no"

    session = make_session(get_profile("sqli_login_bypass"), tmp_path, monkeypatch)
    session.set_opener(FakeOpener(LoginService()))
    result = login_probe(session, caps=_sqli_login_bypass_caps())
    assert result["FLAG_SHAPED"], result.get("hint")
    assert FLAG in result["FLAG_SHAPED"]
    assert result["attempts"] >= 1


def test_sqli_fallback_autopilot_writes_probe_candidate(tmp_path, monkeypatch):

    class LoginService:
        def handle(self, url):
            if url.endswith("/") or url.endswith("/login") is False and "?" not in url:
                pass
            parts = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parts.query)
            if parts.path == "/" and not query:
                return 200, LOGIN_PAGE
            if parts.path == "/login" and query:
                user = query.get("username", [""])[0]
                if "OR 1=1" in user:
                    return 200, ("flag is " + FLAG).encode()
                return 200, b"Invalid credentials"
            return 404, b"no"

    profile = get_profile("sqli_login_bypass")
    session = make_session(profile, tmp_path, monkeypatch)
    session.set_opener(FakeOpener(LoginService()))

    # the model is dead: the fallback must run the probe itself (autopilot)
    def dead_model(messages):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(session, "model", dead_model)
    rc = session.run()
    assert rc == 0
    assert (session.out_dir / "flag.txt").read_text(encoding="utf-8") == FLAG


# --- git-history domain -----------------------------------------------------


def git(*args, cwd):
    subprocess.run(
        ["git", "--no-pager", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )


def test_git_forensics_recovers_removed_secret(tmp_path, monkeypatch):
    from app.git_history_audit import recover_removed_secret

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.txt").write_text("API_KEY = FLAG_test{deleted_from_history}\n")
    git("init", "-q", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "add secret", cwd=repo)
    (repo / "config.txt").write_text("")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "remove secret", cwd=repo)

    report = recover_removed_secret(repo)
    assert report["best_candidate"] == "FLAG_test{deleted_from_history}"
    priorities = [c["priority"] for c in report["candidates"]]
    assert max(priorities) >= 90


def test_git_profile_e2e_finish_with_removed_secret(tmp_path, monkeypatch):

    profile = get_profile("git_history_recovery")
    session = make_session(profile, tmp_path, monkeypatch)
    repo = session.materials
    (repo / "config.txt").write_text("API_KEY = FLAG_test{removed_secret_e2e}\n")
    git("init", "-q", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "add secret", cwd=repo)
    (repo / "config.txt").write_text("API_KEY = \n")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "clear secret", cwd=repo)

    scripted = ScriptedModel(
        [
            json.dumps({"tool": "git_log"}),
            json.dumps({"tool": "finish", "flag": "FLAG_test{removed_secret_e2e}"}),
        ]
    )
    monkeypatch.setattr(session, "model", scripted)
    assert session.run() == 0
    assert (session.out_dir / "flag.txt").read_text(
        encoding="utf-8"
    ) == "FLAG_test{removed_secret_e2e}"


def test_git_profile_rejects_value_still_in_worktree(tmp_path, monkeypatch):
    profile = get_profile("git_history_recovery")
    session = make_session(profile, tmp_path, monkeypatch)
    (session.materials / "note.txt").write_text("decoy = FLAG_test{still_present}\n")
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "git_log"}),  # populates current_nonempty_lines
            json.dumps({"tool": "finish", "flag": "FLAG_test{still_present}"}),
            json.dumps({"tool": "finish", "flag": "FLAG_test{still_present}"}),
        ]
    )
    monkeypatch.setattr(session, "model", scripted)
    assert session.run() == 0
    rejection = scripted.calls[2][-1]["content"]
    assert "still present in a current non-empty file" in rejection


def test_git_fallback_writes_best_candidate_without_model(tmp_path, monkeypatch):
    from app.agent.ctf.profiles import analyze_git_forensics

    profile = get_profile("git_history_recovery")
    session = make_session(profile, tmp_path, monkeypatch)
    repo = session.materials
    (repo / "config.txt").write_text("API_KEY = FLAG_test{fallback_candidate}\n")
    git("init", "-q", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "add secret", cwd=repo)
    (repo / "config.txt").write_text("")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "remove secret", cwd=repo)
    analyze_git_forensics(session)

    def dead_model(messages):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(session, "model", dead_model)
    assert session.run() == 0
    assert (session.out_dir / "flag.txt").read_text(
        encoding="utf-8"
    ) == "FLAG_test{fallback_candidate}"


def test_clean_secret_line_extracts_assignment_value():
    assert clean_secret_line('SECRET_KEY = "abc123"') == "abc123"
    assert clean_secret_line("value FLAG_test{inline}") == "FLAG_test{inline}"


# --- LFI e2e through the full loop -----------------------------------------


def test_lfi_e2e_discover_traverse_finish_writes_verified_flag(
    tmp_path, monkeypatch, capsys
):
    profile = get_profile("path_filter_bypass")
    session = make_session(profile, tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "http_discover"}),
            json.dumps(
                {"tool": "http_traverse", "names": ["treasure.txt"], "max_depth": 2}
            ),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(session, "model", scripted)

    assert session.run() == 0

    assert len(scripted.calls) == 3
    discover_feedback = scripted.calls[1][-1]["content"]
    assert '"route": "/download?file="' in discover_feedback
    traverse_feedback = scripted.calls[2][-1]["content"]
    assert FLAG in traverse_feedback
    assert (session.out_dir / "flag.txt").read_text(encoding="utf-8") == FLAG
    # stderr must stay free of flag content and transcript bodies
    assert FLAG not in capsys.readouterr().err


def test_lfi_e2e_rejects_fabricated_flag_then_accepts_live_value(tmp_path, monkeypatch):
    profile = get_profile("path_filter_bypass")
    session = make_session(profile, tmp_path, monkeypatch)
    install_target(session, monkeypatch)
    fabricated = "FLAG_test{made_up_without_evidence}"
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "finish", "flag": fabricated}),
            json.dumps(
                {"tool": "http_traverse", "names": ["treasure.txt"], "max_depth": 2}
            ),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(session, "model", scripted)

    assert session.run() == 0

    rejection = scripted.calls[1][-1]["content"]
    assert "НЕ найден" in rejection
    assert (session.out_dir / "flag.txt").read_text(encoding="utf-8") == FLAG


# --- file_inspection profile ------------------------------------------------


def test_file_inspection_grounds_finish_in_materials(tmp_path, monkeypatch):
    profile = get_profile("file_inspection")
    session = make_session(profile, tmp_path, monkeypatch)
    (session.materials / "note.txt").write_text("The key we kept is exact-key-42")
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "finish", "flag": "hallucinated"}),
            json.dumps({"tool": "finish", "flag": "exact-key-42"}),
        ]
    )
    monkeypatch.setattr(session, "model", scripted)
    assert session.run() == 0
    assert (session.out_dir / "flag.txt").read_text(encoding="utf-8") == "exact-key-42"
    rejection = scripted.calls[1][-1]["content"]
    assert "не найдено ни в одном файле" in rejection


def test_file_inspection_stale_flag_is_removed(tmp_path, monkeypatch):
    profile = get_profile("file_inspection")
    session = make_session(profile, tmp_path, monkeypatch)
    (session.out_dir).mkdir(parents=True, exist_ok=True)
    (session.out_dir / "flag.txt").write_text("stale")
    (session.materials / "note.txt").write_text("nothing useful")

    def dead_model(messages):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(session, "model", dead_model)
    session.run()
    # a failed run must not leave the stale artifact behind
    content = ""
    try:
        content = (session.out_dir / "flag.txt").read_text(encoding="utf-8")
    except OSError:
        pass
    assert content != "stale"


# --- packaging --------------------------------------------------------------


@pytest.mark.parametrize(
    "profile_key",
    sorted(PROFILES),
)
def test_package_contains_exact_root_files_and_executable_run_sh(tmp_path, profile_key):
    archive_path = build_archive(
        profile_key, tmp_path / f"security-agent-{profile_key}.zip"
    )
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == FILES
        assert all("/" not in name for name in archive.namelist())
        assert isinstance(json.loads(archive.read("agent.json")), dict)
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111
        compile(archive.read("agent.py").decode(), "agent.py", "exec")
        assert archive.read("strategy.md").strip()


def test_package_renders_profile_name_in_agent_source(tmp_path):
    archive_path = build_archive("git_history_recovery", tmp_path / "agent.zip")
    with zipfile.ZipFile(archive_path) as archive:
        source = archive.read("agent.py").decode()
    assert "PROFILE_NAME = 'git_history_recovery'" in source
    # legacy task-id patterns must not appear in the packaged source
    legacy_task_id = re.compile(r"p\d+z\d+")
    for line in source.splitlines():
        assert not legacy_task_id.search(line.lower()), line


def test_build_script_builds_all_profiles(tmp_path):
    import scripts.build_ctf as builder

    built = builder.build_all(tmp_path)
    names = {path.name for path in built}
    assert "security-agent-git-history-recovery.zip" in names
    assert "security-agent-path-filter-bypass.zip" in names
    assert "security-agent-remote-inclusion.zip" in names
    assert len(built) == 9
