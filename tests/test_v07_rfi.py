"""v7 cross-verification: the RFI arsenal vs our own request guard.

Every URI-scheme vector the remote_inclusion profile fires (all 31 scheme
templates, all 10 filter-bypass obfuscations, all 17 SSRF targets) is
pointed at no_scheme()/the guarded endpoints — and must be rejected. The
same suite proves the http_include matrix runner behaves (route discovery,
canary hit, FLAG_SHAPED short-circuit) against a local fake target.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from app.agent.ctf import profiles
from app.agent.ctf.profiles import (
    INCLUDE_SCHEMES,
    PROFILES,
    SCHEME_FILTER_BYPASSES,
    SSRF_TARGETS,
    tool_http_include,
)
from app.http_guard import GuardError, no_scheme
from app.service import RunService
from app.web import create_app
from tests.test_v06_hardening import RUN_ID


@pytest.fixture()
def web(tmp_path):
    """Same guarded app fixture as the v6 suite (local copy, no shadowing)."""
    service = RunService(tmp_path / "runs")
    app = create_app(runs_dir=tmp_path / "runs", service=service)
    client = TestClient(app, base_url="http://localhost")
    html = client.get("/").text
    match = re.search(r'name="csrf-token" content="([^"]+)"', html)
    client.headers["x-csrf-token"] = match.group(1)
    reports = tmp_path / "runs" / RUN_ID / "reports"
    reports.mkdir(parents=True)
    (reports / "report.md").write_text("# report\n", encoding="utf-8")
    (reports / "findings.json").write_text("[]", encoding="utf-8")
    (reports / "summary.json").write_text(
        '{"run_id": "%s", "total": 0}' % RUN_ID, encoding="utf-8"
    )
    return client


# --- 1. every scheme template is rejected after placeholder rendering ----


def _render_schemes():
    """Expand every {res}/{abs}/{host} placeholder, mirroring the engine."""
    res = ["flag.txt", "notes.txt", "app.py"]
    abs_reads = [a.lstrip("/") for a in profiles.FIXED_ABS_READS[:8]]
    out = []
    for scheme in INCLUDE_SCHEMES:
        v = scheme.replace("{host}", "target:8000")
        if "{res}" in v:
            for r in res:
                out.append(v.replace("{res}", r))
        elif "{abs}" in v:
            for a in abs_reads:
                out.append(v.replace("{abs}", a))
        else:
            out.append(v)
    return out


@pytest.mark.parametrize("vector", _render_schemes())
def test_every_scheme_vector_is_rejected(vector):
    for form in (vector, _double_encode(vector)):
        with pytest.raises(GuardError):
            no_scheme(form)


def _double_encode(v: str) -> str:
    import urllib.parse

    return urllib.parse.quote(v, safe="")


# --- 2. every filter-bypass obfuscation is rejected -------------------------


def _concrete_scheme_vectors(limit=40):
    """Concrete inclusion vectors, same expansion as the engine."""
    res = ["flag.txt", "notes.txt"]
    abs_reads = [a.lstrip("/") for a in profiles.FIXED_ABS_READS[:8]]
    out = []
    for scheme in INCLUDE_SCHEMES:
        v = scheme.replace("{host}", "target:8000")
        if "{res}" in v:
            for r in res:
                out.append(v.replace("{res}", r))
        elif "{abs}" in v:
            for a in abs_reads:
                out.append(v.replace("{abs}", a))
        else:
            out.append(v)
    return list(dict.fromkeys(out))[:limit]


@pytest.mark.parametrize("idx", range(len(SCHEME_FILTER_BYPASSES)))
def test_every_scheme_bypass_is_rejected(idx):
    tmpl, fn = SCHEME_FILTER_BYPASSES[idx]
    if tmpl == "{scheme_vec}":
        bases = _concrete_scheme_vectors()
    else:
        bases = _render_one_template(tmpl)
    fired = 0
    for base in bases:
        try:
            obfuscated = fn(base)
        except Exception:
            continue
        if not obfuscated:
            continue
        fired += 1
        with pytest.raises(GuardError):
            no_scheme(obfuscated)
        with pytest.raises(GuardError):
            no_scheme(_double_encode(obfuscated))
    assert fired, "obfuscation produced no concrete vector"


def _render_one_template(tmpl: str):
    res = ["flag.txt"]
    host = "target:8000"
    out = []
    v = tmpl.replace("{host}", host)
    if "{res}" in v:
        for r in res:
            out.append(v.replace("{res}", r))
    elif "{abs}" in v:
        out.append(v.replace("{abs}", "etc/passwd"))
    elif v.strip():
        out.append(v)
    return out or [tmpl]


# --- 3. every SSRF target is rejected --------------------------------------


@pytest.mark.parametrize("target", SSRF_TARGETS)
def test_every_ssrf_target_is_rejected(target):
    with pytest.raises(GuardError):
        no_scheme(target)


# --- 4. live endpoints reject scheme payloads ------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "php://filter/convert.base64-encode/resource=flag.txt",
        "data://text/plain;base64,PD9waHAgPz4=",
        "http://169.254.169.254/latest/meta-data/",
        "//localhost/flag.txt",
        "expect://cat%20flag.txt",
        "file:///etc/passwd",
    ],
)
def test_findings_filters_reject_scheme_payloads(web, payload):
    for param in ("severity", "source", "category"):
        response = web.get(f"/api/runs/{RUN_ID}/findings", params={param: payload})
        assert response.status_code == 400, (param, payload)
        assert response.json()["error"] == "invalid_uri_scheme"


@pytest.mark.parametrize(
    "payload",
    [
        "php%3a%2f%2ffilter%2fresource%3dflag.txt",
        "a%3a%2f%2fb",
        "data%3atext%2fplain%2cX",
    ],
)
def test_artifact_endpoint_rejects_encoded_schemes(web, payload):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/{payload}")
    assert response.status_code in (400, 404)


# --- 5. legit values still flow --------------------------------------------


@pytest.mark.parametrize(
    "value", ["high", "low", "sast", "dast", "notes.txt", "report.md"]
)
def test_legit_filter_values_pass(web, value):
    response = web.get(f"/api/runs/{RUN_ID}/findings", params={"severity": value})
    assert response.status_code == 200
    assert response.json() == []


# --- 6. the http_include matrix runner against a fake vulnerable target ----


class _IncludeHandler(BaseHTTPRequestHandler):
    """Mimics a service whose /download?file= reaches include()."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query)
        value = (q.get("file") or [""])[0]
        # the vulnerable branch: php://filter returns base64 of the file
        if value.startswith("php://filter") and "flag.txt" in value:
            import base64

            body = base64.b64encode(b"FLAG{rfi_canary_123}").decode()
            self._send(200, body)
        elif value.startswith("data:"):
            self._send(200, "RFI_PROBE data uri executed")
        elif "169.254.169.254" in value:
            self._send(200, "ami-id: ami-0123456789abcdef0")
        else:
            self._send(404, "not found")

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def fake_include_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _IncludeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % server.server_address[1]
    server.shutdown()


class _FakeSession:
    """Minimal Session stand-in: only the API tool_http_include uses."""

    def __init__(self, target):
        self.target = target
        self.route = "/download?file="
        self.routes = []

    def public_names(self):
        return ["notes.txt"]

    def http_get(self, path, method="GET"):
        return {"path": path, "sha1": "home"}

    def http_batch(self, action):
        import urllib.parse
        import urllib.request

        results = []
        for p in action.get("paths", []):
            try:
                url = self.target + ("/" + p if p.startswith("?") else p)
                with urllib.request.urlopen(url, timeout=5) as r:
                    data = r.read(100_000)
                    results.append(
                        {
                            "path": p,
                            "status": r.status,
                            "preview": data[:400].decode("utf-8", "replace"),
                        }
                    )
            except urllib.error.HTTPError as e:
                results.append({"path": p, "status": e.code, "preview": ""})
            except Exception as e:
                results.append({"path": p, "error": str(e)[:120]})
        return results

    def distinct(self, results, homepage_sha=None):
        out = []
        for r in results:
            if r.get("status") == 200 and r.get("preview"):
                out.append(
                    {
                        "path": r["path"],
                        "preview": r["preview"],
                        "flag_shaped_values": _flag_shaped(r["preview"]),
                    }
                )
        return out


def _flag_shaped(text):
    import re

    m = re.search(r"FLAG\{[^}]+\}", text)
    if m:
        return [m.group()]
    try:
        import base64

        decoded = base64.b64decode(text.strip(), validate=False)
        found = re.findall(rb"FLAG\{[^}]+\}", decoded)
        return [f.decode() for f in found]
    except Exception:
        return []


@pytest.mark.local_net
def test_http_include_finds_filter_chain_flag(fake_include_target):
    session = _FakeSession(fake_include_target)
    out = tool_http_include(
        session, {"names": ["flag.txt"], "route": "/download?file="}
    )
    assert "FLAG_SHAPED" in out, out.get("hint")
    assert out["FLAG_SHAPED"][0]["flag_shaped_values"] == ["FLAG{rfi_canary_123}"]


def test_http_include_survives_total_failure():
    class _DeadSession(_FakeSession):
        def http_batch(self, action):
            return [
                {"path": p, "status": 404, "preview": ""}
                for p in action.get("paths", [])
            ]

    out = tool_http_include(_DeadSession("http://127.0.0.1:1"), {"names": ["flag.txt"]})
    assert "FLAG_SHAPED" not in out
    assert out["scheme_hits"] == []
    assert "hint" in out


# --- 7. profile registry integrity ----------------------------------------


def test_remote_inclusion_profile_registered():
    profile = PROFILES["remote_inclusion"]
    assert profile.name == "remote_inclusion"
    assert "http_include" in profile.tool_descriptions
    assert "php://filter" in profile.hint
    assert "169.254.169.254" in profile.hint


def test_rfi_vectors_carry_no_brand_mentions():
    forbidden = ("vega", "p1z1", "p2z3", "p3z2", "p3z3", "p4z2", "p4z4", "p4z8")
    blobs = (
        list(INCLUDE_SCHEMES)
        + list(SSRF_TARGETS)
        + [t for t, _ in SCHEME_FILTER_BYPASSES]
    )
    for item in blobs:
        low = str(item).lower()
        assert not any(w in low for w in forbidden), item
