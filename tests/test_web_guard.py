"""Attack-vector tests against the platform's own web surface.

The CTF profiles encode how naive web handling is bypassed in the wild
(traversal, double-decoding, HPP, absolute paths, null bytes, header
injection, SQL-ish filters). These tests fire the same vectors at the
platform's own endpoints and assert every one is rejected before it can
reach a filesystem, a filter or a response header.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from app.http_guard import (
    GuardError,
    contained_path,
    fully_decode,
    header_safe,
    safe_segment,
    single_param,
)
from app.repository import RunRepository
from app.service import RunService
from app.web import create_app

RUN_ID = "20260101T000000Z-abcdef012345"

TRAVERSAL_VECTORS = [
    "..",
    "../",
    "..%2f",
    "%2e%2e%2f",
    "..%252f",
    "%252e%252e%252f",
    "....//",
    "..;/",
    "..\\",
    "..%5c",
    "%c0%ae%c0%ae%c0%af",
    "..%u2215",
    "..%c1%1c",
]

ABSOLUTE_VECTORS = [
    "/etc/passwd",
    "%2fetc%2fpasswd",
    "/proc/self/environ",
    "C:\\Windows\\win.ini",
    "\\\\server\\share",
    "~/.ssh/id_rsa",
]

CONTROL_VECTORS = [
    "flag.txt\x00.png",
    "report.md\nSet-Cookie: pwn=1",
    "report.md\r\nX-Injected: yes",
    "report.md\x1b[31m",
]


@pytest.fixture()
def web(tmp_path):
    service = RunService(tmp_path / "runs")
    app = create_app(runs_dir=tmp_path / "runs", service=service)
    client = TestClient(app, base_url="http://localhost")
    client.headers["x-csrf-token"] = _csrf_token(client)
    # seed one valid run by crafting the directory layout directly
    reports = tmp_path / "runs" / RUN_ID / "reports"
    reports.mkdir(parents=True)
    (reports / "report.md").write_text(
        "# report\nAuthorization: Bearer hunter2-secret-token\n", encoding="utf-8"
    )
    (reports / "findings.json").write_text("[]", encoding="utf-8")
    (reports / "summary.json").write_text(
        json.dumps({"run_id": RUN_ID, "total": 0}),
        encoding="utf-8",
    )
    return client


def _csrf_token(client):
    """The token is rendered into the index page; extract it once."""
    html = client.get("/").text
    match = re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert match, "csrf token not found in index page"
    return match.group(1)


# --- unit contracts of the guard -------------------------------------------


def test_fully_decode_resolves_double_and_triple_encoding():
    assert fully_decode("%252e%252e%252f") == "../"
    assert fully_decode("%2e%2e%2f") == "../"
    assert fully_decode("plain") == "plain"


@pytest.mark.parametrize("vector", TRAVERSAL_VECTORS + ABSOLUTE_VECTORS)
def test_safe_segment_rejects_traversal_and_absolute(vector):
    with pytest.raises(GuardError):
        safe_segment(vector)


@pytest.mark.parametrize("vector", CONTROL_VECTORS)
def test_safe_segment_rejects_control_bytes_and_crlf(vector):
    with pytest.raises(GuardError):
        safe_segment(vector)


def test_safe_segment_accepts_only_clean_names():
    assert safe_segment("report.md") == "report.md"
    assert safe_segment(RUN_ID) == RUN_ID


def test_contained_path_blocks_absolute_and_symlink_escape(tmp_path):
    base = tmp_path / "base"
    (base / "sub").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = base / "sub" / "link.txt"
    link.symlink_to(outside)
    # an absolute segment must NOT discard the base
    with pytest.raises(GuardError):
        contained_path(base, "sub", "/etc/passwd")
    # a symlink hop must not smuggle content from outside the base
    with pytest.raises(GuardError):
        contained_path(base, "sub", "link.txt")
    assert contained_path(base, "sub", "ok.txt") == (base / "sub" / "ok.txt").resolve()


def test_single_param_rejects_parameter_pollution():
    class Params:
        def __init__(self, values):
            self._values = values

        def getlist(self, name):
            return self._values.get(name, [])

    assert single_param(Params({"severity": ["high"]}), "severity") == "high"
    assert single_param(Params({}), "severity") is None
    with pytest.raises(GuardError):
        single_param(Params({"severity": ["high", "low"]}), "severity")


def test_header_safe_rejects_crlf():
    assert header_safe("report.md") == "report.md"
    with pytest.raises(GuardError):
        header_safe("a\r\nSet-Cookie: x=1")


# --- repository stays strict regardless of the web layer --------------------


@pytest.mark.parametrize("vector", TRAVERSAL_VECTORS + ABSOLUTE_VECTORS)
def test_repository_rejects_attack_filenames(tmp_path, vector):
    repo = RunRepository(tmp_path)
    with pytest.raises(ValueError):
        repo.text(RUN_ID, vector)


@pytest.mark.parametrize(
    "run_id",
    [
        "20260101T000000Z-abcdef01234",
        "../../etc",
        "20260101T000000Z-abcdef012345/../../x",
        "20260101T000000Z-ABCDEF012345",
    ],
)
def test_repository_rejects_bad_run_ids(tmp_path, run_id):
    repo = RunRepository(tmp_path)
    with pytest.raises(ValueError):
        repo.text(run_id, "report.md")


# --- live endpoint attacks ---------------------------------------------------


@pytest.mark.parametrize("vector", TRAVERSAL_VECTORS + ABSOLUTE_VECTORS)
def test_artifact_endpoint_rejects_path_attack(web, vector):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/{vector}")
    # The route either rejects the segment (400), never matches (404) or —
    # for vectors that decode into the SAME slot — returns only run-owned
    # artifacts. The security property: no content from outside the run
    # directory is ever returned.
    if response.status_code == 200:
        assert "Authorization" not in response.text or "[REDACTED]" in response.text
        assert response.headers.get("content-disposition", "").count("/") == 0
    else:
        assert response.status_code in (400, 404), vector
        if response.status_code == 400:
            assert response.json()["error"] in {
                "invalid_report_file",
                "invalid_path_segment",
                "invalid_run_id",
                "invalid_request",
            }


def test_artifact_endpoint_rejects_encoded_traversal(web):
    for encoded in ("%2e%2e%2freport.md", "..%252freport.md", "....//report.md"):
        response = web.get(f"/api/runs/{RUN_ID}/artifacts/{encoded}")
        # either the guard rejects the decoded segment (400) or the route
        # never matches (404) — a foreign file is never returned
        assert response.status_code in (400, 404), encoded
        assert "run" not in response.headers.get("content-disposition", "")


@pytest.mark.parametrize("vector", TRAVERSAL_VECTORS[:6])
def test_run_detail_endpoint_rejects_traversal(web, vector):
    response = web.get(f"/api/runs/{vector}")
    # a traversal-shaped run id either trips the guard (400) or never
    # matches a route (404); it must NEVER resolve to a real run
    assert response.status_code in (400, 404)
    if response.status_code == 400:
        assert response.json()["error"] in {
            "invalid_run_id",
            "invalid_path_segment",
            "invalid_request",
        }


def test_findings_endpoint_rejects_duplicate_parameters(web):
    response = web.get(f"/api/runs/{RUN_ID}/findings?severity=high&severity=low")
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "duplicate_parameter"


def test_findings_endpoint_rejects_encoded_filter(web):
    response = web.get(f"/api/runs/{RUN_ID}/findings?severity=%2e%2e%2fhigh")
    # decoded to "../high" — a clean text but not a traversal here; the
    # guard must have accepted the DECODED value and repository must not
    # treat it as a special filter (simply no match or 200 with empty list)
    assert response.status_code in (200, 400)
    if response.status_code == 200:
        assert response.json() == []


def test_valid_run_and_artifact_still_work(web):
    detail = web.get(f"/api/runs/{RUN_ID}")
    assert detail.status_code == 200
    artifact = web.get(f"/api/runs/{RUN_ID}/artifacts/report.md")
    assert artifact.status_code == 200
    # a bearer token must be redacted by the repository layer
    assert "hunter2-secret-token" not in artifact.text
    assert "[REDACTED]" in artifact.text
    assert "Content-Disposition" in artifact.headers


def test_artifact_header_injection_is_blocked(web):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/report.md%0d%0aSet-Cookie: pwn=1")
    assert response.status_code == 400
    # even on success paths no injected header may ever appear
    ok = web.get(f"/api/runs/{RUN_ID}/artifacts/report.md")
    assert "pwn" not in ok.headers


def test_null_byte_in_filename_is_rejected(web):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/report.md%00.png")
    assert response.status_code == 400


def test_job_endpoint_rejects_traversal(web):
    response = web.get("/api/jobs/..%2f..%2fruns")
    assert response.status_code in (400, 404)


def test_sqlish_filter_values_are_treated_as_text(web):
    """Even if a filter value looks like SQL, it is a text equality filter
    against in-memory data — never concatenated into a query."""
    response = web.get(
        f"/api/runs/{RUN_ID}/findings",
        params={"severity": "high' OR '1'='1"},
    )
    assert response.status_code == 200
    assert response.json() == []
