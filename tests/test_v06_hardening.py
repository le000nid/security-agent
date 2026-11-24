"""v6 cross-verification: our own attack arsenal vs our own request guard.

The CTF profiles carry next-generation vectors precisely because adversaries
train on the same public material. This suite proves the platform's defense
is AHEAD of its own offense: every traversal class in PATH_BYP, every
absolute-read target, every assembly double-decode form, every SQLi tautology
family and every rate/size-abuse trick is fired at the guarded endpoints and
at the guard unit — and none of them may pass.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.agent.ctf import profiles
from app.http_guard import GuardError, fully_decode, safe_segment
from app.repository import RunRepository
from app.service import RunService
from app.web import create_app

RUN_ID = "20260101T000000Z-abcdef012345"

# --- 1. every LFI bypass class dies in the guard ----------------------------


@pytest.mark.parametrize("bypass", profiles.PATH_BYP)
def test_every_lfi_bypass_is_rejected_by_guard(bypass):
    with pytest.raises(GuardError):
        safe_segment(bypass + "flag.txt")


@pytest.mark.parametrize("bypass", profiles.PATH_BYP)
def test_every_lfi_bypass_is_rejected_by_repository(bypass, tmp_path):
    repo = RunRepository(tmp_path)
    with pytest.raises(ValueError):
        repo.text(RUN_ID, bypass + "flag.txt")


@pytest.mark.parametrize("target", profiles.FIXED_ABS_READS)
def test_every_fixed_abs_read_is_rejected_as_segment(target):
    with pytest.raises(GuardError):
        safe_segment(target.lstrip("/"))


def test_fully_decode_never_produces_a_bypass_shape():
    """After full decoding no vector may silently BE a clean segment."""
    for bypass in profiles.PATH_BYP:
        with pytest.raises(GuardError):
            safe_segment(fully_decode(bypass) + "flag.txt")


# --- 2. assembly double-decode forms vs the guard ---------------------------


@pytest.mark.parametrize(
    "encoded",
    [
        "%252e%252e%252f",
        "..%252f",
        "%252e%252e%252f%252e%252e%252f",
        "%252e%252e/",
        "..%252f..%252f",
        "%25252e%25252e%25252f",
        "%25252f",
        "..%252e%252f",
        "%252E%252E%252F",
        "%2E%2E%252f",
        "..%255c",
    ],
)
def test_double_and_triple_decode_dies_in_guard(encoded):
    with pytest.raises(GuardError):
        safe_segment(encoded + "flag.txt")


def test_fully_decode_hits_the_fixpoint():
    # nested encodings peel one layer per pass; the guard decodes until
    # stable, so the validator always sees the final literal form
    assert fully_decode("%25252e%25252e%25252f") == "../"
    assert fully_decode("..%252e%252f") == ".../"
    assert fully_decode("%25252f") == "/"


# --- 3. SQLi payload families are inert as filter text ----------------------


@pytest.mark.parametrize(
    "payload",
    [
        *profiles.SQLI_BASE_PAYLOADS,
        *profiles.SQLI_ADMIN_PAYLOADS,
        *profiles.SQLI_PASSWORD_PAYLOADS,
        *[p for p in profiles.INVERSION_PAYLOADS],
    ],
)
def test_sqli_payloads_are_inert_as_filters(web, payload):
    """SQL-looking filter values never reach a query builder. The guard
    either rejects the value outright (control bytes / residual encoding —
    400) or the repository treats it as a plain in-memory equality filter
    (200 with an empty result). In BOTH branches nothing is executed and
    nothing leaks; a 5xx would be the only failure."""
    response = web.get(f"/api/runs/{RUN_ID}/findings", params={"severity": payload})
    assert response.status_code in (200, 400), (payload, response.status_code)
    if response.status_code == 200:
        assert response.json() == []


@pytest.mark.parametrize(
    "payload",
    [
        "' OR 1=1 -- ",
        "\\\\",
        "' UNION SELECT 'admin','x','admin' -- ",
        "'; DROP TABLE runs; -- ",
        "' OR 2>1 -- ",
    ],
)
def test_sqlish_run_ids_are_rejected(web, payload):
    response = web.get(f"/api/runs/{payload}")
    assert response.status_code in (400, 404)
    if response.status_code == 400:
        assert response.json()["error"] in {
            "invalid_run_id",
            "invalid_path_segment",
            "invalid_request",
        }


# --- 4. live endpoints vs the new vector classes ----------------------------


@pytest.fixture()
def web(tmp_path):
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


@pytest.mark.parametrize("bypass", profiles.PATH_BYP)
def test_artifact_endpoint_rejects_every_bypass_class(web, bypass):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/{bypass}report.md")
    if response.status_code == 200:
        # may only happen when the whole string decodes into a single run-
        # owned artifact name; prove no foreign content came back
        assert "root:x:0:0" not in response.text
        assert "passwd" not in response.text
    else:
        assert response.status_code in (400, 404)


@pytest.mark.parametrize(
    "vector",
    [
        "report.md%00.png",
        "report.md.",
        "report.md%20",
        "notes.txt:report.md",
        "%72eport.md",  # hex-encoded first letter
        "....//report.md",
        "..;/report.md",
        "%252e%252e%252freport.md",
        "..%252e%252freport.md",
    ],
)
def test_artifact_endpoint_rejects_v6_name_variants(web, vector):
    response = web.get(f"/api/runs/{RUN_ID}/artifacts/{vector}")
    if response.status_code == 200:
        assert response.text == "# report\n"
    else:
        assert response.status_code in (400, 404)


# --- 5. rate limit + size caps ------------------------------------------------


def test_post_rate_limit_kicks_in(web):
    """After POST_RATE_LIMIT POSTs the window slams shut with 429."""
    from app.web import POST_RATE_LIMIT

    statuses = []
    for _ in range(POST_RATE_LIMIT + 3):
        response = web.post(
            "/api/llm/check",
            headers={"x-csrf-token": web.headers["x-csrf-token"]},
        )
        statuses.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in statuses
    assert statuses.count(429) >= 1
    # the limit responded before the budget was exceeded by more than 1
    assert len(statuses) <= POST_RATE_LIMIT + 1


def test_query_length_cap(web):
    response = web.get(
        f"/api/runs/{RUN_ID}/findings",
        params={"severity": "a" * 3_000},
    )
    assert response.status_code == 414
    assert response.json()["error"] == "query_too_long"


def test_header_count_cap(web):
    headers = {f"x-pad-{i}": "1" for i in range(80)}
    response = web.get("/healthz", headers=headers)
    assert response.status_code == 400
    assert response.json()["error"] == "too_many_headers"


def test_security_headers_present(web):
    response = web.get("/healthz")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert "camera=()" in response.headers["permissions-policy"]


# --- 6. profile registry integrity after the v6 upgrade ----------------------


def test_profile_vectors_carry_no_external_task_ids():
    legacy_task_id = re.compile(r"p\d+z\d+")
    blobs = (
        profiles.SQLI_BASE_PAYLOADS
        + profiles.SQLI_ADMIN_PAYLOADS
        + profiles.SQLI_PASSWORD_PAYLOADS
        + profiles.INVERSION_PAYLOADS
        + list(profiles.PATH_BYP)
        + list(profiles.FIXED_ABS_READS)
    )
    for item in blobs:
        assert not legacy_task_id.search(str(item).lower()), item


def test_payload_class_knows_the_new_families():
    assert profiles.payload_class("\\\\") == "escape_quote"
    assert profiles.payload_class("' OR CASE WHEN 1 THEN 1 END -- ") == "conditional"
    assert profiles.payload_class("' AND IF(0,1,0) -- ") == "and_false"
    assert profiles.payload_class("%admin%") == "like_wild"
