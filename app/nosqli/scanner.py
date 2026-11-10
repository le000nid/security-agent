"""Four bounded requests per contract; compare record identity and field values."""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

import httpx

from app.models import Finding
from app.nosqli.profiles import Profile, load_profiles
from app.validation import validate_target_url

MAX_RESPONSE_BYTES = 1_048_576
MAX_RECORDS = 200


class Inconclusive(ValueError):
    """An observation does not satisfy the configured comparison contract."""


def at_path(value, path: list[str]):
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise Inconclusive("response_shape")
        value = value[key]
    return value


def request_document(profile: Profile, value) -> dict:
    root = current = {}
    for key in profile.field_path[:-1]:
        current[key] = {}
        current = current[key]
    current[profile.field_path[-1]] = value
    return root


def records(document, profile: Profile) -> dict[tuple[str, str], str]:
    rows = at_path(document, profile.records_path)
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise Inconclusive("record_limit_or_shape")
    result = {}
    for row in rows:
        identity = at_path(row, profile.id_path)
        value = at_path(row, profile.value_path)
        if (
            type(identity) not in (str, int)
            or not str(identity)
            or len(str(identity)) > 256
            or type(value) is not str
            or len(value) > 256
        ):
            raise Inconclusive("invalid_record")
        key = (type(identity).__name__, str(identity))
        if key in result:
            raise Inconclusive("duplicate_record_id")
        result[key] = value
    return result


def _strict_json(body: bytes):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Inconclusive("duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise Inconclusive("invalid_json")

    try:
        return json.loads(
            body, object_pairs_hook=unique_pairs, parse_constant=invalid_constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Inconclusive("invalid_json") from None


def observe(client: httpx.Client, url: str, profile: Profile, value):
    document = request_document(profile, value)
    kwargs = (
        {"json": document}
        if profile.method == "POST"
        else {
            "params": {
                profile.query_parameter: json.dumps(document, separators=(",", ":"))
            }
        }
    )
    started = monotonic()
    with client.stream(profile.method, url, **kwargs) as response:
        status = response.status_code
        if status in (400, 422):
            return status, None
        if status != 200:
            raise Inconclusive(f"http_{status}")
        content_type = (
            response.headers.get("content-type", "").split(";")[0].strip().lower()
        )
        if content_type != "application/json" and not content_type.endswith("+json"):
            raise Inconclusive("content_type")
        chunks, size = [], 0
        for chunk in response.iter_bytes():
            if monotonic() - started > 15:
                raise Inconclusive("response_deadline")
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise Inconclusive("response_too_large")
            chunks.append(chunk)
        return status, records(_strict_json(b"".join(chunks)), profile)


def compare(baseline, probe, control, repeated, expected: str) -> str:
    if not baseline or any(value != expected for value in baseline.values()):
        raise Inconclusive("baseline_does_not_match_contract")
    if baseline != repeated:
        raise Inconclusive("unstable_baseline")
    if control:
        raise Inconclusive("control_not_empty")
    if probe is None:
        return "rejected"
    if (
        baseline.keys() < probe.keys()
        and all(probe[key] == value for key, value in baseline.items())
        and any(value != expected for value in probe.values())
    ):
        return "confirmed"
    return "not_detected"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    outcomes: list[dict] = field(default_factory=list)


def scan_profiles(
    target: str,
    selected: list[str],
    raw: Path,
    *,
    transport: httpx.BaseTransport | None = None,
) -> ScanResult:
    target = validate_target_url(target)
    parts = urlsplit(target)
    if parts.path not in ("", "/") or parts.query:
        raise ValueError("nosqli_profiles_require_target_origin")
    profiles = load_profiles(selected)
    result = ScanResult()
    # No redirects or environment proxy routing. One local origin per run.
    with httpx.Client(
        timeout=httpx.Timeout(5.0),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
        headers={"Accept": "application/json"},
    ) as client:
        for profile in profiles:
            url = target.rstrip("/") + profile.path
            entry = {
                "profile": profile.id,
                "method": profile.method,
                "path": profile.path,
            }
            observations = []
            try:
                marker = "nosqli-missing-" + uuid.uuid4().hex
                for value in (
                    profile.baseline,
                    {"$ne": marker},
                    marker,
                    profile.baseline,
                ):
                    observations.append(observe(client, url, profile, value))
                baseline, probe, control, repeated = [item[1] for item in observations]
                if any(observations[i][0] != 200 for i in (0, 2, 3)):
                    raise Inconclusive("baseline_or_control_rejected")
                entry["status"] = compare(
                    baseline, probe, control, repeated, profile.baseline
                )
            except Inconclusive as exc:
                entry.update(status="inconclusive", reason=str(exc))
            except httpx.HTTPError:
                entry.update(status="inconclusive", reason="transport_error")
            entry["http_statuses"] = [item[0] for item in observations]
            entry["record_counts"] = [
                len(item[1]) if item[1] is not None else None for item in observations
            ]
            entry["record_digests"] = [
                hashlib.sha256(
                    json.dumps(sorted(item[1].items()), ensure_ascii=True).encode()
                ).hexdigest()
                if item[1] is not None
                else None
                for item in observations
            ]
            if entry["status"] == "inconclusive":
                result.warnings.append(
                    f"nosqli_inconclusive:{profile.id}:{entry['reason']}"
                )
            if entry["status"] == "confirmed":
                evidence = json.dumps(entry, ensure_ascii=True, sort_keys=True)
                result.findings.append(
                    Finding(
                        id="nosqli-"
                        + hashlib.sha256((url + profile.id).encode()).hexdigest()[:16],
                        title="NoSQL operator changes query result scope",
                        source="DAST",
                        tool="nosqli-http",
                        category="nosqli",
                        normalized_category="injection",
                        severity="medium",
                        confidence="high",
                        location=url,
                        evidence=evidence,
                        description=(
                            "An operator object returned a strict superset of baseline records, "
                            "including a different field value. The missing-value control was empty "
                            "and the repeated baseline was stable. This confirms filter manipulation "
                            "under the configured API contract; it does not identify the database engine."
                        ),
                        recommendation="Accept scalar values only; construct database filters from validated, allowlisted fields.",
                        raw_output_ref=f"{raw.as_posix()}#{len(result.outcomes) + 1}",
                    )
                )
            result.outcomes.append(entry)
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(
        json.dumps({"profiles": result.outcomes}, indent=2) + "\n", encoding="utf-8"
    )
    return result
