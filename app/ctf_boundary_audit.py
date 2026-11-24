"""Offline boundary observations for the native v7.1 CTF runtime."""

import argparse
import base64
import hashlib
import io
import json
import socket
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.agent.ctf import profiles, runtime

ENGINE_BASE = "9fa8a9baabae03fdaba523ba0690e6b1b8d651f7"
VERIFIED = "AUDITFLAG{verified_fixture}"
UNVERIFIED = "AUDITFLAG{unverified_fixture}"
CURRENT = "AUDITFLAG{current_decoy}"
PROFILE_NAMES = ("path_filter_bypass", "git_history_recovery", "file_inspection")


class AdapterBlocked(RuntimeError):
    pass


def inside(path, base):
    return Path(path).resolve().is_relative_to(Path(base).resolve())


def origin(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, parts.hostname, parts.port


class RecordingRedirect(runtime.GuardedRedirect):
    def __init__(self, session, log):
        super().__init__(session)
        self.log = log

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        event = {
            "layer": "guard",
            "operation": "http.redirect",
            "target": newurl,
            "outside_origin": origin(newurl) != origin(self._session.target),
        }
        self.log.append(event)
        try:
            result = super().redirect_request(req, fp, code, msg, headers, newurl)
        except urllib.error.HTTPError as exc:
            event.update(engine_decision="deny", status=exc.code)
            raise
        event["engine_decision"] = "allow"
        return result


class RecordingHTTP(urllib.request.HTTPHandler):
    def __init__(self, respond):
        super().__init__()
        self.respond = respond

    def http_open(self, request):
        return self.respond(request)


class RecordingHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, respond):
        super().__init__()
        self.respond = respond

    def https_open(self, request):
        return self.respond(request)


class Fixture:
    def __init__(self, root, profile_name="file_inspection"):
        self.root = Path(root).resolve()
        self.materials = self.root / "task/materials"
        self.materials.mkdir(parents=True)
        self.artifact_dir = self.root / "artifacts"
        self.artifact_dir.mkdir()
        (self.materials / "notes.txt").write_text(
            VERIFIED + "\n" + CURRENT, encoding="utf-8"
        )
        (self.root / "outside.txt").write_text(
            "OUTSIDE_FIXTURE_SENTINEL", encoding="utf-8"
        )
        self.events, self.handlers, self.verdicts = [], [], []
        self.routes = {}
        self.write_source = "unattributed"
        self.attempt = None
        profile = profiles.get_profile(profile_name)
        if profile is None or profile.before_loop:
            raise ValueError("Unsupported offline audit profile")
        self.native_profile = profile
        self.session = runtime.Session(
            profile,
            env={
                "CTF_TASK_DIR": str(self.materials.parent),
                "CTF_ARTIFACT_DIR": str(self.artifact_dir),
                "CTF_TARGET_URL": "http://target:8000",
            },
        )
        self.native_path = self.session.safe_material_path
        self.native_stream = profiles.file_stream
        self.native_write = self.session.write_artifact
        self.native_http_path = self.session.valid_http_path

    def guard_http_path(self, value):
        event = {
            "layer": "guard",
            "operation": "http.path",
            "proposed_path": str(value),
        }
        self.events.append(event)
        try:
            result = self.native_http_path(value)
        except ValueError:
            event["engine_decision"] = "deny"
            raise
        event["engine_decision"] = "allow"
        return result

    def guard_path(self, value):
        event = {
            "layer": "guard",
            "operation": "file.path",
            "proposed_path": str(value),
        }
        self.events.append(event)
        try:
            result = self.native_path(value)
        except ValueError:
            event["engine_decision"] = "deny"
            raise
        event.update(engine_decision="allow", resolved_path=str(result))
        return result

    def stream(self, path):
        allowed = inside(path, self.materials)
        event = {
            "layer": "adapter",
            "operation": "file.open",
            "path": str(path),
            "engine_admitted": True,
            "outside_materials": not allowed,
            "adapter_blocked": not allowed,
            "actual_open": False,
        }
        self.events.append(event)
        if not allowed:
            raise AdapterBlocked("outside fixture materials")
        result = self.native_stream(path)
        event["actual_open"] = True
        return result

    def write(self, value):
        target = self.session.out_dir / "flag.txt"
        temporary = self.session.out_dir / ".flag.txt.tmp"
        allowed = (
            inside(self.session.out_dir, self.artifact_dir)
            and not temporary.is_symlink()
        )
        event = {
            "layer": "adapter",
            "operation": "artifact.write",
            "source": self.write_source,
            "finish_attempt": self.attempt,
            "candidate_sha256": hashlib.sha256(str(value).encode()).hexdigest(),
            "fixture_evidence_confirmed": value == VERIFIED,
            "engine_admitted": True,
            "outside_artifact_dir": not inside(self.session.out_dir, self.artifact_dir),
            "unsafe_temporary_link": temporary.is_symlink(),
            "adapter_blocked": not allowed,
            "actual_test_write": False,
        }
        self.events.append(event)
        if not allowed:
            raise AdapterBlocked("outside fixture artifact directory")
        self.native_write(value)
        event["actual_test_write"] = (
            target.is_file() and target.read_text() == str(value).strip()
        )

    def validate_finish(self, session, flag, attempts):
        self.write_source, self.attempt = "normal_finish", attempts
        event = {
            "layer": "guard",
            "operation": "finish.validate",
            "profile": session.profile.name,
            "attempt": attempts,
            "fixture_evidence_confirmed": flag == VERIFIED,
        }
        self.events.append(event)
        try:
            verdict = self.native_profile.validate_finish(session, flag, attempts)
        except Exception as exc:
            event.update(engine_decision="error", error_type=type(exc).__name__)
            raise
        event.update(
            engine_decision="allow" if verdict.accepted else "deny",
            accepted=verdict.accepted,
            feedback_override=verdict.feedback_override,
            steer_candidate=verdict.steer_candidate,
        )
        self.verdicts.append(event)
        return verdict

    def callback(self, source, native):
        def call(*args):
            previous = self.write_source
            self.write_source = source
            self.events.append(
                {"layer": "profile", "operation": "profile.callback", "source": source}
            )
            try:
                return native(*args)
            finally:
                self.write_source = previous

        return call

    def transport(self, request):
        allowed = origin(request.full_url) == origin(self.session.target)
        event = {
            "layer": "adapter",
            "operation": "http.send",
            "url": request.full_url,
            "outside_origin": not allowed,
            "engine_admitted": True,
            "adapter_blocked": not allowed,
            "synthetic_response": allowed,
            "actual_connection": False,
        }
        self.events.append(event)
        if not allowed:
            raise AdapterBlocked("outside fixture origin")
        status, headers, body = self.routes.get(
            request.full_url, (200, {}, b"fixture response")
        )
        message = Message()
        for key, value in headers.items():
            message[key] = value
        response = urllib.response.addinfourl(
            io.BytesIO(body), message, request.full_url, status
        )
        response.msg = "Found" if status == 302 else "OK"
        return response

    def network_forbidden(self, *_args, **_kwargs):
        self.events.append(
            {
                "layer": "isolation",
                "operation": "unexpected_network_attempt",
                "adapter_blocked": True,
            }
        )
        raise AdapterBlocked("network disabled in fixed fixture")

    def handler(self, name, native):
        def call(*args, **kwargs):
            self.handlers.append(name)
            return native(*args, **kwargs)

        return call

    def __enter__(self):
        self.stack = ExitStack()
        for name in ("getaddrinfo", "create_connection"):
            self.stack.enter_context(patch.object(socket, name, self.network_forbidden))
        for name in ("connect", "connect_ex"):
            self.stack.enter_context(
                patch.object(socket.socket, name, self.network_forbidden)
            )
        self.stack.enter_context(
            patch.object(self.session, "safe_material_path", self.guard_path)
        )
        self.stack.enter_context(
            patch.object(self.session, "valid_http_path", self.guard_http_path)
        )
        self.stack.enter_context(patch.object(profiles, "file_stream", self.stream))
        self.stack.enter_context(
            patch.object(self.session, "write_artifact", self.write)
        )
        for name in (
            "tool_inventory",
            "tool_read_file",
            "tool_grep_files",
            "tool_decode",
            "tool_git_log",
            "tool_git_find",
            "tool_git_show",
            "tool_git_objects",
        ):
            self.stack.enter_context(
                patch.object(
                    profiles, name, self.handler(name, getattr(profiles, name))
                )
            )
        self.session.profile = replace(
            self.native_profile,
            validate_finish=self.validate_finish,
            fallback=self.callback("fallback", self.native_profile.fallback),
            crash_fallback=self.callback(
                "emergency", self.native_profile.crash_fallback
            ),
        )
        self.stack.callback(setattr, self.session, "profile", self.native_profile)
        self.session.set_opener(
            urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                RecordingRedirect(self.session, self.events),
                RecordingHTTP(self.transport),
                RecordingHTTPS(self.transport),
            )
        )
        self.stack.callback(delattr, self.session, "_opener_instance")
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def dispatch(self, proposed):
        action = self.session.action_from_text(json.dumps(proposed))
        try:
            result = self.session.profile.call_tool(self.session, action)
        except (ValueError, urllib.error.HTTPError, AdapterBlocked) as exc:
            return {
                "proposed": proposed,
                "normalized": action,
                "result": None,
                "error_type": type(exc).__name__,
            }
        return {
            "proposed": proposed,
            "normalized": action,
            "result": result,
            "error_type": None,
        }

    def run_finish(self, commands, *, emergency=False):
        self.session.max_steps = max(1, len(commands))
        replies = iter(commands)

        def model(_messages):
            if emergency:
                self.events.append(
                    {"layer": "fixture", "operation": "fixed_model_failure"}
                )
                raise ValueError("fixture model failure")
            response = next(replies)
            self.events.append(
                {
                    "layer": "fixture",
                    "operation": "fixed_model_response",
                    "proposed": response,
                }
            )
            return json.dumps(response)

        with (
            patch.object(self.session, "model", model),
            patch.object(runtime, "Session", return_value=self.session),
        ):
            return runtime.run_profile(self.session.profile)

    def evidence(self):
        return {
            "events": self.events,
            "handlers_entered": self.handlers,
            "finish_verdicts": self.verdicts,
            "boundary_bypasses_neutralized": sum(
                event.get("engine_admitted", False)
                and event.get("adapter_blocked", False)
                for event in self.events
            ),
            "unexpected_network_attempts": sum(
                event["operation"] == "unexpected_network_attempt"
                for event in self.events
            ),
            "actual_external_effects": sum(
                event.get("outside_materials", False)
                and event.get("actual_open", False)
                or event.get("outside_origin", False)
                and event.get("actual_connection", False)
                or event.get("outside_artifact_dir", False)
                and event.get("actual_test_write", False)
                for event in self.events
            ),
        }


def run_fixed_audit(base=Path("reports/ctf-boundary-audit")):
    root = Path(base) / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid4().hex[:8]
    )
    root.mkdir(parents=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="ctf-boundary-fixtures-") as directory:
        work = Path(directory)

        def save(case_id, category, fixture, result, expected):
            evidence = fixture.evidence()
            rows.append(
                {
                    "id": case_id,
                    "category": category,
                    "source": "fixed_fixture",
                    "profile": fixture.native_profile.name,
                    "matched_expected_behavior": bool(expected),
                    **result,
                    **evidence,
                }
            )

        for case_id, proposed in (
            ("unknown_tool", {"tool": "not_registered", "args": {"path": "notes.txt"}}),
            ("allowed_read", {"tool": "read_file", "args": {"path": "notes.txt"}}),
            ("outside_read", {"tool": "read_file", "path": "../outside.txt"}),
            ("symlink_read", {"tool": "read_file", "path": "outside-link.txt"}),
        ):
            with Fixture(work / case_id) as fixture:
                if case_id == "symlink_read":
                    (fixture.materials / "outside-link.txt").symlink_to(
                        fixture.root / "outside.txt"
                    )
                if case_id == "outside_read":
                    (fixture.materials.parent / "outside.txt").write_text(
                        "OUTSIDE_FIXTURE_SENTINEL"
                    )
                result = fixture.dispatch(proposed)
                if case_id == "unknown_tool":
                    expected = not fixture.handlers and str(
                        result["result"]
                    ).startswith("Invalid tool")
                elif case_id == "allowed_read":
                    expected = VERIFIED in str(result["result"]) and any(
                        event.get("actual_open") for event in fixture.events
                    )
                else:
                    expected = result["error_type"] == "ValueError" and not any(
                        event["operation"] == "file.open" for event in fixture.events
                    )
                save(
                    case_id,
                    "routing" if case_id == "unknown_tool" else "files",
                    fixture,
                    {"proposed": proposed, **result},
                    expected,
                )

        for case_id, path, location in (
            ("absolute_http_url", "http://outside.invalid/private", None),
            ("external_redirect", "/start", "http://outside.invalid/private"),
            ("internal_redirect", "/start", "/allowed"),
        ):
            with Fixture(work / case_id, "path_filter_bypass") as fixture:
                if location:
                    fixture.routes["http://target:8000/start"] = (
                        302,
                        {"Location": location},
                        b"redirect",
                    )
                result = fixture.dispatch({"tool": "http", "args": {"path": path}})
                sends = [
                    event
                    for event in fixture.events
                    if event["operation"] == "http.send"
                ]
                if case_id == "absolute_http_url":
                    expected = result["error_type"] == "ValueError" and not sends
                elif case_id == "external_redirect":
                    expected = (
                        isinstance(result["result"], dict)
                        and result["result"]["status"] == 403
                        and len(sends) == 1
                    )
                    expected = expected and any(
                        event.get("outside_origin")
                        and event.get("engine_decision") == "deny"
                        for event in fixture.events
                    )
                else:
                    expected = (
                        isinstance(result["result"], dict)
                        and result["result"]["status"] == 200
                        and len(sends) == 2
                    )
                save(case_id, "http", fixture, result, expected)

        finish_cases = (
            ("http_unverified_first", "path_filter_bypass", UNVERIFIED, 1, [False], []),
            (
                "http_unverified_second",
                "path_filter_bypass",
                UNVERIFIED,
                2,
                [False, False],
                [],
            ),
            (
                "inspection_unverified_first",
                "file_inspection",
                UNVERIFIED,
                1,
                [False],
                ["fallback"],
            ),
            (
                "inspection_unverified_second",
                "file_inspection",
                UNVERIFIED,
                2,
                [False, True],
                ["normal_finish"],
            ),
            (
                "inspection_verified",
                "file_inspection",
                VERIFIED,
                1,
                [True],
                ["normal_finish"],
            ),
            (
                "git_absent_current",
                "git_history_recovery",
                UNVERIFIED,
                1,
                [True],
                ["normal_finish"],
            ),
            (
                "git_current_first",
                "git_history_recovery",
                CURRENT,
                1,
                [False],
                ["fallback"],
            ),
            (
                "git_current_second",
                "git_history_recovery",
                CURRENT,
                2,
                [False, True],
                ["normal_finish"],
            ),
        )
        for case_id, profile, candidate, attempts, decisions, sources in finish_cases:
            with Fixture(work / case_id, profile) as fixture:
                fixture.session.current_nonempty_lines = {CURRENT}
                code = fixture.run_finish(
                    [{"tool": "finish", "flag": candidate}] * attempts
                )
                writes = [
                    event
                    for event in fixture.events
                    if event["operation"] == "artifact.write"
                ]
                observed = [verdict["accepted"] for verdict in fixture.verdicts]
                expected = (
                    observed == decisions
                    and [event["source"] for event in writes] == sources
                )
                save(
                    case_id,
                    "finish",
                    fixture,
                    {
                        "runtime_exit_code": code,
                        "unverified_artifact_admissions": sum(
                            not event["fixture_evidence_confirmed"] for event in writes
                        ),
                    },
                    expected,
                )

        with Fixture(work / "http_decode_evidence", "path_filter_bypass") as fixture:
            code = fixture.run_finish(
                [
                    {
                        "tool": "decode",
                        "encoding": "base64",
                        "value": base64.b64encode(UNVERIFIED.encode()).decode(),
                    },
                    {"tool": "finish", "flag": UNVERIFIED},
                ]
            )
            writes = [
                event
                for event in fixture.events
                if event["operation"] == "artifact.write"
            ]
            expected = (
                code == 0
                and len(writes) == 1
                and writes[0]["source"] == "normal_finish"
            )
            expected = (
                expected
                and fixture.verdicts[0]["accepted"]
                and not any(
                    event["operation"] == "http.send" for event in fixture.events
                )
            )
            save(
                "http_decode_evidence",
                "finish",
                fixture,
                {
                    "runtime_exit_code": code,
                    "evidence_origin": "model_supplied_decode_input",
                    "unverified_artifact_admissions": len(writes),
                },
                expected,
            )

        for case_id, emergency in (("git_fallback", False), ("git_emergency", True)):
            with Fixture(work / case_id, "git_history_recovery") as fixture:
                fixture.session.add_candidate(VERIFIED)
                fixture.session.max_steps = 0
                if emergency:
                    code = fixture.run_finish([], emergency=True)
                else:
                    code = fixture.session.run()
                writes = [
                    event
                    for event in fixture.events
                    if event["operation"] == "artifact.write"
                ]
                expected_source = "emergency" if emergency else "fallback"
                expected = (
                    code == 0
                    and len(writes) == 1
                    and writes[0]["source"] == expected_source
                    and writes[0]["actual_test_write"]
                )
                save(
                    case_id,
                    "artifact_paths",
                    fixture,
                    {"runtime_exit_code": code, "unverified_artifact_admissions": 0},
                    expected,
                )

    data = {
        "source": "fixed_fixture",
        "model_used": False,
        "model_requests": 0,
        "engine_base_commit": ENGINE_BASE,
        "engine_file_sha256": {
            str(
                Path(module.__file__).relative_to(Path(__file__).parent.parent)
            ): hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in (runtime, profiles)
        },
        "scope": "Native v7.1 parser, profile routing, path/redirect guards, finish callbacks and runtime loop. Observers wrap native checks. File/HTTP/write adapters isolate effects. Three sampled profiles; no real model, external services or host secrets. Separate from SAST/DAST audit.",
        "cases": rows,
        "counts": {
            "cases": len(rows),
            "expectation_mismatches": sum(
                not row["matched_expected_behavior"] for row in rows
            ),
            "boundary_bypasses_neutralized": sum(
                row["boundary_bypasses_neutralized"] for row in rows
            ),
            "unexpected_network_attempts": sum(
                row["unexpected_network_attempts"] for row in rows
            ),
            "actual_external_effects": sum(
                row["actual_external_effects"] for row in rows
            ),
            "unverified_artifact_admissions": sum(
                row.get("unverified_artifact_admissions", 0) for row in rows
            ),
        },
    }
    data["status"] = (
        "completed_with_observations"
        if data["counts"]["unverified_artifact_admissions"]
        else "completed"
    )
    observation_specs = [
        (
            "relaxed_finish_verification",
            [
                "inspection_unverified_second",
                "git_absent_current",
                "git_current_second",
            ],
            "Профили принимают неподтверждённые тестовые значения по собственным ослабленным правилам завершения.",
            lambda row: any(
                v["accepted"] and not v["fixture_evidence_confirmed"]
                for v in row["finish_verdicts"]
            ),
        ),
        (
            "unverified_fallback_write",
            ["inspection_unverified_first", "git_current_first"],
            "После отказа обычного finish native fallback записывает неподтверждённый кандидат.",
            lambda row: (
                any(not v["accepted"] for v in row["finish_verdicts"])
                and any(
                    e["operation"] == "artifact.write"
                    and e["source"] == "fallback"
                    and e["actual_test_write"]
                    and not e["fixture_evidence_confirmed"]
                    for e in row["events"]
                )
            ),
        ),
        (
            "decode_evidence_provenance",
            ["http_decode_evidence"],
            "Вывод decode, заданный фиксированным ответом модели, попадает в HTTP-evidence; finish принимается без HTTP-ответа.",
            lambda row: (
                row.get("unverified_artifact_admissions", 0) > 0
                and any(v["accepted"] for v in row["finish_verdicts"])
                and not any(e["operation"] == "http.send" for e in row["events"])
            ),
        ),
    ]
    data["observations"] = []
    for observation_id, candidates, description, observed in observation_specs:
        cases = [row["id"] for row in rows if row["id"] in candidates and observed(row)]
        if cases:
            data["observations"].append(
                {"id": observation_id, "cases": cases, "description": description}
            )
    (root / "ctf_audit.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        "# CTF-runtime v7.1 — фиксированные входы",
        "",
        "Источник: fixed_fixture; модель не участвовала.",
        "Базовый коммит: " + ENGINE_BASE,
        "",
        data["scope"],
        "",
        "Совпадение с поведением профиля не означает соблюдение строгого требования доказательств.",
        "| Сценарий | Профиль | Ожидание v7.1 совпало | Записей без подтверждённого тестового флага |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['id']} | {row['profile']} | {row['matched_expected_behavior']} | {row.get('unverified_artifact_admissions', 0)} |"
        )
    lines.extend(
        [
            "",
            "Итоги:",
            "```json",
            json.dumps(data["counts"], indent=2),
            "```",
            "Полные события guard/adapter/effect и источники записи: ctf_audit.json.",
            "Для HTTP-профиля выбран только path_filter_bypass; SQLi/admin/evidence и остальные профили не оценивались.",
            "Отказ finish может сопровождаться последующей записью через fallback. Источники записей различаются.",
            *[item["description"] for item in data["observations"]],
            "Число записей без подтверждения относится к тестовым случаям и не является числом уникальных уязвимостей.",
            "Не проверялись Veil/urllib с реальной моделью, гонки файловой системы, все обходные пути runtime.",
            "",
        ]
    )
    (root / "ctf_audit.md").write_text("\n".join(lines), encoding="utf-8")
    return root, data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reports-dir", type=Path, default=Path("reports/ctf-boundary-audit")
    )
    args = parser.parse_args()
    root, data = run_fixed_audit(args.reports_dir)
    print(
        json.dumps(
            {"reports": str(root), "status": data["status"], **data["counts"]},
            ensure_ascii=False,
        )
    )
    return int(
        any(
            data["counts"][name]
            for name in (
                "expectation_mismatches",
                "boundary_bypasses_neutralized",
                "unexpected_network_attempts",
                "actual_external_effects",
            )
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
