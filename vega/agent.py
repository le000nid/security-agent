#!/usr/bin/env python3
"""Self-contained VEGA export: LLM proposes, validator checks, fixed tool executes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

MAX_STEPS = 25
MAX_OBSERVATION_CHARS = 12000
MAX_RESPONSE_BYTES = 65536
TARGET_ORIGIN = "http://target:8000"
ALLOWED_ACTIONS = {
    "LIST_FILES",
    "READ_FILE",
    "SEARCH_FILES",
    "GIT_LOG",
    "GIT_SHOW",
    "HTTP_REQUEST",
    "WRITE_FLAG",
    "FINISH",
}
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class VegaError(RuntimeError):
    """Safe application-authored error; never contains provider secrets."""


def bounded(value: object, limit: int = MAX_OBSERVATION_CHARS) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _string(value: object, name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise VegaError(f"invalid_{name}")
    if "\x00" in value:
        raise VegaError(f"invalid_{name}")
    return value


def _integer(
    value: object, name: str, *, minimum: int, maximum: int, default: int
) -> int:
    if value is None:
        return default
    if type(value) is not int or not minimum <= value <= maximum:
        raise VegaError(f"invalid_{name}")
    return value


def _keys(
    arguments: object, allowed: set[str], required: set[str] | None = None
) -> dict:
    required = required or set()
    if not isinstance(arguments, dict):
        raise VegaError("invalid_arguments")
    if set(arguments) - allowed or not required <= set(arguments):
        raise VegaError("invalid_arguments")
    return arguments


def validate_action(payload: object) -> dict[str, Any]:
    """Strict action contract; unknown fields never reach an executor."""

    if not isinstance(payload, dict) or set(payload) != {
        "action",
        "arguments",
        "reason",
    }:
        raise VegaError("invalid_action_envelope")
    action = payload.get("action")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise VegaError("unknown_action")
    reason = _string(payload.get("reason"), "reason", maximum=1000).strip()
    arguments = payload.get("arguments")

    if action == "LIST_FILES":
        args = _keys(arguments, {"path"})
        result = {
            "path": _string(args["path"], "path", maximum=500)
            if "path" in args
            else "."
        }
    elif action == "READ_FILE":
        args = _keys(arguments, {"path", "offset", "max_chars"}, {"path"})
        result = {
            "path": _string(args["path"], "path", maximum=500),
            "offset": _integer(
                args.get("offset"), "offset", minimum=0, maximum=10_000_000, default=0
            ),
            "max_chars": _integer(
                args.get("max_chars"),
                "max_chars",
                minimum=1,
                maximum=MAX_OBSERVATION_CHARS,
                default=8000,
            ),
        }
    elif action == "SEARCH_FILES":
        args = _keys(arguments, {"query", "path", "max_results"}, {"query"})
        result = {
            "query": _string(args["query"], "query", maximum=300),
            "path": _string(args["path"], "path", maximum=500)
            if "path" in args
            else ".",
            "max_results": _integer(
                args.get("max_results"),
                "max_results",
                minimum=1,
                maximum=100,
                default=30,
            ),
        }
    elif action == "GIT_LOG":
        args = _keys(arguments, {"repo", "limit"})
        result = {
            "repo": _string(args["repo"], "repo", maximum=500)
            if "repo" in args
            else ".",
            "limit": _integer(
                args.get("limit"), "limit", minimum=1, maximum=50, default=20
            ),
        }
    elif action == "GIT_SHOW":
        args = _keys(arguments, {"repo", "commit", "path"}, {"commit"})
        result = {
            "repo": _string(args["repo"], "repo", maximum=500)
            if "repo" in args
            else ".",
            "commit": _string(args["commit"], "commit", maximum=100),
        }
        if "path" in args:
            result["path"] = _string(args["path"], "path", maximum=500)
    elif action == "HTTP_REQUEST":
        args = _keys(
            arguments, {"method", "path", "headers", "body"}, {"method", "path"}
        )
        method = _string(args["method"], "method", maximum=10).upper()
        if method not in HTTP_METHODS:
            raise VegaError("invalid_http_method")
        result = {
            "method": method,
            "path": _string(args["path"], "http_path", maximum=4000),
            "headers": args.get("headers", {}),
            "body": args.get("body", ""),
        }
    elif action == "WRITE_FLAG":
        args = _keys(arguments, {"value"}, {"value"})
        value = _string(args["value"], "flag", maximum=4096).strip()
        if "\n" in value or "\r" in value:
            raise VegaError("invalid_flag")
        result = {"value": value}
    else:
        _keys(arguments, set())
        result = {}
    return {"action": action, "arguments": result, "reason": reason}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Runtime:
    def __init__(
        self,
        task_dir: Path | None = None,
        artifact_dir: Path | None = None,
        *,
        http_opener=None,
    ) -> None:
        self.task_root = (task_dir or Path(os.getenv("VEGA_TASK_DIR", "."))).resolve(
            strict=True
        )
        candidate = self.task_root / "materials"
        self.materials_root = (
            candidate.resolve(strict=True) if candidate.is_dir() else self.task_root
        )
        configured_artifact = artifact_dir or (
            Path(os.environ["VEGA_CTF_ARTIFACT_DIR"])
            if "VEGA_CTF_ARTIFACT_DIR" in os.environ
            else None
        )
        if configured_artifact is None:
            raise VegaError("missing_artifact_directory")
        self.artifact_dir = configured_artifact.resolve(strict=False)
        self.flag_path = self.artifact_dir / "flag.txt"
        self.http_opener = http_opener or urllib.request.build_opener(NoRedirect())

    def resolve_task_path(self, value: str, *, directory: bool | None = None) -> Path:
        value = _string(value, "path", maximum=500)
        try:
            candidate = (self.task_root / value).resolve(strict=True)
        except OSError:
            raise VegaError("invalid_path") from None
        if not _inside(candidate, self.task_root):
            raise VegaError("path_outside_task")
        if directory is True and not candidate.is_dir():
            raise VegaError("not_a_directory")
        if directory is False and not candidate.is_file():
            raise VegaError("not_a_file")
        return candidate

    def resolve_repo(self, value: str) -> Path:
        value = _string(value, "repo", maximum=500)
        try:
            candidate = (self.materials_root / value).resolve(strict=True)
        except OSError:
            raise VegaError("invalid_repo") from None
        if not _inside(candidate, self.materials_root) or not candidate.is_dir():
            raise VegaError("repo_outside_materials")
        git_entry = candidate / ".git"
        if not git_entry.exists():
            raise VegaError("not_a_git_repository")
        if git_entry.is_dir():
            git_directory = git_entry.resolve(strict=True)
        elif git_entry.is_file():
            try:
                declaration = git_entry.read_text(
                    encoding="utf-8", errors="strict"
                ).strip()
            except (OSError, UnicodeError):
                raise VegaError("invalid_git_repository") from None
            if not declaration.casefold().startswith("gitdir:"):
                raise VegaError("invalid_git_repository")
            try:
                git_directory = (
                    candidate / declaration.split(":", 1)[1].strip()
                ).resolve(strict=True)
            except OSError:
                raise VegaError("invalid_git_repository") from None
        else:
            raise VegaError("invalid_git_repository")
        if not _inside(git_directory, self.materials_root):
            raise VegaError("git_metadata_outside_materials")
        return candidate

    def instruction(self) -> str:
        candidates = [
            self.task_root / "instruction.md",
            self.materials_root / "instruction.md",
            Path.cwd() / "instruction.md",
        ]
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if _inside(resolved, self.task_root) and resolved.is_file():
                return bounded(
                    resolved.read_text(encoding="utf-8", errors="replace"), 12000
                )
        return (
            "Исследовать доступные materials и при необходимости http://target:8000; "
            "найти фактический secret/flag, записать только его значение в artifact."
        )

    def inventory(self) -> str:
        base = self.materials_root
        entries = []
        for path in sorted(base.rglob("*")):
            if ".git" in path.parts:
                continue
            relative = path.relative_to(self.task_root).as_posix()
            entries.append(relative + ("/" if path.is_dir() else ""))
            if len(entries) >= 200:
                entries.append("...[inventory truncated]")
                break
        return "\n".join(entries) or "[materials empty]"

    def list_files(self, path: str) -> str:
        directory = self.resolve_task_path(path, directory=True)
        entries = []
        for child in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
            resolved = child.resolve(strict=True)
            if not _inside(resolved, self.task_root):
                continue
            entries.append(child.name + ("/" if child.is_dir() else ""))
            if len(entries) >= 200:
                entries.append("...[truncated]")
                break
        return "\n".join(entries) or "[empty directory]"

    def read_file(self, path: str, offset: int, max_chars: int) -> str:
        file = self.resolve_task_path(path, directory=False)
        if file.stat().st_size > 10_000_000:
            raise VegaError("file_too_large")
        text = file.read_text(encoding="utf-8", errors="replace")
        chunk = text[offset : offset + max_chars]
        suffix = "\n...[more available]" if offset + max_chars < len(text) else ""
        return chunk + suffix

    def search_files(self, query: str, path: str, max_results: int) -> str:
        root = self.resolve_task_path(path, directory=True)
        needle = query.casefold()
        matches = []
        for file in sorted(root.rglob("*")):
            if not file.is_file() or ".git" in file.parts:
                continue
            resolved = file.resolve(strict=True)
            if not _inside(resolved, self.task_root) or file.stat().st_size > 1_000_000:
                continue
            try:
                lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if needle in line.casefold():
                    relative = file.relative_to(self.task_root).as_posix()
                    matches.append(f"{relative}:{number}: {line[:500]}")
                    if len(matches) >= max_results:
                        return bounded("\n".join(matches))
        return bounded("\n".join(matches) or "[no matches]")

    def _git(self, repo: Path, arguments: list[str]) -> str:
        env = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "LANG")
            if key in os.environ
        }
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=repo,
                env=env,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise VegaError("git_execution_failed") from None
        output = completed.stdout if completed.returncode == 0 else completed.stderr
        return bounded(f"exit={completed.returncode}\n{output}")

    def git_log(self, repo: str, limit: int) -> str:
        return self._git(
            self.resolve_repo(repo),
            ["log", "--oneline", "--no-decorate", f"--max-count={limit}"],
        )

    def git_show(self, repo: str, commit: str, path: str | None = None) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@{}^~+-]{0,99}", commit):
            raise VegaError("invalid_commit")
        arguments = ["show", "--no-ext-diff", "--format=fuller", commit]
        if path is not None:
            pure = PurePosixPath(path.replace("\\", "/"))
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise VegaError("invalid_git_path")
            arguments.extend(["--", pure.as_posix()])
        return self._git(self.resolve_repo(repo), arguments)

    @staticmethod
    def validate_http_url(path: str) -> str:
        if any(ord(character) < 32 for character in path):
            raise VegaError("invalid_http_path")
        if path.startswith(("http://", "https://")):
            url = path
        else:
            if not path.startswith("/"):
                raise VegaError("invalid_http_path")
            url = TARGET_ORIGIN + path
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
        except ValueError:
            raise VegaError("invalid_http_url") from None
        if (
            parsed.scheme != "http"
            or parsed.hostname != "target"
            or port != 8000
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise VegaError("http_origin_not_allowed")
        return urllib.parse.urlunsplit(
            ("http", "target:8000", parsed.path or "/", parsed.query, "")
        )

    def http_request(
        self, method: str, path: str, headers: object, body: object
    ) -> str:
        url = self.validate_http_url(path)
        if not isinstance(headers, dict) or len(headers) > 20:
            raise VegaError("invalid_http_headers")
        safe_headers = {}
        denied = {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "proxy-authorization",
            "proxy-connection",
        }
        for name, value in headers.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name)
                or name.casefold() in denied
                or not isinstance(value, str)
                or len(value) > 1000
                or "\r" in value
                or "\n" in value
            ):
                raise VegaError("invalid_http_headers")
            safe_headers[name] = value
        if not isinstance(body, str) or len(body) > 32768:
            raise VegaError("invalid_http_body")
        data = body.encode() if body else None
        request = urllib.request.Request(
            url, data=data, headers=safe_headers, method=method
        )
        try:
            response = self.http_opener.open(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError, OSError):
            raise VegaError("http_request_failed") from None
        with response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > MAX_RESPONSE_BYTES
            raw = raw[:MAX_RESPONSE_BYTES]
            status = getattr(response, "status", response.getcode())
            selected_headers = []
            for index, (name, value) in enumerate(response.headers.items()):
                if index >= 30:
                    break
                selected_headers.append(f"{name}: {value[:1000]}")
            text = raw.decode("utf-8", errors="replace")
        return bounded(
            f"status={status}\n"
            + "\n".join(selected_headers)
            + "\n\n"
            + text
            + ("\n...[response truncated]" if truncated else "")
        )

    def write_flag(self, value: str) -> str:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.artifact_dir / ".flag.txt.tmp"
        temporary.write_text(value, encoding="utf-8", newline="")
        temporary.replace(self.flag_path)
        if (
            not self.flag_path.is_file()
            or not self.flag_path.read_text(encoding="utf-8").strip()
        ):
            raise VegaError("artifact_write_failed")
        return "Artifact written and verified as non-empty."

    def artifact_ready(self) -> bool:
        try:
            return bool(self.flag_path.read_text(encoding="utf-8").strip())
        except OSError:
            return False

    def execute(self, action: dict[str, Any]) -> str:
        name, args = action["action"], action["arguments"]
        if name == "LIST_FILES":
            return self.list_files(**args)
        if name == "READ_FILE":
            return self.read_file(**args)
        if name == "SEARCH_FILES":
            return self.search_files(**args)
        if name == "GIT_LOG":
            return self.git_log(**args)
        if name == "GIT_SHOW":
            return self.git_show(**args)
        if name == "HTTP_REQUEST":
            return self.http_request(**args)
        if name == "WRITE_FLAG":
            return self.write_flag(**args)
        if name == "FINISH":
            if not self.artifact_ready():
                raise VegaError("artifact_not_ready")
            return "Finished with verified artifact."
        raise VegaError("unknown_action")


class OpenAIClient:
    def __init__(self, *, transport=None) -> None:
        base = os.getenv("OPENAI_BASE_URL", "").strip().rstrip("/")
        key = os.getenv("OPENAI_API_KEY", "")
        model = os.getenv("LOCAL_AGENT_MODEL", "").strip()
        session = os.getenv("VEGA_AGENT_SESSION_ID", "").strip()
        if not base or not key or not model or not session:
            raise VegaError("missing_llm_runtime_configuration")
        try:
            parsed = urllib.parse.urlsplit(base)
        except ValueError:
            raise VegaError("invalid_llm_base_url") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise VegaError("invalid_llm_base_url")
        self.url = base + "/chat/completions"
        self.model = model
        self._key = key
        self._session = session
        self._transport = transport or urllib.request.urlopen

    def complete(self, messages: list[dict[str, str]]) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "response_format": {"type": "json_object"},
                "max_tokens": 1600,
            }
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "X-VEGA-Agent-Session": self._session,
            },
        )
        try:
            response = self._transport(request, timeout=45)
            with response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as exc:
            raise VegaError(f"llm_http_{exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise VegaError("llm_transport_error") from None
        if len(raw) > 2_000_000:
            raise VegaError("llm_response_too_large")
        try:
            envelope = json.loads(raw)
            choice = envelope["choices"][0]
            content = choice["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise VegaError("llm_response_invalid") from None
        if choice.get("finish_reason") != "stop" or not isinstance(content, str):
            raise VegaError("llm_response_incomplete")
        if not content.strip():
            raise VegaError("llm_response_empty")
        return content


def decode_action(content: str) -> dict[str, Any]:
    if not isinstance(content, str) or len(content) > 20000:
        raise VegaError("planner_json_invalid")
    try:
        payload = json.loads(content)
    except (ValueError, RecursionError):
        raise VegaError("planner_json_invalid") from None
    return validate_action(payload)


def plan(client: OpenAIClient, messages: list[dict[str, str]]) -> dict[str, Any]:
    try:
        return decode_action(client.complete(messages))
    except VegaError as first:
        if not str(first).startswith(("planner_", "invalid_", "unknown_action")):
            raise
        repair = [
            *messages,
            {
                "role": "user",
                "content": (
                    "Previous planner output was rejected by the local validator "
                    f"with safe code '{first}'. Return one complete JSON object with "
                    "exactly action, arguments and reason. Do not repeat the invalid output."
                ),
            },
        ]
        return decode_action(client.complete(repair))


def system_prompt(strategy: str) -> str:
    return (
        "You are a bounded evidence agent in an authorized VEGA task. "
        "LLM proposes; the application validates; a fixed tool executes. Never request shell "
        "commands or paths outside the task. Use only these actions: LIST_FILES, READ_FILE, "
        "SEARCH_FILES, GIT_LOG, GIT_SHOW, HTTP_REQUEST, WRITE_FLAG, FINISH. HTTP is restricted "
        "to http://target:8000, though unusual/encoded paths are allowed. Gather evidence, do "
        "not guess a flag, and write only the confirmed value. Return strict JSON with exactly "
        'this shape: {"action":"READ_FILE","arguments":{"path":"materials/file",'
        '"offset":0,"max_chars":8000},"reason":"why this evidence matters"}. '
        "Arguments must match the selected action; FINISH has an empty object.\n\nStrategy:\n"
        + strategy
    )


def run(runtime: Runtime, client: OpenAIClient, strategy: str) -> int:
    observations = [
        {
            "step": 0,
            "action": "INITIAL_CONTEXT",
            "observation": bounded(
                "TASK INSTRUCTION:\n"
                + runtime.instruction()
                + "\n\nMATERIALS INVENTORY:\n"
                + runtime.inventory()
            ),
        }
    ]
    system = system_prompt(strategy)
    for step in range(1, MAX_STEPS + 1):
        messages = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "step": step,
                        "steps_remaining": MAX_STEPS - step + 1,
                        "artifact_ready": runtime.artifact_ready(),
                        "observations": observations[-12:],
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        action = plan(client, messages)
        print(f"step {step}: {action['action']}", flush=True)
        try:
            observation = runtime.execute(action)
        except VegaError as exc:
            observation = f"Action rejected or failed with safe code: {exc}"
        observations.append(
            {
                "step": step,
                "action": action["action"],
                "observation": bounded(observation),
            }
        )
        if action["action"] == "FINISH" and runtime.artifact_ready():
            print("artifact ready", flush=True)
            return 0
    if runtime.artifact_ready():
        print("artifact ready at step limit", flush=True)
        return 0
    raise VegaError("step_limit_without_artifact")


def main() -> int:
    try:
        script_dir = Path(__file__).resolve().parent
        strategy = (script_dir / "strategy.md").read_text(
            encoding="utf-8", errors="replace"
        )
        return run(Runtime(), OpenAIClient(), bounded(strategy, 16000))
    except VegaError as exc:
        print(f"VEGA agent failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("VEGA agent failed: internal_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
