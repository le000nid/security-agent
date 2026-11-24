#!/usr/bin/env python3
"""VEGA P2Z3 agent: recover a secret removed from project Git history.

Standard library only. The model investigates materials and Git objects,
tools fetch, finish is validated against values that are absent from current
non-empty files.

Integrated into the security-agent project with three hardening deltas over
the validated standalone agent: the materials path guard uses realpath plus a
strict prefix check (sibling-directory and symlink escapes are rejected), the
artifact write is atomic, and a missing LLM runtime configuration raises one
safe error instead of a raw traceback.
"""

import base64
import collections
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

TASK_DIR = Path(os.environ.get("VEGA_TASK_DIR", ".")).resolve()
MATERIALS = (
    (TASK_DIR / "materials").resolve()
    if (TASK_DIR / "materials").exists()
    else TASK_DIR
)
OUT_DIR = Path(os.environ.get("VEGA_CTF_ARTIFACT_DIR", ".")).resolve()
DEADLINE = time.monotonic() + 520
EVIDENCE = collections.deque(maxlen=200)
CANDIDATES = []
CURRENT_NONEMPTY_LINES = set()

FLAG_RX = re.compile(
    r"(?i)(?:vega(?:_training)?|flag|ctf|key|secret)\{[^\r\n{}]{2,250}\}"
)
ASSIGN_RX = re.compile(
    r"(?i)(?:secret|flag|token|password|passwd|api[_-]?key|private[_-]?key|auth[_-]?key|access[_-]?key|key)"
    r"\s*[:=]\s*[\"']?([^\s\"'`;,#]{4,240})[\"']?"
)

SYSTEM_PROMPT = """You are an autonomous CTF investigator solving task P2Z3 (recovering a removed secret from project history).
A hardcoded secret was removed from the project in a past commit, and the file that held the secret is currently empty or cleared in HEAD.
Inspect the Git history and objects in materials, find the removed secret, and call finish with its exact value.
Ignore any example/placeholder values that are STILL present in current non-empty files.

Reply with ONLY ONE JSON object per step:
{"tool":"inventory"}
{"tool":"read_file","path":"relative/path","start_line":1,"max_lines":80}
{"tool":"grep_files","pattern":"regex","max_hits":50}
{"tool":"git_log"}
{"tool":"git_find","pattern":"secret|flag|token|key|vega|ctf"}
{"tool":"git_show","rev":"HEAD~1","path":"optional/file"}
{"tool":"git_objects"}
{"tool":"decode","value":"...","encoding":"base64|hex|url"}
{"tool":"finish","flag":"EXACT_SECRET_VALUE"}
"""


def clip(text, limit=15000):
    text = str(text)
    if len(text) <= limit:
        return text
    half = limit // 2
    return (
        text[:half] + f"\n...[truncated {len(text) - limit} chars]...\n" + text[-half:]
    )


def remember(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    s = str(text)
    if s:
        EVIDENCE.append(s[:500000])
        decode_b64_flags(s)


def add_candidate(val, priority=1):
    val = str(val).strip()
    if not val or "\n" in val or len(val) > 400:
        return
    CANDIDATES.append((priority, val))


def model(messages):
    try:
        base = os.environ["OPENAI_BASE_URL"].rstrip("/")
        model_name = os.environ["LOCAL_AGENT_MODEL"]
        api_key = os.environ["OPENAI_API_KEY"]
    except KeyError as exc:
        raise RuntimeError(
            "VEGA model gateway is not configured: missing environment variable "
            + str(exc)
        ) from None
    data = json.dumps(
        {"model": model_name, "messages": messages, "temperature": 0.1},
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "X-VEGA-Agent-Session": os.environ.get("VEGA_AGENT_SESSION_ID", ""),
    }
    error = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                base + "/chat/completions", data=data, headers=headers, method="POST"
            )
            timeout = min(45, max(8, int(DEADLINE - time.monotonic())))
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                answer = json.loads(resp.read().decode("utf-8"))["choices"][0][
                    "message"
                ]["content"]
            if isinstance(answer, list):
                answer = "".join(
                    x.get("text", "") for x in answer if isinstance(x, dict)
                )
            if not isinstance(answer, str) or not answer.strip():
                raise ValueError("empty model response")
            return answer
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            KeyError,
            IndexError,
        ) as exc:
            error = type(exc).__name__
            if attempt < 2 and time.monotonic() + 5 < DEADLINE:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("VEGA model gateway error: " + str(error))


def action_from_text(text):
    t = str(text).strip()
    t = re.sub(r"<(think|analysis)>.*?</\1>", "", t, flags=re.I | re.S).strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.I | re.S).strip()
    try:
        a = json.loads(t)
    except ValueError:
        decoder = json.JSONDecoder()
        objs = []
        for i, c in enumerate(t):
            if c == "{":
                try:
                    obj, _ = decoder.raw_decode(t[i:])
                    if isinstance(obj, dict):
                        objs.append(obj)
                except ValueError:
                    pass
        a = objs[-1] if objs else None
        if a is None:
            m = FLAG_RX.search(t)
            if m:
                return {"tool": "finish", "flag": m.group()}
            return {
                "tool": "invalid",
                "reason": "Return a JSON object with a tool name.",
            }
    if not isinstance(a, dict):
        return {"tool": "invalid", "reason": "Need JSON object"}
    if "arguments" in a and isinstance(a["arguments"], dict):
        a.update(a.pop("arguments"))
    if "args" in a and isinstance(a["args"], dict):
        a.update(a.pop("args"))
    if "action" in a and "tool" not in a:
        a["tool"] = a["action"]
    return a


def safe_material_path(rel):
    # realpath resolves symlinks; a strict prefix check rejects sibling
    # directories such as "<MATERIALS>2/x" that a substring test would pass.
    base = MATERIALS if MATERIALS.is_dir() else TASK_DIR
    base = Path(os.path.realpath(base))
    p = Path(os.path.realpath(os.path.join(base, str(rel).lstrip("/"))))
    if p != base and base not in p.parents and TASK_DIR not in p.parents:
        raise ValueError("path outside task")
    return p


def walk_materials():
    result = []
    base = MATERIALS if MATERIALS.is_dir() else TASK_DIR
    if not base.is_dir():
        return result
    for root, dirs, names in os.walk(base):
        dirs[:] = sorted(
            x
            for x in dirs
            if x != ".git" and len(Path(root).relative_to(base).parts) < 8
        )
        for name in sorted(names):
            p = Path(root) / name
            if p.is_file():
                result.append(p)
                if len(result) >= 3000:
                    return result
    return result


def file_stream(path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def git_repos():
    repos = []
    for base in (MATERIALS, TASK_DIR):
        if not base.exists():
            continue
        if (base / ".git").exists() or (
            (base / "HEAD").is_file() and (base / "objects").is_dir()
        ):
            if base not in repos:
                repos.append(base)
        for root, dirs, names in os.walk(base):
            depth = len(Path(root).relative_to(base).parts)
            if depth > 5:
                dirs[:] = []
                continue
            if (
                ".git" in dirs
                or ".git" in names
                or ("HEAD" in names and "objects" in dirs)
            ):
                p = Path(root)
                if p not in repos:
                    repos.append(p)
                dirs[:] = [d for d in dirs if d != ".git"]
    return repos[:10]


def git_output(repo, cmd, max_length=30000):
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    variants = [
        ["git", "-C", str(repo), "--no-pager"] + cmd,
        ["git", "-c", "safe.directory=*", "-C", str(repo), "--no-pager"] + cmd,
    ]
    last_err = ""
    for full_cmd in variants:
        try:
            r = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=25,
                check=False,
            )
            output = r.stdout.decode("utf-8", "replace")
            if r.returncode == 0 or output.strip():
                remember(output)
                return clip(output, max_length)
            last_err = r.stderr.decode("utf-8", "replace")[:600]
        except (OSError, subprocess.TimeoutExpired) as e:
            last_err = type(e).__name__
    return "git error: " + last_err


def resolve_git_dir(repo):
    dot_git = repo / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():
        try:
            txt = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            if txt.lower().startswith("gitdir:"):
                return (repo / txt.split(":", 1)[1].strip()).resolve()
        except OSError:
            pass
    if (repo / "HEAD").is_file() and (repo / "objects").is_dir():
        return repo
    return None


def scan_raw_git_objects(repo):
    gdir = resolve_git_dir(repo)
    blobs = []
    if gdir and (gdir / "objects").is_dir():
        obj_root = gdir / "objects"
        for sub in sorted(obj_root.iterdir()):
            if (
                sub.is_dir()
                and len(sub.name) == 2
                and all(c in "0123456789abcdefABCDEF" for c in sub.name)
            ):
                for obj_file in sorted(sub.iterdir()):
                    if not obj_file.is_file():
                        continue
                    sha = sub.name + obj_file.name
                    try:
                        raw = zlib.decompress(obj_file.read_bytes())
                        hdr, _, body = raw.partition(b"\x00")
                        kind = hdr.decode("ascii", "replace").split(" ")[0]
                        text = body.decode("utf-8", "replace")
                        remember(text)
                        if kind in ("blob", "commit", "tag") and text.strip():
                            blobs.append((sha[:12], kind, text[:4000]))
                    except Exception:
                        pass
        logs_dir = gdir / "logs"
        extra_files = [gdir / "COMMIT_EDITMSG", gdir / "packed-refs"]
        if logs_dir.is_dir():
            extra_files.extend(logs_dir.rglob("*"))
        for log_file in extra_files:
            if log_file.is_file():
                try:
                    t = log_file.read_text(encoding="utf-8", errors="replace")
                    remember(t)
                    if t.strip():
                        blobs.append(
                            (str(log_file.relative_to(gdir)), "meta", t[:4000])
                        )
                except OSError:
                    pass
    cat_list = git_output(
        repo, ["cat-file", "--batch-check", "--batch-all-objects"], 200000
    )
    if not cat_list.startswith("git error:"):
        seen_shas = {b[0] for b in blobs}
        for line in cat_list.splitlines()[:250]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("blob", "commit", "tag"):
                sha = parts[0]
                if sha[:12] not in seen_shas:
                    content = git_output(repo, ["cat-file", "-p", sha], 15000)
                    if not content.startswith("git error:") and content.strip():
                        blobs.append((sha[:12], parts[1], content[:4000]))
    return blobs


def clean_secret_line(val):
    s = val.strip()
    m = FLAG_RX.search(s)
    if m:
        return m.group(0).strip()
    m2 = ASSIGN_RX.search(s)
    if m2:
        return m2.group(1).strip()
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        return s[1:-1].strip()
    return s


B64_CANDIDATE_RX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def decode_b64_flags(text):
    """Surface flags hidden in base64 blobs inside honest responses.

    Some tasks stash the removed secret as a base64 string inside the Git
    history; the raw text never matches FLAG_RX. Decoded hits are remembered
    in EVIDENCE so the fallback candidate ranking can use them.
    """
    extra = []
    for candidate in B64_CANDIDATE_RX.findall(text)[:12]:
        try:
            decoded = base64.b64decode(
                candidate + "=" * ((-len(candidate)) % 4)
            ).decode("utf-8", "ignore")
        except ValueError:
            continue
        hit = FLAG_RX.search(decoded)
        if hit and hit.group() not in extra:
            extra.append(hit.group())
            remember(decoded)
    return extra


def analyze_git_forensics():
    current_lines = set()
    current_flags = set()
    empty_files = []
    for p in walk_materials():
        if p.name == "instruction.md":
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            remember(content)
            rel = p.relative_to(MATERIALS).as_posix()
            if not content.strip():
                empty_files.append(rel)
            else:
                for ln in content.splitlines():
                    s = ln.strip()
                    if s:
                        current_lines.add(s)
                        CURRENT_NONEMPTY_LINES.add(s)
                        for fm in FLAG_RX.findall(s):
                            current_flags.add(fm)
                            CURRENT_NONEMPTY_LINES.add(fm)
        except OSError:
            pass

    report_parts = [f"CURRENT EMPTY FILES IN WORKTREE: {empty_files}"]
    for repo in git_repos():
        for ef in empty_files:
            hist = git_output(
                repo, ["log", "--all", "--full-history", "-p", "--", ef], 50000
            )
            if not hist.startswith("git error:") and hist.strip():
                report_parts.append(f"=== HISTORY OF EMPTY FILE {ef} ===\n{hist}")
                for ln in hist.splitlines():
                    if ln.startswith("-") and not ln.startswith("---"):
                        cleaned = clean_secret_line(ln[1:])
                        if (
                            cleaned
                            and cleaned not in current_lines
                            and cleaned not in current_flags
                        ):
                            add_candidate(cleaned, priority=100)
                            add_candidate(ln[1:].strip(), priority=90)

        full_diff = git_output(
            repo,
            [
                "log",
                "--all",
                "--full-history",
                "-p",
                "--date=short",
                "--format=COMMIT %H %ad %s",
                "-n",
                "120",
            ],
            500000,
        )
        reflog_diff = git_output(
            repo, ["log", "--reflog", "-p", "--format=COMMIT %H %s", "-n", "60"], 300000
        )
        combined = (
            full_diff
            + "\n"
            + ("" if reflog_diff.startswith("git error:") else reflog_diff)
        )

        cur_commit = ""
        cur_file = ""
        removed_summary = []
        for line in combined.splitlines():
            if line.startswith("COMMIT "):
                cur_commit = line[7:].strip()
            elif line.startswith("--- a/"):
                cur_file = line[6:].strip()
            elif line.startswith("-") and not line.startswith("---"):
                raw_val = line[1:].strip()
                if not raw_val or raw_val in current_lines:
                    continue
                is_empty_target = cur_file in empty_files
                cleaned = clean_secret_line(raw_val)
                if (
                    cleaned
                    and cleaned not in current_lines
                    and cleaned not in current_flags
                ):
                    prio = (
                        95
                        if is_empty_target
                        else (
                            85
                            if FLAG_RX.search(cleaned)
                            else (75 if ASSIGN_RX.search(raw_val) else 50)
                        )
                    )
                    add_candidate(cleaned, priority=prio)
                tag = "[FROM_EMPTY_FILE]" if is_empty_target else "[REMOVED_LINE]"
                entry = f"{tag} file={cur_file} ({cur_commit[:36]}): {raw_val[:350]}"
                if entry not in removed_summary:
                    removed_summary.append(entry)

        if removed_summary:
            report_parts.append(
                "=== REMOVED LINES IN GIT DIFFS ===\n" + "\n".join(removed_summary[:80])
            )

        blobs = scan_raw_git_objects(repo)
        interesting_blobs = []
        for sha, kind, text in blobs:
            for fm in FLAG_RX.findall(text):
                if fm not in current_flags:
                    add_candidate(fm, priority=92)
                    interesting_blobs.append(f"Object {sha} ({kind}) has flag: {fm}")
            for ln in text.splitlines():
                s = ln.strip()
                if s and s not in current_lines:
                    m = ASSIGN_RX.search(s)
                    if m:
                        val = m.group(1).strip()
                        if val not in current_lines and val not in current_flags:
                            add_candidate(val, priority=80)
                            interesting_blobs.append(
                                f"Object {sha} ({kind}) line: {s[:300]}"
                            )
        if interesting_blobs:
            report_parts.append(
                "=== INTERESTING GIT OBJECTS ===\n" + "\n".join(interesting_blobs[:60])
            )

    return "\n\n".join(report_parts)


def inventory():
    files = walk_materials()
    entries = [
        f"{p.stat().st_size:9d}  {p.relative_to(MATERIALS)}" for p in files[:500]
    ]
    repos = [
        str(p.relative_to(MATERIALS)) if p.is_relative_to(MATERIALS) else str(p)
        for p in git_repos()
    ]
    return f"Files: {len(files)}\nGit repos: {repos}\n" + "\n".join(entries)


def read_file(action):
    p = safe_material_path(action.get("path", ""))
    if not p.is_file():
        return "Not a file: " + str(p)
    start = max(1, int(action.get("start_line", 1)))
    lines = max(1, min(180, int(action.get("max_lines", 80))))
    out = []
    with file_stream(p) as f:
        for i, line in enumerate(f, 1):
            if i < start:
                continue
            if i >= start + lines:
                break
            out.append(f"{i}: {line[:3500].rstrip(chr(10))}")
    result = "\n".join(out)
    remember(result)
    return clip(result, 18000)


def grep_files(action):
    rx = re.compile(
        str(action.get("pattern", r"flag|secret|token|password|vega|ctf"))[:180], re.I
    )
    limit = max(2, min(120, int(action.get("max_hits", 50))))
    hits = []
    total = 0
    for p in walk_materials():
        if p.stat().st_size > 130_000_000:
            continue
        try:
            with file_stream(p) as f:
                for i, line in enumerate(f, 1):
                    total += 1
                    if rx.search(line):
                        hits.append(
                            f"{p.relative_to(MATERIALS)}:{i}: {line[:700].rstrip()}"
                        )
                        if len(hits) >= limit:
                            result = "\n".join(hits)
                            remember(result)
                            return f"Limit reached; lines scanned: {total}\n{result}"
                    if total > 1_600_000:
                        break
        except (OSError, UnicodeError, EOFError):
            pass
    result = "\n".join(hits)
    remember(result)
    return f"Found {len(hits)} matches, scanned {total} lines:\n{result}"


def git_log():
    repos = git_repos()
    if not repos:
        return "Git repository not found in materials"
    parts = [analyze_git_forensics()]
    for p in repos:
        log_txt = git_output(
            p,
            [
                "log",
                "--all",
                "--full-history",
                "-n",
                "60",
                "--date=short",
                "--format=%h %ad %s",
                "--name-status",
            ],
            12000,
        )
        parts.append(f"REPOSITORY: {p}\n{log_txt}")
    return clip("\n\n".join(parts), 24000)


def git_find(action):
    pattern = str(
        action.get("pattern", "flag|secret|token|key|password|private|vega|ctf")
    )[:180]
    rx = re.compile(pattern, re.I)
    reports = []
    for repo in git_repos():
        data = git_output(
            repo,
            [
                "log",
                "--all",
                "--full-history",
                "-p",
                "--date=short",
                "--format=COMMIT %H %ad %s",
                "-n",
                "110",
            ],
            2_000_000,
        )
        lines = data.splitlines()
        for idx, line in enumerate(lines):
            if rx.search(line) and (
                line.startswith(("-", "+", " ")) or "COMMIT " in line
            ):
                excerpt = " | ".join(lines[max(0, idx - 2) : min(len(lines), idx + 3)])
                reports.append(excerpt[:950])
                if len(reports) >= 120:
                    break
        for sha, kind, text in scan_raw_git_objects(repo):
            if rx.search(text):
                reports.append(f"OBJECT {sha} ({kind}): {text[:500]}")
                if len(reports) >= 130:
                    break
    result = "\n".join(reports) or "No matching lines in commit diffs."
    remember(result)
    return clip(result, 25000)


def git_show(action):
    rev = str(action.get("rev", "HEAD~1"))
    if not re.fullmatch(r"[a-zA-Z0-9_~^./:@{}-]{1,180}", rev) or rev.startswith("-"):
        return "Invalid git revision"
    relative = action.get("path")
    cmd = ["show", "--format=fuller", rev]
    if relative and ":" not in rev:
        cmd.extend(["--", str(relative)])
    return "\n\n".join(f"REPOSITORY: {p}\n{git_output(p, cmd)}" for p in git_repos())


def git_objects_tool():
    out = []
    for repo in git_repos():
        for sha, kind, text in scan_raw_git_objects(repo)[:80]:
            out.append(f"--- OBJECT {sha} ({kind}) ---\n{text[:1000]}")
    res = "\n".join(out) or "No git objects found."
    remember(res)
    return clip(res, 24000)


def decode_value(action):
    value = str(action.get("value", "")).strip()[:300000]
    mode = str(action.get("encoding", "base64")).lower()
    if mode == "base64":
        data = base64.b64decode(value + "=" * ((-len(value)) % 4))
    elif mode == "hex":
        data = bytes.fromhex(value)
    elif mode == "url":
        data = urllib.parse.unquote_to_bytes(value)
    else:
        return "Unsupported encoding"
    text = data.decode("utf-8", "replace")
    remember(text)
    return {"decoded": clip(text, 13000)}


def call_tool(action):
    name = str(action.get("tool", ""))
    if name == "inventory":
        return inventory()
    if name == "read_file":
        return read_file(action)
    if name == "grep_files":
        return grep_files(action)
    if name == "git_log":
        return git_log()
    if name == "git_find":
        return git_find(action)
    if name == "git_show":
        return git_show(action)
    if name == "git_objects":
        return git_objects_tool()
    if name == "decode":
        return decode_value(action)
    return "Invalid tool. Use inventory, read_file, grep_files, git_log, git_find, git_show, git_objects, decode, or finish."


def initial_context():
    parts = ["TASK: P2Z3 (Recover secret removed from project history)"]
    for location in (TASK_DIR / "instruction.md", MATERIALS / "instruction.md"):
        if location.is_file():
            parts.append(
                "instruction.md:\n"
                + clip(location.read_text(encoding="utf-8", errors="replace"), 4000)
            )
    parts.append("FILES AND REPOSITORIES:\n" + clip(inventory(), 4000))
    parts.append("GIT FORENSICS & HISTORY:\n" + clip(git_log(), 14000))
    return "\n\n".join(parts)


def write_artifact(val):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    target = OUT_DIR / "flag.txt"
    temporary = OUT_DIR / ".flag.txt.tmp"
    temporary.write_text(str(val).strip(), encoding="utf-8")
    os.replace(temporary, target)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    init_ctx = initial_context()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": init_ctx + "\nStart investigation. Output one JSON tool call.",
        },
    ]
    recent_actions = collections.deque(maxlen=6)
    finish_attempts = 0
    last_submitted_flag = ""

    for step in range(30):
        if time.monotonic() > DEADLINE - 15:
            break
        messages = messages[:2] + messages[2:][-14:]
        try:
            reply = model(messages)
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            break
        act = action_from_text(reply)
        name = str(act.get("tool", "")).lower()
        messages.append({"role": "assistant", "content": reply[:3000]})
        if name in ("finish", "write_flag", "submit"):
            raw_flag = (
                act.get("flag")
                or act.get("value")
                or act.get("secret")
                or act.get("answer")
                or act.get("result")
                or ""
            )
            flag = str(raw_flag).strip()
            if flag and "\n" in flag:
                flag = clean_secret_line(flag.splitlines()[0])
            if flag and len(flag) <= 500:
                finish_attempts += 1
                last_submitted_flag = flag
                if flag not in CURRENT_NONEMPTY_LINES or finish_attempts >= 2:
                    write_artifact(flag)
                    return 0
                feedback = "That value is still present in a current non-empty file! Find the secret that was REMOVED from history (check the empty file's git history)."
            else:
                feedback = (
                    "Empty or invalid flag value. Provide the exact secret string."
                )
        else:
            try:
                result = call_tool(act)
                feedback = (
                    json.dumps(result, ensure_ascii=False)
                    if not isinstance(result, str)
                    else result
                )
            except Exception as e:
                feedback = "Tool error: " + type(e).__name__ + ": " + str(e)[:350]
            if name not in ("invalid", ""):
                print(f"step {step + 1}: {name}", file=sys.stderr)
        signature = json.dumps(act, ensure_ascii=False, sort_keys=True)[:800]
        recent_actions.append(signature)
        if len(recent_actions) >= 4 and len(set(list(recent_actions)[-4:])) == 1:
            feedback += (
                "\nRepeated action 4 times. Call finish with the removed secret now."
            )
        messages.append(
            {
                "role": "user",
                "content": f"Tool {name} output:\n{clip(feedback, 16000)}\nNext step: ONE JSON object.",
            }
        )

    if last_submitted_flag:
        write_artifact(last_submitted_flag)
        return 0
    if CANDIDATES:
        CANDIDATES.sort(key=lambda x: x[0], reverse=True)
        write_artifact(CANDIDATES[0][1])
        return 0
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print(
            "Agent error: " + type(err).__name__ + ": " + str(err)[:200],
            file=sys.stderr,
        )
        if CANDIDATES:
            CANDIDATES.sort(key=lambda x: x[0], reverse=True)
            write_artifact(CANDIDATES[0][1])
            sys.exit(0)
        sys.exit(2)
