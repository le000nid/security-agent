"""Read-only Git history audit: candidate commit IDs and removed secrets.

Two capabilities share one hardened Git layer:

* ``audit_history`` — the original candidate-commit report (``-G`` over
  assignment-shaped diffs), used by the CLI console script;
* ``recover_removed_secret`` — the Git-forensics engine behind the
  ``git_history_recovery`` CTF profile: diff the worktree against history,
  raw-scan ``.git/objects`` and rank values that are absent from every
  current non-empty file (a value still present is a stub or decoy, not the
  answer).
"""

import argparse
import json
import os
import re
import subprocess
import zlib
from pathlib import Path

ASSIGNMENT = (
    r"(^|[^[:alnum:]_])(api[_-]?key|secret[_-]?key|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token|password|passwd)[\"']?[[:space:]]*[:=]"
)
COMMIT_ID = re.compile(rb"(?:[a-f0-9]{40}|[a-f0-9]{64})")
FLAG_RX = re.compile(r"(?i)(?:flag|ctf|key|secret|token)\{[^\r\n{}]{2,250}\}")
ASSIGN_RX = re.compile(
    r"(?i)(?:secret|flag|token|password|passwd|api[_-]?key|private[_-]?key|"
    r"auth[_-]?key|access[_-]?key|key)\s*[:=]\s*[\"']?([^\s\"'`;,#]{4,240})[\"']?"
)


def audit_history(source: Path, limit: int) -> dict:
    root = source.resolve(strict=True)
    metadata = root / ".git"
    if metadata.is_symlink() or not (metadata.is_dir() or metadata.is_file()):
        raise ValueError("Pass the root of a local Git working tree")

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    env.update(
        GIT_ALLOW_PROTOCOL="",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    git = ["git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false"]
    git_dir = _git_output(
        root, env, git, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    objects = Path(os.fsdecode(git_dir.rstrip(b"\r\n"))) / "objects" / "info"
    if any((objects / name).exists() for name in ("alternates", "http-alternates")):
        raise ValueError("Repositories using external object stores are unsupported")

    output = _git_output(
        root,
        env,
        git,
        "log",
        "--all",
        "--full-history",
        "--format=%H",
        "--no-patch",
        "--no-show-signature",
        "--no-notes",
        "--no-ext-diff",
        "--no-textconv",
        "--regexp-ignore-case",
        f"--max-count={limit + 1}",
        "-G",
        ASSIGNMENT,
        "--",
    )
    hashes = output.splitlines()
    if any(COMMIT_ID.fullmatch(value) is None for value in hashes):
        raise ValueError("Unexpected output from Git")
    return {
        "candidate_commits": [value.decode("ascii") for value in hashes[:limit]],
        "truncated": len(hashes) > limit,
    }


def _git_output(root: Path, env: dict[str, str], git: list[str], *args: str) -> bytes:
    result = subprocess.run(
        [*git, *args], cwd=root, env=env, capture_output=True, check=False, timeout=30
    )
    if result.returncode:
        raise ValueError("Could not read local Git history")
    return result.stdout


# --------------------------------------------------------------------------
# Removed-secret recovery engine (git_history_recovery CTF profile)
# --------------------------------------------------------------------------


def clean_secret_line(val: str) -> str:
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


def _forensics_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _loose_git_output(repo: Path, cmd: list[str], max_length: int = 30000) -> str:
    """Best-effort git read with safe.directory fallback; '' on failure."""
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
                env=_forensics_env(),
                timeout=25,
                check=False,
            )
            output = r.stdout.decode("utf-8", "replace")
            if r.returncode == 0 or output.strip():
                return output[:max_length]
            last_err = r.stderr.decode("utf-8", "replace")[:600]
        except (OSError, subprocess.TimeoutExpired) as e:
            last_err = type(e).__name__
    return "git error: " + last_err


def resolve_git_dir(repo: Path) -> Path | None:
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


def scan_raw_git_objects(repo: Path):
    """Loose objects (zlib), packed cat-file enumeration and git metadata."""
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
                    if t.strip():
                        blobs.append(
                            (str(log_file.relative_to(gdir)), "meta", t[:4000])
                        )
                except OSError:
                    pass
    cat_list = _loose_git_output(
        repo, ["cat-file", "--batch-check", "--batch-all-objects"], 200000
    )
    if not cat_list.startswith("git error:"):
        seen_shas = {b[0] for b in blobs}
        for line in cat_list.splitlines()[:250]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("blob", "commit", "tag"):
                sha = parts[0]
                if sha[:12] not in seen_shas:
                    content = _loose_git_output(repo, ["cat-file", "-p", sha], 15000)
                    if not content.startswith("git error:") and content.strip():
                        blobs.append((sha[:12], parts[1], content[:4000]))
    return blobs


def recover_removed_secret(materials: Path) -> dict:
    """Rank secret candidates REMOVED from history and absent from the
    current worktree. Returns candidates plus a human-readable forensics
    report; values still present in non-empty files are excluded (stubs)."""
    materials = Path(materials)
    current_lines = set()
    current_flags = set()
    empty_files = []
    for p in sorted(materials.rglob("*")):
        if not p.is_file() or ".git" in p.parts or p.name == "instruction.md":
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            rel = p.relative_to(materials).as_posix()
            if not content.strip():
                empty_files.append(rel)
            else:
                for ln in content.splitlines():
                    s = ln.strip()
                    if s:
                        current_lines.add(s)
                        for fm in FLAG_RX.findall(s):
                            current_flags.add(fm)
        except OSError:
            pass

    candidates: list[tuple[int, str]] = []
    report_parts = [f"CURRENT EMPTY FILES IN WORKTREE: {empty_files}"]

    def add(val, priority):
        val = str(val).strip()
        if not val or "\n" in val or len(val) > 400:
            return
        candidates.append((priority, val))

    repo = materials
    for ef in empty_files:
        hist = _loose_git_output(
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
                        add(cleaned, priority=100)
                        add(ln[1:].strip(), priority=90)

    full_diff = _loose_git_output(
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
    reflog_diff = _loose_git_output(
        repo, ["log", "--reflog", "-p", "--format=COMMIT %H %s", "-n", "60"], 300000
    )
    combined = (
        full_diff + "\n" + ("" if reflog_diff.startswith("git error:") else reflog_diff)
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
                add(cleaned, priority=prio)
            tag = "[FROM_EMPTY_FILE]" if is_empty_target else "[REMOVED_LINE]"
            entry = f"{tag} file={cur_file} ({cur_commit[:36]}): {raw_val[:350]}"
            if entry not in removed_summary:
                removed_summary.append(entry)
    if removed_summary:
        report_parts.append(
            "=== REMOVED LINES IN GIT DIFFS ===\n" + "\n".join(removed_summary[:80])
        )

    interesting_blobs = []
    for sha, kind, text in scan_raw_git_objects(repo):
        for fm in FLAG_RX.findall(text):
            if fm not in current_flags:
                add(fm, priority=92)
                interesting_blobs.append(f"Object {sha} ({kind}) has flag: {fm}")
        for ln in text.splitlines():
            s = ln.strip()
            if s and s not in current_lines:
                m = ASSIGN_RX.search(s)
                if m:
                    val = m.group(1).strip()
                    if val not in current_lines and val not in current_flags:
                        add(val, priority=80)
                        interesting_blobs.append(
                            f"Object {sha} ({kind}) line: {s[:300]}"
                        )
    if interesting_blobs:
        report_parts.append(
            "=== INTERESTING GIT OBJECTS ===\n" + "\n".join(interesting_blobs[:60])
        )

    candidates.sort(key=lambda x: x[0], reverse=True)
    return {
        "best_candidate": candidates[0][1] if candidates else "",
        "candidates": [
            {"priority": priority, "value": value}
            for priority, value in candidates[:20]
        ],
        "report": "\n\n".join(report_parts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Root of a local Git working tree")
    parser.add_argument(
        "--limit", type=int, default=100, help="Maximum candidate commits"
    )
    parser.add_argument(
        "--recover-secret",
        action="store_true",
        help="Run removed-secret forensics instead of the commit-ID report",
    )
    args = parser.parse_args()
    if not 1 <= args.limit <= 200:
        parser.error("--limit must be between 1 and 200")
    try:
        if args.recover_secret:
            report = recover_removed_secret(args.source)
            print(
                json.dumps(
                    {
                        "best_candidate": report["best_candidate"],
                        "candidates": report["candidates"],
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        report = audit_history(args.source, args.limit)
    except subprocess.TimeoutExpired:
        parser.exit(1, "History audit timed out\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"History audit failed: {exc}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
