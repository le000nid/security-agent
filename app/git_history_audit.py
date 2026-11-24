"""Read-only Git history audit that reports candidate commit IDs."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

ASSIGNMENT = (
    r"(^|[^[:alnum:]_])(api[_-]?key|secret[_-]?key|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token|password|passwd)[\"']?[[:space:]]*[:=]"
)
COMMIT_ID = re.compile(rb"(?:[a-f0-9]{40}|[a-f0-9]{64})")


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Root of a local Git working tree")
    parser.add_argument(
        "--limit", type=int, default=100, help="Maximum candidate commits"
    )
    args = parser.parse_args()
    if not 1 <= args.limit <= 200:
        parser.error("--limit must be between 1 and 200")
    try:
        report = audit_history(args.source, args.limit)
    except subprocess.TimeoutExpired:
        parser.exit(1, "History audit timed out\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"History audit failed: {exc}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
