"""Build standalone four-file CTF submissions from the embedded engine.

The CTF agents live inside the application (``app.agent.ctf``); this module
renders them back into the exact standalone contract the runner harness
expects — a ZIP with exactly ``run.sh``, ``agent.json``, ``agent.py`` and
``strategy.md`` in its root, standard library only.

``agent.py`` is assembled from the integrated sources: the shared runtime,
the profile registry and a tiny profile-specific entry point. No task-named
files ship in the archive; profiles are selected by their functional name.
"""

from __future__ import annotations

import json
import stat
import tempfile
import zipfile
from pathlib import Path

FILES = ("run.sh", "agent.json", "agent.py", "strategy.md")

RUN_SH = """#!/bin/sh
set -eu
exec python3 "$(dirname "$0")/agent.py"
"""

ENTRY_TEMPLATE = '''#!/usr/bin/env python3
"""Standalone CTF agent: {profile_name} — {summary}.

Rendered from the integrated security-agent engine (app.agent.ctf); this
file embeds the shared runtime and the profile registry below. Standard
library only.
"""

from __future__ import annotations

import sys

PROFILE_NAME = {profile_name!r}

# --- embedded engine (runtime + profiles) --------------------------------
{engine}

# --- standalone entry point ----------------------------------------------


def main() -> int:
    profile = get_profile(PROFILE_NAME)
    if profile is None:  # pragma: no cover - guarded by the builder
        print("unknown profile: " + PROFILE_NAME, file=sys.stderr)
        return 2
    return run_profile(profile)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # never a traceback into the harness log
        print(
            "Agent error: " + type(err).__name__ + ": " + str(err)[:200],
            file=sys.stderr,
        )
        sys.exit(2)
'''

EVIDENCE_ENTRY_TEMPLATE = '''#!/usr/bin/env python3
"""Standalone bounded evidence agent.

Rendered from the integrated security-agent engine (app.agent.ctf.evidence);
standard library only. Strict action contract: LIST_FILES, READ_FILE,
SEARCH_FILES, GIT_LOG, GIT_SHOW, HTTP_REQUEST, WRITE_FLAG, FINISH.
"""

from __future__ import annotations

import sys

# --- embedded engine (evidence profile) -----------------------------------
{engine}

# --- standalone entry point ----------------------------------------------

STRATEGY_TEXT = {strategy_text!r}


def standalone_main() -> int:
    try:
        client = OpenAIClient()  # fail fast on missing gateway config
        return run(Runtime(), client, bounded(STRATEGY_TEXT, 16000))
    except CtfError as exc:
        print("CTF agent failed: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("CTF agent failed: internal_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(standalone_main())
'''


def _module_source(module_name: str, strip_package_prefixes: bool = True) -> str:
    """Render an integrated module as standalone source.

    ``from app.agent.ctf.x import y`` lines are dropped (the modules are
    concatenated into one namespace), and ``sys``-only stdlib imports are
    kept: the rendered file must run with the standard library alone.
    """
    import importlib
    import inspect

    module = importlib.import_module(module_name)
    source = inspect.getsource(module)
    lines = source.splitlines()
    out = []
    skip_prefixes = (
        "from app.agent.ctf",
        "from app.",
        "import app",
    )
    in_dropped_import = False
    for line in lines:
        if in_dropped_import:
            # multi-line `from app... import (` continuation: keep dropping
            # until the closing parenthesis
            if ")" in line:
                in_dropped_import = False
            continue
        if strip_package_prefixes and line.startswith(skip_prefixes):
            if "(" in line and ")" not in line:
                in_dropped_import = True
            continue
        if line.startswith("from __future__ import"):
            # the entry template already provides it at the top of the file
            continue
        out.append(line)
    return "\n".join(out)


def render_agent_source(profile_key: str, strategy_md: str) -> str:
    """Render the standalone agent.py for one profile."""
    from app.agent.ctf.profiles import get_profile

    engine = (
        _module_source("app.agent.ctf.runtime")
        + "\n\n\n"
        + _module_source("app.agent.ctf.profiles")
    )
    if profile_key == "evidence":
        return EVIDENCE_ENTRY_TEMPLATE.format(
            engine=_module_source("app.agent.ctf.evidence"),
            strategy_text=strategy_md,
        )
    profile = get_profile(profile_key)
    if profile is None:
        raise ValueError(f"unknown profile: {profile_key}")
    return ENTRY_TEMPLATE.format(
        profile_name=profile.name,
        summary=profile.summary,
        engine=engine,
    )


def _strategy_text(profile_key: str) -> str:
    """The strategy.md body: hint + tool descriptions + summary header."""
    if profile_key == "evidence":
        from app.agent.ctf.evidence import EVIDENCE_STRATEGY

        return (
            "# Bounded evidence agent\n\n"
            "Обнаружить фактический secret/flag в materials и записать его "
            "точное значение в артефакт. Строгий контракт действий, "
            "HTTP только на http://target:8000, редиректы отключены.\n\n"
            + EVIDENCE_STRATEGY
        )
    from app.agent.ctf.profiles import get_profile

    profile = get_profile(profile_key)
    if profile is None:
        raise ValueError(f"unknown profile: {profile_key}")
    return (
        f"# {profile.name}\n\n"
        f"{profile.summary}\n\n"
        f"## Инструкция\n\n{profile.hint}\n\n"
        f"## Инструменты\n{profile.tool_descriptions}\n"
    )


def build_archive(profile_key: str, destination: Path, strategy_path=None) -> Path:
    """Build the four-file standalone ZIP for one profile."""
    profile_key = str(profile_key).strip().lower()
    from app.agent.ctf import PROFILES

    if profile_key not in PROFILES:
        raise ValueError(f"unknown profile: {profile_key}")

    strategy = (
        strategy_path.read_text(encoding="utf-8", errors="replace")
        if strategy_path is not None
        else _strategy_text(profile_key)
    )
    if not strategy.strip():
        raise ValueError("empty strategy")
    agent_source = render_agent_source(profile_key, strategy)
    compile(agent_source, "agent.py", "exec")  # must be valid Python

    manifest = {
        "name": f"security-agent-{profile_key}",
        "version": "1.0.0",
        "entrypoint": "run.sh",
    }

    destination = Path(destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{profile_key}-",
            suffix=".zip",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
        contents = {
            "run.sh": RUN_SH.encode(),
            "agent.json": (json.dumps(manifest, indent=2) + "\n").encode(),
            "agent.py": agent_source.encode(),
            "strategy.md": strategy.encode(),
        }
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            for name in FILES:
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                mode = 0o755 if name == "run.sh" else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, contents[name])
        with zipfile.ZipFile(temporary) as archive:
            if tuple(archive.namelist()) != FILES or archive.testzip() is not None:
                raise ValueError("invalid standalone ZIP")
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
