#!/usr/bin/env python3
"""One-shot textual rename for the v4 -> v5 code de-branding.

Rewrites module paths, env vars, header names, error classes, prompts and
doc references across the codebase. Run once from the repo root.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (old, new) ordered pairs — longest/most specific first
REPLACEMENTS = [
    # module paths
    ("app.agent.vega", "app.agent.ctf"),
    ("app/agent/vega", "app/agent/ctf"),
    ("agent.vega", "agent.ctf"),
    # env vars (runtime reads CTF_* names)
    ("VEGA_TASK_DIR", "CTF_TASK_DIR"),
    ("VEGA_CTF_ARTIFACT_DIR", "CTF_ARTIFACT_DIR"),
    ("VEGA_TARGET_URL", "CTF_TARGET_URL"),
    ("VEGA_AGENT_MAX_STEPS", "CTF_AGENT_MAX_STEPS"),
    ("VEGA_AGENT_SESSION_ID", "CTF_AGENT_SESSION_ID"),
    # headers / UA / error surfaces
    ("X-VEGA-Agent-Session", "X-Agent-Session"),
    ("X-vega-agent-session", "X-agent-session"),
    ("VEGA-CTF-Agent/1.0", "CTF-Agent/1.0"),
    ("VEGA model gateway", "CTF model gateway"),
    ("VEGA agent failed", "CTF agent failed"),
    ("VegaError", "CtfError"),
    # file/test/doc names
    ("tests/test_vega_engine.py", "tests/test_ctf_engine.py"),
    ("tests/test_vega_evidence.py", "tests/test_ctf_evidence.py"),
    ("tests/test_vega_cli.py", "tests/test_ctf_cli.py"),
    ("benchmark/verify_vega_profiles.py", "benchmark/verify_ctf_profiles.py"),
    ("verify_vega_profiles", "verify_ctf_profiles"),
    ("scripts/build_vega.py", "scripts/build_ctf.py"),
    ("docs/VEGA.md", "docs/CTF_AGENTS.md"),
    ("VEGA.md", "CTF_AGENTS.md"),
    ("test_vega_", "test_ctf_"),
]

FILES = [
    "app/agent/ctf/__init__.py",
    "app/agent/ctf/runtime.py",
    "app/agent/ctf/profiles.py",
    "app/agent/ctf/evidence.py",
    "app/agent/ctf/package.py",
    "app/cli.py",
    "app/main.py",
    "app/file_exposure_sast.py",
    "app/git_history_audit.py",
    "benchmark/verify_ctf_profiles.py",
    "benchmark/verify_file_exposure_sast.py",
    "scripts/build_ctf.py",
    "tests/test_ctf_engine.py",
    "tests/test_ctf_evidence.py",
    "tests/test_ctf_cli.py",
    "tests/test_file_exposure_sast.py",
    "docs/CTF_AGENTS.md",
    "README.md",
]

for rel in FILES:
    path = ROOT / rel
    if not path.exists():
        print(f"SKIP missing {rel}")
        continue
    text = path.read_text(encoding="utf-8")
    original = text
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    if text != original:
        path.write_text(text, encoding="utf-8")
        print(f"rewrote {rel}")

print("done")
