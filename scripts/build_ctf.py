#!/usr/bin/env python3
"""Build every standalone CTF submission from the embedded engine.

The CTF agents live in the application core (``app.agent.ctf``); this
script renders each profile back into the exact four-file standalone
contract the runner harness expects:

    run.sh  agent.json  agent.py  strategy.md

Profiles are identified by functional names (``git_history_recovery``,
``path_filter_bypass``, ...).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PROFILE_OUTPUTS = {
    "evidence": "security-agent-evidence.zip",
    "file_inspection": "security-agent-file-inspection.zip",
    "git_history_recovery": "security-agent-git-history-recovery.zip",
    "path_filter_bypass": "security-agent-path-filter-bypass.zip",
    "path_assembly_bypass": "security-agent-path-assembly-bypass.zip",
    "remote_inclusion": "security-agent-remote-inclusion.zip",
    "sqli_login_bypass": "security-agent-sqli-login-bypass.zip",
    "sqli_admin_bypass": "security-agent-sqli-admin-bypass.zip",
    "sqli_auth_inversion": "security-agent-sqli-auth-inversion.zip",
}


def build_all(dist: Path | None = None) -> list[Path]:
    from app.agent.ctf.package import build_archive

    output_dir = dist or (PROJECT_ROOT / "dist")
    output_dir.mkdir(parents=True, exist_ok=True)
    built = []
    for profile_key, filename in PROFILE_OUTPUTS.items():
        built.append(build_archive(profile_key, output_dir / filename))
    return built


if __name__ == "__main__":
    for path in build_all():
        print(path)
