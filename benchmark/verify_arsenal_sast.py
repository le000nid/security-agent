"""SAST-слой арсенала: семь правил CWE против target-фикстур (нужен Semgrep).

В отличие от код-уровня (benchmark.verify_arsenal) здесь используется
реальный Semgrep со strict-режимом: каждое правило обязано дать находку
в vulnerable-фикстуре и ни одной — в benign-фикстуре.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.scanner_env import scanner_environment

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = REPO_ROOT / "config" / "semgrep-arsenal.yaml"
# сканируем только свои фикстуры: правила арсенала специфичны для его ловушек
TARGETS = (
    "targets/arsenal-lfi",
    "targets/arsenal-rfi",
    "targets/arsenal-sqli",
)
EXPECTED = {
    ("targets/arsenal-lfi/vulnerable.py", "arsenal-python-open-concat"),
    ("targets/arsenal-lfi/vulnerable.py", "arsenal-python-join-open-write"),
    ("targets/arsenal-lfi/vulnerable.py", "arsenal-python-extractall-unfiltered"),
    ("targets/arsenal-rfi/vulnerable.py", "arsenal-python-urlopen-variable"),
    ("targets/arsenal-sqli/vulnerable.py", "arsenal-python-stringbuilt-sql"),
    ("targets/arsenal-sqli/vulnerable.py", "arsenal-python-executescript-input"),
    ("targets/arsenal-sqli/vulnerable.py", "arsenal-python-vacuum-into-built"),
}
BENIGN_PATHS = (
    "targets/arsenal-lfi/benign.py",
    "targets/arsenal-rfi/benign.py",
    "targets/arsenal-sqli/benign.py",
)


def main() -> None:
    executable = shutil.which("semgrep")
    if not executable:
        raise SystemExit("semgrep was not found on PATH; use the agent Docker image")
    with tempfile.TemporaryDirectory(prefix="arsenal-sast-") as home:
        try:
            proc = subprocess.run(
                [
                    executable,
                    "scan",
                    "--config",
                    str(RULES),
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--strict",
                    *TARGETS,
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
                cwd=REPO_ROOT,
                env=scanner_environment(home),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemExit(f"Semgrep execution failed: {exc}") from exc
    if proc.returncode != 0:
        raise SystemExit(
            f"Semgrep failed (exit {proc.returncode}): {proc.stderr[-400:]}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit("Invalid Semgrep JSON output") from exc
    if payload.get("errors"):
        raise SystemExit(f"Semgrep scan errors: {payload['errors'][:2]}")
    scanned = set(payload.get("paths", {}).get("scanned", []))
    missing = [
        path
        for path in BENIGN_PATHS + tuple(p for p, _ in EXPECTED)
        if path not in scanned
    ]
    if missing:
        raise SystemExit(f"Fixture files were not scanned: {sorted(missing)}")
    actual = {
        (record["path"], record["check_id"].rsplit(".", 1)[-1])
        for record in payload.get("results", [])
    }
    if actual != EXPECTED:
        raise SystemExit(
            f"arsenal SAST drift: missing {EXPECTED - actual}, "
            f"unexpected {actual - EXPECTED}"
        )
    print("Arsenal SAST passed: 7 CWE rules, 7 findings in vulnerable, 0 in benign")


if __name__ == "__main__":
    main()
