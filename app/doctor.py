"""Container diagnostics; model discovery only when explicitly requested."""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from app import __version__
from app.benchmarks import BenchmarkRegistry
from app.config import Settings
from app.llm import OpenAICompatibleClient
from app.preflight import check_target_reachable
from app.resources import config_directory
from app.scanner_env import scanner_environment


def diagnose(*, check_llm: bool = False, check_benchmarks: bool = False) -> int:
    failed = False
    print(f"ai-security-agent {__version__}; {platform.system()}/{platform.machine()}")
    for binary, flag in (("semgrep", "--version"), ("nuclei", "-version")):
        path = shutil.which(binary)
        if not path:
            print(f"FAIL {binary} unavailable; rebuild the agent image")
            failed = True
            continue
        try:
            with TemporaryDirectory() as home:
                result = subprocess.run(
                    [path, flag],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=scanner_environment(home),
                    check=False,
                )
            print(f"{binary}: {(result.stdout + result.stderr).strip()[:300]}")
            failed |= result.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            print(f"FAIL {binary} version check failed")
            failed = True
    try:
        Path("runs").mkdir(exist_ok=True)
        with TemporaryDirectory(dir="runs"):
            pass
        print("OK writable runs directory")
    except OSError:
        print("FAIL runs unwritable; check bind mount UID/GID")
        failed = True
    for path in (
        config_directory() / "semgrep.yaml",
        config_directory() / "nuclei",
    ):
        print(f"{'OK' if path.exists() else 'FAIL'} {path}")
        failed |= not path.exists()
    try:
        registry = BenchmarkRegistry.load()
        print("OK benchmark registry")
        for benchmark in registry.list():
            if benchmark.source_path:
                source = Path(benchmark.local_source())
                print(f"{'OK' if source.is_dir() else 'FAIL'} source: {benchmark.id}")
                failed |= not source.is_dir()
            if check_benchmarks and benchmark.target_url:
                try:
                    check_target_reachable(benchmark.target_url)
                    print(f"OK HTTP: {benchmark.id}")
                except (OSError, ValueError):
                    print(
                        f"FAIL HTTP: {benchmark.id}; start bundled benchmark services"
                    )
                    failed = True
    except (OSError, ValueError):
        print("FAIL benchmark registry or source configuration")
        failed = True
    missing = [
        name
        for name in ("LLM_PROVIDER", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
        if not os.getenv(name) or os.getenv(name) == "replace_me"
    ]
    print(
        "LLM configuration: "
        + ("missing " + ", ".join(missing) if missing else "present (values hidden)")
    )
    if check_llm:
        try:
            OpenAICompatibleClient(
                settings=Settings.from_env()
            ).ensure_model_available()
            print("OK model discovery (no completion)")
        except ValueError:
            print(
                "FAIL model discovery; check configuration, authentication and model ID"
            )
            failed = True
    return 6 if failed else 0
