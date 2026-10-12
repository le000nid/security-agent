"""Nuclei process integration."""

import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from app.resources import config_directory
from app.scanner_env import scanner_environment
from app.validation import validate_target_url

TEMPLATE_DIRECTORY = config_directory() / "nuclei"


class NucleiError(RuntimeError):
    """Raised when Nuclei cannot be started or exits unsuccessfully."""


def run_nuclei(target_url: str, output_path: Path) -> None:
    """Run Nuclei against an already validated target and write JSONL output."""

    target_url = validate_target_url(target_url)
    executable = shutil.which("nuclei")
    if executable is None:
        raise NucleiError(
            "nuclei was not found on PATH. Install it from the official Nuclei project."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("", encoding="utf-8")
    command = [
        executable,
        "-u",
        target_url,
        "-jsonl",
        "-o",
        str(output_path),
        "-silent",
        "-t",
        str(TEMPLATE_DIRECTORY),
        "-type",
        "http",
        "-disable-redirects",
        "-no-interactsh",
        "-disable-update-check",
        "-rate-limit",
        "5",
    ]
    try:
        with TemporaryDirectory(prefix="nuclei-lab-") as home:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=scanner_environment(home),
                timeout=15 * 60,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NucleiError(f"Failed to run nuclei: {exc}") from exc

    if completed.returncode != 0:
        raise NucleiError(
            f"nuclei exited with code {completed.returncode}; inspect logs/"
        )

    output_path.touch(exist_ok=True)
