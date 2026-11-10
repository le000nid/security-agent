"""Exercise launcher profile selection without starting Docker or contacting a lab."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ("nosqli-profile-catalog", "nosqli-mongo-api", False),
    ("nosqli-profile-catalog-safe", "nosqli-mongo-api", False),
    ("nosqli-profile-inventory", "nosqli-portable-api", True),
    ("nosqli-profile-inventory-safe", "nosqli-portable-api", True),
]


def check_command(output, service, portable):
    assert "--profile nosqli-mongo" in output
    assert ("--profile nosqli-portable" in output) == portable
    assert "up -d --build --wait --wait-timeout 180" in output
    assert output.strip().endswith(service)


@pytest.mark.skipif(
    os.name == "nt" or not shutil.which("bash"), reason="Unix Bash required"
)
@pytest.mark.parametrize("benchmark,service,portable", CASES)
def test_bash_nosqli_profiles(benchmark, service, portable):
    program = 'source "$1"; docker() { printf "%s\\n" "$*"; }; start_benchmark_lab "$2"'
    completed = subprocess.run(
        [
            "bash",
            "-c",
            program,
            "launcher-test",
            str(ROOT / "scripts/common.sh"),
            benchmark,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    check_command(completed.stdout, service, portable)


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell not installed")
@pytest.mark.parametrize("benchmark,service,portable", CASES)
def test_powershell_nosqli_profiles(tmp_path, benchmark, service, portable):
    script = tmp_path / "launcher-test.ps1"
    script.write_text(
        "param([string]$Common, [string]$Benchmark)\n"
        ". $Common\n"
        'function Invoke-Docker { Write-Output ($args -join " ") }\n'
        "Start-BenchmarkLab $Benchmark\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(ROOT / "scripts/common.ps1"),
            benchmark,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    check_command(completed.stdout, service, portable)
