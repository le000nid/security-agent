"""Exercise release scripts in a disposable repository, never the user's index."""

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def release_repo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git unavailable")
    for name in ("scripts/package.ps1", "scripts/package.sh", ".gitattributes"):
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    (tmp_path / "app").mkdir()
    (tmp_path / "app/__init__.py").write_text('__version__ = "0.4.1"\n')
    (tmp_path / ".env.example").write_text("LLM_API_KEY=replace_me\n")
    for name in (
        "runs/old.json",
        "logs/.gitkeep",
        "reports/old.md",
        ".pytest_cache/item",
        "app/__pycache__/example.pyc",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("runtime artifact")

    def git(*args):
        return subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )

    git("init")
    git("add", ".")
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "release fixture",
    )
    (tmp_path / ".env").write_text("LLM_API_KEY=untracked-training-placeholder\n")
    return tmp_path, git


def package_command(root):
    if sys.platform == "win32":
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(root / "scripts/package.ps1"),
        ]
    return ["bash", str(root / "scripts/package.sh")]


def test_release_archive_excludes_runtime_and_untracked_secrets(release_repo):
    root, _ = release_repo
    result = subprocess.run(
        package_command(root), cwd=root, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(root / "dist/security-agent-v0.4.1.zip") as archive:
        names = archive.namelist()
        assert "app/__init__.py" in names and ".env.example" in names
        assert not any(
            n.startswith(("runs/", "logs/", "reports/", ".git/", ".pytest_cache/"))
            or "__pycache__" in n
            or n == ".env"
            for n in names
        )
        assert b"untracked-training-placeholder" not in b"".join(
            archive.read(n) for n in names
        )
    retry = subprocess.run(
        package_command(root), cwd=root, capture_output=True, timeout=30
    )
    assert retry.returncode != 0  # No silent overwrite.


def test_release_refuses_tracked_secret_file(release_repo):
    root, git = release_repo
    git("add", ".env")
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "unsafe fixture",
    )
    result = subprocess.run(
        package_command(root), cwd=root, capture_output=True, timeout=30
    )
    assert result.returncode != 0
    assert not (root / "dist/security-agent-v0.4.1.zip").exists()
