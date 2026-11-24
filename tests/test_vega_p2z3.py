"""Offline contracts and end-to-end loop for the integrated VEGA P2Z3 agent.

No sockets are used: the model is scripted and Git runs against a temporary
repository created with `git init` in tmp_path, matching the no-network rule
from tests/conftest.py.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from scripts.build_vega import REQUIRED, build, build_p2z3
from vega_p2z3 import agent as p2z3

FLAG = "VEGA_training{p2z3_removed_from_history}"


@pytest.fixture()
def p2(monkeypatch, tmp_path):
    task = tmp_path / "task"
    materials = task / "materials"
    materials.mkdir(parents=True)
    artifact = tmp_path / "artifact"
    monkeypatch.setattr(p2z3, "TASK_DIR", task.resolve())
    monkeypatch.setattr(p2z3, "MATERIALS", materials.resolve())
    monkeypatch.setattr(p2z3, "OUT_DIR", artifact.resolve())
    monkeypatch.setattr(p2z3, "DEADLINE", time.monotonic() + 300)
    monkeypatch.setattr(p2z3, "CANDIDATES", [])
    monkeypatch.setattr(p2z3, "CURRENT_NONEMPTY_LINES", set())
    monkeypatch.setattr(p2z3, "EVIDENCE", p2z3.collections.deque(maxlen=200))
    return p2z3


class ScriptedModel:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, messages):
        # snapshot: main() keeps mutating the same list after the model returns
        self.calls.append([dict(m) for m in messages])
        if not self.replies:
            raise AssertionError("scripted model ran out of replies")
        return self.replies.pop(0)


def git(*args, cwd):
    subprocess.run(
        ["git", "--no-pager", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(cwd),
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        },
    )


def seed_history_repo(materials: Path) -> None:
    """One commit with the secret, then a second commit that empties the file."""
    git("init", "-q", cwd=materials)
    (materials / "config.py").write_text('API_KEY = "%s"\n' % FLAG, encoding="utf-8")
    (materials / "notes.md").write_text("project notes\n", encoding="utf-8")
    git("add", "-A", cwd=materials)
    git("commit", "-qm", "add config with key", cwd=materials)
    (materials / "config.py").write_text("", encoding="utf-8")
    git("add", "-A", cwd=materials)
    git("commit", "-qm", "scrub the secret", cwd=materials)


# --- packaging ----------------------------------------------------------------


def test_p2z3_package_contains_exact_root_files_and_executable_run_sh(tmp_path):
    archive_path = build_p2z3(tmp_path / "security-agent-p2z3.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert tuple(archive.namelist()) == REQUIRED
        assert all("/" not in name for name in archive.namelist())
        manifest = json.loads(archive.read("agent.json"))
        assert manifest["format"] == "vega-agent-harness"
        assert manifest["entrypoint"] == "agent.py"
        assert archive.getinfo("run.sh").external_attr >> 16 & 0o111
        assert "git_log" in archive.read("agent.py").decode()


def test_build_keeps_profiles_distinct(tmp_path):
    with (
        zipfile.ZipFile(build(tmp_path / "vega.zip")) as vega,
        zipfile.ZipFile(build_p2z3(tmp_path / "p2z3.zip")) as p2z3_archive,
    ):
        vega_manifest = json.loads(vega.read("agent.json"))
        p2z3_manifest = json.loads(p2z3_archive.read("agent.json"))
        assert vega_manifest != p2z3_manifest
        assert "analyze_git_forensics" not in vega.read("agent.py").decode()
        assert "analyze_git_forensics" in p2z3_archive.read("agent.py").decode()


# --- path guard ---------------------------------------------------------------


def test_safe_material_path_rejects_escape_sibling_and_symlink(p2, tmp_path):
    base = Path(p2.MATERIALS)
    (base / "ok.txt").write_text("ok", encoding="utf-8")
    evil = tmp_path / "materials_evil"
    evil.mkdir()
    (evil / "secret.txt").write_text("nope", encoding="utf-8")
    assert p2.safe_material_path("ok.txt") == (base / "ok.txt").resolve()
    # the P2Z3 contract allows the surrounding task dir (Git metadata lives
    # there) but rejects anything beyond it
    with pytest.raises(ValueError, match="path outside task"):
        p2.safe_material_path("../../../outside.txt")
    # regression guard: a sibling directory next to the task dir must not pass
    with pytest.raises(ValueError, match="path outside task"):
        p2.safe_material_path("../../materials_evil/secret.txt")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = base / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this platform")
    with pytest.raises(ValueError, match="path outside task"):
        p2.safe_material_path("escape.txt")


# --- parser and decoder contracts ---------------------------------------------


def test_flag_rx_accepts_only_flag_shaped_values(p2):
    assert p2.FLAG_RX.findall("VEGA_training{a-b_c}") == ["VEGA_training{a-b_c}"]
    assert p2.FLAG_RX.findall("flag{one} and ctf{two}") == ["flag{one}", "ctf{two}"]
    assert p2.FLAG_RX.findall("password123") == []


def test_action_from_text_normalizes_every_planner_shape(p2):
    assert p2.action_from_text('{"tool":"git_log"}') == {"tool": "git_log"}
    assert p2.action_from_text('```json\n{"tool":"inventory"}\n```') == {
        "tool": "inventory"
    }
    assert p2.action_from_text('{"tool":"finish","arguments":{"flag":"x"}}') == {
        "tool": "finish",
        "flag": "x",
    }
    # the last complete JSON object in prose wins
    assert p2.action_from_text('first {"tool":"git_log"} then {"tool":"finish"}') == {
        "tool": "finish"
    }
    assert p2.action_from_text("Сдаю VEGA_training{p2z3_x}") == {
        "tool": "finish",
        "flag": "VEGA_training{p2z3_x}",
    }
    assert p2.action_from_text("no json here")["tool"] == "invalid"


def test_model_missing_configuration_raises_safe_error(p2, monkeypatch):
    for name in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "LOCAL_AGENT_MODEL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="not configured.*OPENAI_BASE_URL"):
        p2.model([{"role": "user", "content": "hi"}])


def test_decode_value_supports_all_encodings(p2):
    encoded = base64.b64encode("VEGA{b64}".encode()).decode()
    assert p2.decode_value({"value": encoded})["decoded"] == "VEGA{b64}"
    assert p2.decode_value({"value": "%2e%2e%2f", "encoding": "url"})["decoded"] == (
        "../"
    )
    assert p2.decode_value({"value": "4142", "encoding": "hex"})["decoded"] == "AB"
    assert p2.decode_value({"value": "x", "encoding": "rot13"}) == (
        "Unsupported encoding"
    )


def test_decode_b64_flags_surfaces_hidden_secret(p2):
    blob = base64.b64encode(("note: " + FLAG).encode("utf-8")).decode()
    assert p2.decode_b64_flags(blob) == [FLAG]
    assert any(FLAG in item for item in p2.EVIDENCE)
    assert p2.decode_b64_flags("plain page without blobs") == []


def test_clean_secret_line_extracts_assignment_value(p2):
    assert p2.clean_secret_line('API_KEY = "%s"' % FLAG) == FLAG
    assert p2.clean_secret_line('api_key = "quoted"') == "quoted"
    assert p2.clean_secret_line("bare line") == "bare line"


# --- git forensics contracts ---------------------------------------------------


def test_git_forensics_finds_removed_secret_and_ranks_it(p2):
    seed_history_repo(Path(p2.MATERIALS))
    report = p2.analyze_git_forensics()
    assert "config.py" in report
    assert any(FLAG == value for _prio, value in p2.CANDIDATES)
    best_prio = max(prio for prio, _value in p2.CANDIDATES)
    assert best_prio >= 90  # removed-line priority dominates decoys


def test_inventory_and_grep_operate_inside_materials(p2):
    seed_history_repo(Path(p2.MATERIALS))
    listing = p2.inventory()
    assert "notes.md" in listing
    assert ".git" not in listing
    hits = p2.grep_files({"pattern": "notes"})
    assert "notes.md" in hits


def test_git_show_rejects_injection_style_revisions(p2):
    seed_history_repo(Path(p2.MATERIALS))
    assert p2.git_show({"rev": "--output=/tmp/x"}) == "Invalid git revision"
    assert "scrub the secret" in p2.git_show({"rev": "HEAD"})


# --- end-to-end agent loop ------------------------------------------------------


def test_e2e_finish_with_removed_secret_writes_artifact(p2, monkeypatch, capsys):
    seed_history_repo(Path(p2.MATERIALS))
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "inventory"}),
            json.dumps({"tool": "git_log"}),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(p2, "model", scripted)

    assert p2.main() == 0

    assert len(scripted.calls) == 3
    git_feedback = scripted.calls[2][-1]["content"]
    assert FLAG in git_feedback  # forensics report exposed the removed value
    assert (Path(p2.OUT_DIR) / "flag.txt").read_text(encoding="utf-8") == FLAG
    # stderr must stay free of flag content
    assert FLAG not in capsys.readouterr().err


def test_e2e_rejects_value_still_present_in_worktree(p2, monkeypatch):
    seed_history_repo(Path(p2.MATERIALS))
    still_there = "VEGA_training{still_in_current_file}"
    (Path(p2.MATERIALS) / "decoy.py").write_text(
        'DECOY = "%s"\n' % still_there, encoding="utf-8"
    )
    scripted = ScriptedModel(
        [
            json.dumps({"tool": "git_log"}),
            json.dumps({"tool": "finish", "flag": still_there}),
            json.dumps({"tool": "finish", "flag": FLAG}),
        ]
    )
    monkeypatch.setattr(p2, "model", scripted)

    assert p2.main() == 0

    rejection = scripted.calls[2][-1]["content"]
    assert "still present in a current non-empty file" in rejection
    assert (Path(p2.OUT_DIR) / "flag.txt").read_text(encoding="utf-8") == FLAG


def test_e2e_fallback_writes_best_candidate_without_model(p2, monkeypatch):
    seed_history_repo(Path(p2.MATERIALS))

    # model unavailable: the loop breaks, CANDIDATES from forensics are used
    def broken_model(_messages):
        raise RuntimeError("VEGA model gateway error: URLError")

    monkeypatch.setattr(p2, "model", broken_model)

    assert p2.main() == 0

    assert (Path(p2.OUT_DIR) / "flag.txt").read_text(encoding="utf-8") == FLAG
