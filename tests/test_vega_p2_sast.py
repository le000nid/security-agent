import json

import pytest

from app import vega_p2_sast


@pytest.mark.parametrize("task", vega_p2_sast.TASKS)
def test_instruction_only_does_not_report_a_clean_scan(tmp_path, monkeypatch, task):
    (tmp_path / "instruction.md").write_text("http://target:8000")

    def unexpected_scan(*args, **kwargs):
        pytest.fail("An instruction-only input must not launch Semgrep")

    monkeypatch.setattr(vega_p2_sast, "run_semgrep", unexpected_scan)
    report = vega_p2_sast.inspect(task, tmp_path)
    assert report["sast"]["status"] == "no_source"
    assert report["scope"] == "sast_only"
    assert set(report["stages"]) == {
        "http_discovery",
        "secret_extraction",
        "flag_write",
    }
    assert all(s["status"] == "not_implemented" for s in report["stages"].values())
    assert not (tmp_path / "flag.txt").exists()


def test_backup_inventory_is_relative_and_does_not_read_values(tmp_path):
    for name in ("public/site.bak", "old/index.php", "site-backup.zip", "active.js"):
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"synthetic-private-marker")
    result = vega_p2_sast.inspect("p2z2", tmp_path)["sast"]
    assert result["status"] == "completed"
    assert result["inspected_files"] == 4
    assert result["backup_candidates"] == [
        {
            "path": "old/index.php",
            "reason": "old_copy_directory",
            "under_web_named_directory": False,
            "http_verified": False,
        },
        {
            "path": "public/site.bak",
            "reason": "backup_suffix",
            "under_web_named_directory": True,
            "http_verified": False,
        },
        {
            "path": "site-backup.zip",
            "reason": "backup_archive_name",
            "under_web_named_directory": False,
            "http_verified": False,
        },
    ]
    assert "synthetic-private-marker" not in json.dumps(result)


def test_backup_inventory_does_not_follow_links(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    outside = tmp_path / "outside.bak"
    outside.touch()
    try:
        (root / "linked.bak").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable")
    assert vega_p2_sast.inspect("p2z2", root)["sast"]["status"] == "no_source"


def test_partial_semgrep_coverage_is_rejected(tmp_path, monkeypatch):
    for name in ("one.py", "two.py"):
        (tmp_path / name).write_text("pass\n")
    (tmp_path / ".semgrepignore").write_text("*.py\n")

    def incomplete(source, output, **options):
        assert options["timeout"] <= 180
        assert not (source / ".semgrepignore").exists()
        output.write_text(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": [str(source / "one.py")]},
                }
            )
        )

    monkeypatch.setattr(vega_p2_sast, "run_semgrep", incomplete)
    with pytest.raises(ValueError, match="did not cover"):
        vega_p2_sast.inspect("p2z1", tmp_path)


def test_oversize_source_fails_without_starting_scan(tmp_path, monkeypatch):
    (tmp_path / "large.py").write_text("pass\n")
    monkeypatch.setattr(vega_p2_sast, "MAX_FILE_BYTES", 2)
    with pytest.raises(ValueError, match="source size limit"):
        vega_p2_sast.inspect("p2z1", tmp_path)
