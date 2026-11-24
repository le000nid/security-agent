"""Exercise the file-exposure SAST handoff with the real Semgrep image."""

from pathlib import Path
from tempfile import TemporaryDirectory

from app.file_exposure_sast import inspect

FIXTURES = Path(__file__).resolve().parents[1] / "targets" / "sast-file-exposure"
EXPECTED = {
    ("vulnerable.py", 6, "python-request-file-read"),
    ("vulnerable.js", 5, "javascript-request-file-read"),
    ("vulnerable.js", 6, "javascript-request-file-read"),
    ("vulnerable.php", 4, "php-request-file-read"),
    ("vulnerable.php", 5, "php-local-file-inclusion"),
}


def main() -> None:
    source_scan = inspect("source_scan", FIXTURES)
    scan = source_scan["sast"]
    actual = {(row["path"], row["line"], row["rule"]) for row in scan["findings"]}
    if scan["status"] != "completed" or scan["scanned_files"] != 6:
        raise SystemExit(f"Incorrect traversal scan coverage: {scan}")
    if actual != EXPECTED or len(scan["findings"]) != len(EXPECTED):
        raise SystemExit(
            f"Traversal regression: missing {EXPECTED - actual}, unexpected {actual - EXPECTED}"
        )
    with TemporaryDirectory(prefix="file-exposure-backups-") as directory:
        root = Path(directory)
        for name in (
            "public/index.php.old",
            "old/index.html",
            "site-backup.tar.gz",
            "live.js",
        ):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        backup_inventory = inspect("backup_inventory", root)
        candidates = backup_inventory["sast"]["backup_candidates"]
        actual = {row["path"] for row in candidates}
        if actual != {"public/index.php.old", "old/index.html", "site-backup.tar.gz"}:
            raise SystemExit(f"Backup regression: {actual}")
    for result in (source_scan, backup_inventory):
        if any(s["status"] != "not_implemented" for s in result["stages"].values()):
            raise SystemExit("A live runtime step was marked implemented")
    print("File-exposure SAST passed: 5 findings, 3 offline backup candidates")


if __name__ == "__main__":
    main()
