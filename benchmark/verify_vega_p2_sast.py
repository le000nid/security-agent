"""Exercise VEGA P2's offline handoff with the real Semgrep image."""

from pathlib import Path
from tempfile import TemporaryDirectory

from app.vega_p2_sast import inspect

FIXTURES = Path(__file__).resolve().parents[1] / "targets" / "sast-vega-p2z1"
EXPECTED = {
    ("vulnerable.py", 6, "python-request-file-read"),
    ("vulnerable.js", 5, "javascript-request-file-read"),
    ("vulnerable.js", 6, "javascript-request-file-read"),
    ("vulnerable.php", 4, "php-request-file-read"),
    ("vulnerable.php", 5, "php-local-file-inclusion"),
}


def main() -> None:
    p2z1 = inspect("p2z1", FIXTURES)
    scan = p2z1["sast"]
    actual = {(row["path"], row["line"], row["rule"]) for row in scan["findings"]}
    if scan["status"] != "completed" or scan["scanned_files"] != 6:
        raise SystemExit(f"Incorrect traversal scan coverage: {scan}")
    if actual != EXPECTED or len(scan["findings"]) != len(EXPECTED):
        raise SystemExit(
            f"Traversal regression: missing {EXPECTED - actual}, unexpected {actual - EXPECTED}"
        )
    with TemporaryDirectory(prefix="vega-p2-backups-") as directory:
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
        p2z2 = inspect("p2z2", root)
        candidates = p2z2["sast"]["backup_candidates"]
        actual = {row["path"] for row in candidates}
        if actual != {"public/index.php.old", "old/index.html", "site-backup.tar.gz"}:
            raise SystemExit(f"Backup regression: {actual}")
    for result in (p2z1, p2z2):
        if any(s["status"] != "not_implemented" for s in result["stages"].values()):
            raise SystemExit("A live VEGA step was marked implemented")
    print("VEGA P2 SAST passed: 5 exact source findings, 3 offline backup candidates")


if __name__ == "__main__":
    main()
