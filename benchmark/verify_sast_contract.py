"""Real Semgrep acceptance: clean code is valid; scanning no code is not."""

import json
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from app.semgrep import parse_semgrep_json, run_semgrep

SQL_SOURCE = (
    "from flask import request\n"
    "def lookup(cursor):\n"
    "    name = request.args.get('name')\n"
    "    sql = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
)
SUPPRESSION_CASES = {
    "inline.py": (
        SQL_SOURCE + "    return cursor.execute(sql)  # nosemgrep\n",
        "python-sql-tainted-execute",
    ),
    "above.py": (
        SQL_SOURCE
        + "    # nosemgrep: python-sql-tainted-execute\n    return cursor.execute(sql)\n",
        "python-sql-tainted-execute",
    ),
    "lfi.php": (
        "<?php\n$path = $_GET['page'];\ninclude $path; // nosemgrep\n",
        "php-local-file-inclusion",
    ),
    "rfi.php": (
        '<?php\ninclude("https://plugins.example.invalid/module.php"); // nosemgrep\n',
        "php-remote-file-inclusion",
    ),
}


def verify_suppression(root: Path):
    source = root / "suppression"
    source.mkdir()
    for name, (code, _) in SUPPRESSION_CASES.items():
        (source / name).write_text(code, encoding="utf-8")
    raw = root / "suppression.json"
    run_semgrep(source, raw)
    findings = parse_semgrep_json(raw)
    actual = Counter(
        (Path(f.location.rsplit(":", 1)[0]).name, f.title) for f in findings
    )
    expected = Counter((name, rule) for name, (_, rule) in SUPPRESSION_CASES.items())
    if actual != expected:
        raise ValueError(
            f"Source comments suppressed or changed findings: expected {expected}, got {actual}"
        )
    return len(findings)


def verify():
    with TemporaryDirectory(prefix="sast-contract-") as directory:
        root = Path(directory)
        clean = root / "clean"
        clean.mkdir()
        (clean / "example.py").write_text("pass\n", encoding="utf-8")
        clean_raw = root / "clean.json"
        run_semgrep(clean, clean_raw)
        if parse_semgrep_json(clean_raw):
            raise ValueError("The clean source produced unexpected findings")
        clean_data = json.loads(clean_raw.read_text(encoding="utf-8"))
        if len(clean_data["paths"]["scanned"]) != 1:
            raise ValueError("Expected exactly one clean source file scanned")

        suppression_findings = verify_suppression(root)

        no_code = root / "no-code"
        no_code.mkdir()
        (no_code / "notes.txt").write_text(
            "No supported source code here.\n", encoding="utf-8"
        )
        empty_raw = root / "no-code.json"
        run_semgrep(no_code, empty_raw)
        empty_data = json.loads(empty_raw.read_text(encoding="utf-8"))
        if empty_data.get("errors") != [] or empty_data["paths"]["scanned"] != []:
            raise ValueError("Unexpected no-code scanner response")
        try:
            parse_semgrep_json(empty_raw)
        except ValueError:
            return {
                "clean_files": 1,
                "clean_findings": 0,
                "no_code_scan": "rejected",
                "suppression_findings": suppression_findings,
            }
        raise ValueError("A scan of zero source files was accepted as clean")


def main():
    print("SAST contract passed: " + json.dumps(verify(), sort_keys=True))


if __name__ == "__main__":
    main()
