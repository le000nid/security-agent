"""Check real Semgrep output against annotated NoSQLi API source locations."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

MARKER = re.compile(r"\s*//\s*(ruleid|ok): (javascript-nosqli-[a-z-]+)\s*")


def verify(payload: dict, source: Path) -> dict:
    files = {p.resolve() for p in source.rglob("*.js")}
    if not files or payload.get("errors") != []:
        raise ValueError("No source files or Semgrep reported errors")
    scanned = {Path(p).resolve() for p in payload["paths"]["scanned"]}
    if scanned != files:
        raise ValueError("Semgrep did not scan exactly the expected source files")
    expected, safe = Counter(), Counter()
    for file in files:
        lines = file.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            marker = MARKER.fullmatch(line)
            if marker:
                if index + 1 >= len(lines) or not lines[index + 1].strip():
                    raise ValueError("Annotation is not followed by code")
                key = (str(file), marker[2], index + 2)
                (expected if marker[1] == "ruleid" else safe)[key] += 1
    actual = Counter(
        (
            str(Path(record["path"]).resolve()),
            record["check_id"].rsplit(".", 1)[-1],
            record["start"]["line"],
        )
        for record in payload["results"]
    )
    if not expected or not safe or actual != expected:
        raise ValueError(
            f"NoSQLi SAST mismatch: missing={list((expected - actual).elements())}; "
            f"unexpected={list((actual - expected).elements())}"
        )
    return {
        "status": "passed",
        "scanned_files": len(files),
        "dangerous_cases": expected.total(),
        "safe_cases": safe.total(),
        "findings": actual.total(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_semgrep", type=Path)
    parser.add_argument("--source", type=Path, default=Path("targets/nosqli-lab/src"))
    args = parser.parse_args()
    payload = json.loads(args.raw_semgrep.read_text(encoding="utf-8"))
    print(json.dumps(verify(payload, args.source), indent=2))


if __name__ == "__main__":
    main()
