"""Shared exact acceptance checks for independently annotated scanner fixtures."""

import re
from collections import Counter
from pathlib import PurePosixPath

MARKER = re.compile(r"\s*(?://|#)\s*(ruleid|ok): ([a-z0-9-]+)\s*")


def expectations(fixtures, files):
    present = {
        p.name for p in fixtures.iterdir() if p.suffix in {".js", ".ts", ".py", ".php"}
    }
    if present != files:
        raise ValueError(f"Fixture inventory mismatch: {sorted(present ^ files)}")
    expected, safe = Counter(), Counter()
    for name in sorted(files):
        lines = (fixtures / name).read_text(encoding="utf-8").splitlines()
        annotated = False
        for index, line in enumerate(lines):
            marker = MARKER.fullmatch(line)
            if marker is None:
                continue
            kind, rule = marker.groups()
            if index + 1 >= len(lines) or not lines[index + 1].strip():
                raise ValueError(f"Annotation without code: {name}:{index + 1}")
            if (kind == "ruleid") != name.startswith("vulnerable-"):
                raise ValueError(f"Wrong annotation type: {name}:{index + 1}")
            (expected if kind == "ruleid" else safe)[(name, rule, index + 2)] += 1
            annotated = True
        if not annotated:
            raise ValueError(f"Fixture has no annotations: {name}")
    return expected, safe


def fixture_name(value, fixtures, files):
    if not isinstance(value, str):
        raise TypeError("Expected a string scan path")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.parent.name != fixtures.name or path.name not in files:
        raise ValueError(f"Unexpected scan path: {value}")
    return path.name


def verify(payload, fixtures, files):
    expected, safe = expectations(fixtures, files)
    if not isinstance(payload, dict) or payload.get("errors") != []:
        raise ValueError("Missing errors array or Semgrep reported scan errors")
    scanned = payload["paths"]["scanned"]
    if not isinstance(scanned, list):
        raise TypeError("Expected a scanned paths array")
    # Generic rules can also scan the suite's documentation. It is optional
    # scan input, never an allowed finding or a replacement for a code fixture.
    docs = {"README.md"} if (fixtures / "README.md").is_file() else set()
    names = Counter(fixture_name(p, fixtures, files | docs) for p in scanned)
    if set(names) - docs != files or any(count != 1 for count in names.values()):
        raise ValueError("Not all expected fixtures were scanned exactly once")
    if not isinstance(payload.get("results"), list):
        raise TypeError("Expected a results array")
    actual = Counter()
    for item in payload["results"]:
        line = item["start"]["line"]
        if type(line) is not int or line < 1:
            raise ValueError("Invalid finding line")
        actual[
            (
                fixture_name(item["path"], fixtures, files),
                item["check_id"].rsplit(".", 1)[-1],
                line,
            )
        ] += 1
    if actual != expected:
        raise ValueError(
            f"Missing: {list((expected - actual).elements())}; "
            f"unexpected: {list((actual - expected).elements())}"
        )
    return {
        "files": len(files),
        "dangerous_cases": expected.total(),
        "safe_cases": safe.total(),
        "findings": actual.total(),
    }
