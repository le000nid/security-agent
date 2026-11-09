import copy

import pytest

from benchmark.verify_nosqli_sast import verify


def sample(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    file = source / "example.js"
    file.write_text(
        "// ruleid: javascript-nosqli-example\n"
        "find(unsafe);\n"
        "// ok: javascript-nosqli-example\n"
        "find(safe);\n"
    )
    payload = {
        "errors": [],
        "paths": {"scanned": [str(file)]},
        "results": [
            {
                "path": str(file),
                "check_id": "config.javascript-nosqli-example",
                "start": {"line": 2},
            }
        ],
    }
    return source, file, payload


def test_exact_source_locations_are_checked(tmp_path):
    source, _, payload = sample(tmp_path)
    assert verify(payload, source) == {
        "status": "passed",
        "scanned_files": 1,
        "dangerous_cases": 1,
        "safe_cases": 1,
        "findings": 1,
    }


@pytest.mark.parametrize(
    "failure", ["missed", "safe", "duplicate", "unscanned", "error"]
)
def test_wrong_findings_and_incomplete_scans_are_rejected(tmp_path, failure):
    source, _, payload = sample(tmp_path)
    if failure == "missed":
        payload["results"] = []
    elif failure == "safe":
        payload["results"][0]["start"]["line"] = 4
    elif failure == "duplicate":
        payload["results"].append(copy.deepcopy(payload["results"][0]))
    elif failure == "unscanned":
        payload["paths"]["scanned"] = []
    else:
        payload["errors"] = [{"message": "parser failure"}]
    with pytest.raises(ValueError):
        verify(payload, source)
