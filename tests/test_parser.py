import json
from pathlib import Path

import pytest

from app.parser import NucleiParseError, parse_nuclei_jsonl, save_findings


def test_parse_and_save_nuclei_jsonl(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    raw.write_text(
        json.dumps(
            {
                "template-id": "test-template",
                "info": {
                    "name": "Test finding",
                    "severity": "medium",
                    "description": "A harmless test record",
                    "tags": ["test", "local"],
                },
                "matched-at": "http://localhost:3000/test",
                "matcher-name": "status",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    findings = parse_nuclei_jsonl(raw)

    assert len(findings) == 1
    assert findings[0].id.startswith("nuclei:")
    assert "raw" not in findings[0].model_dump()
    assert findings[0].raw_output_ref.endswith("#L1")
    assert findings[0].severity == "medium"
    assert findings[0].evidence == "status"
    output = tmp_path / "findings.json"
    save_findings(findings, output)
    assert json.loads(output.read_text(encoding="utf-8"))[0]["title"] == "Test finding"


def test_parse_reports_line_number_for_invalid_json(tmp_path: Path) -> None:
    raw = tmp_path / "raw.jsonl"
    raw.write_text("{}\nnot-json\n", encoding="utf-8")

    with pytest.raises(NucleiParseError, match="line 2"):
        parse_nuclei_jsonl(raw)
