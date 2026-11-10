import json

from app.parser import parse_nuclei_jsonl


def test_extracted_comparison_survives_normalization(tmp_path):
    raw = tmp_path / "nuclei.jsonl"
    raw.write_text(
        json.dumps(
            {
                "template-id": "nosqli-mongo-scalar-operator",
                "info": {
                    "name": "Operator injection",
                    "severity": "medium",
                    "tags": ["nosqli"],
                },
                "extracted-results": [
                    "baseline=catalog-apple; changed=catalog-banana; control=[]"
                ],
            }
        )
        + "\n"
    )
    finding = parse_nuclei_jsonl(raw)[0]
    assert "catalog-banana" in finding.evidence
    assert "nosqli-mongo-scalar-operator" in finding.evidence
    assert finding.raw_output_ref.endswith("#L1")


def test_evidence_is_bounded_and_falls_back_for_bad_extractions(tmp_path):
    raw = tmp_path / "nuclei.jsonl"
    for extracted in (["x" * 5000] * 10, {"unexpected": "object"}, [None, 42]):
        raw.write_text(
            json.dumps(
                {
                    "template-id": "rule",
                    "extracted-results": extracted,
                }
            )
            + "\n"
        )
        finding = parse_nuclei_jsonl(raw)[0]
        assert len(finding.evidence) <= 1200
        assert finding.evidence.startswith("rule")
