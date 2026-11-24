"""A source comment must not silence independent audit findings."""

from types import SimpleNamespace

import pytest

from benchmark import verify_sast_contract as contract


@pytest.mark.parametrize("hidden", [None, *contract.SUPPRESSION_CASES])
def test_suppression_acceptance_requires_each_file_and_rule(
    tmp_path, monkeypatch, hidden
):
    monkeypatch.setattr(contract, "run_semgrep", lambda *_: None)
    findings = [
        SimpleNamespace(
            location=str(tmp_path / "suppression" / name) + ":5", title=rule
        )
        for name, (_, rule) in contract.SUPPRESSION_CASES.items()
        if name != hidden
    ]
    monkeypatch.setattr(contract, "parse_semgrep_json", lambda *_: findings)
    if hidden is None:
        assert contract.verify_suppression(tmp_path) == 4
    else:
        with pytest.raises(ValueError, match="suppressed or changed findings"):
            contract.verify_suppression(tmp_path)
