import json
from pathlib import Path

from app import main


def test_cli_pipeline(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    def fake_nuclei(_target: str, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "template-id": "local-test",
                    "info": {"name": "Local test", "severity": "info"},
                    "matched-at": "http://localhost:3000",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(main, "run_nuclei", fake_nuclei)
    monkeypatch.setattr(main, "check_target_reachable", lambda _: None)

    result = main.run(
        ["--target-url", "http://localhost:3000", "--mode", "dast", "--no-llm"]
    )

    assert result == 0
    assert (tmp_path / "logs/raw_nuclei.jsonl").exists()
    assert (tmp_path / "reports/findings.json").exists()
    assert (tmp_path / "reports/report.md").exists()


def test_cli_rejects_external_target(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    assert main.run(["--target-url", "https://example.com", "--no-llm"]) == 1
    assert not (tmp_path / "logs/raw_nuclei.jsonl").exists()


def test_cli_requires_llm_configuration(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLM_PROVIDER", "")
    monkeypatch.setattr(main, "check_target_reachable", lambda _: None)

    def fake_nuclei(_target: str, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("", encoding="utf-8")

    monkeypatch.setattr(main, "run_nuclei", fake_nuclei)
    assert main.run(["--target-url", "http://localhost:3000"]) == 1
    assert (tmp_path / "reports/findings.json").is_file()
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert summary["llm_status"] == "failed"
