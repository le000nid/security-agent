import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from app.repository import RunRepository
from app.service import RunRequest
from benchmark.verify_run import verify

ROOT = Path(__file__).resolve().parent.parent


def test_demo_http_contract_without_network_or_fixture_execution():
    spec = importlib.util.spec_from_file_location(
        "demo_server", ROOT / "targets/demo-full/server.py"
    )
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
    for path in ("/", "/healthz", "/?command=anything"):
        socket = Mock()
        socket.makefile.return_value = io.BytesIO(
            f"GET {path} HTTP/1.0\r\nHost: demo-full\r\n\r\n".encode()
        )
        server.Handler(socket, ("127.0.0.1", 12345), Mock())
        response = b"".join(call.args[0] for call in socket.sendall.call_args_list)
        assert b"200 OK" in response
        assert b"Access-Control-Allow-Origin: *" in response
        assert b"Content-Security-Policy" not in response
        assert b"Referrer-Policy" not in response
        assert b"Server:" not in response
        assert response.endswith(b"Demo Full: local educational security benchmark\n")
    assert "training_patterns" not in vars(server)


def test_registry_baselines_preserve_sample_and_demo():
    old = json.loads((ROOT / "benchmark/expected_findings.json").read_text())
    assert old == json.loads((ROOT / "config/expected/sample-sast.json").read_text())
    assert len(old) == 9
    demo = json.loads((ROOT / "config/expected/demo-full.json").read_text())
    assert len(demo) == 7
    rules = yaml.safe_load((ROOT / "config/semgrep.yaml").read_text())["rules"]
    assert {f["title"] for f in demo if f["source"] == "SAST"} <= {
        r["id"] for r in rules
    }
    templates = [
        yaml.safe_load(p.read_text()) for p in (ROOT / "config/nuclei").glob("*.yaml")
    ]
    assert {f["title"] for f in demo if f["source"] == "DAST"} <= {
        t["info"]["name"] for t in templates
    }


def test_compose_ui_and_demo_security():
    services = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    assert services["ui"]["image"] == services["agent"]["image"]
    assert "depends_on" not in services["agent"]
    assert services["ui"]["ports"] == ["127.0.0.1:8080:8080"]
    assert services["demo-full"]["ports"] == ["127.0.0.1:3001:3000"]
    assert services["juice-shop"]["image"] == "bkimminich/juice-shop:v20.2.0"
    for name in ("agent", "ui", "demo-full"):
        s = services[name]
        assert not s.get("privileged") and s["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in s["security_opt"]
        assert not any("docker.sock" in mount for mount in s.get("volumes", []))


def test_json_redaction_preserves_syntax(tmp_path, monkeypatch):
    run = tmp_path / "20200101T000000Z-000000000000" / "reports"
    run.mkdir(parents=True)
    monkeypatch.setenv("LLM_API_KEY", 'private-"quoted"-key')
    (run / "summary.json").write_text(
        json.dumps({"total": 0, "note": 'private-"quoted"-key'})
    )
    summary = RunRepository(tmp_path).summary(run.parent.name)
    assert summary["note"] == "[REDACTED]"


def test_low_level_network_remains_blocked():
    import socket

    with socket.socket() as sock, pytest.raises(AssertionError, match="Real network"):
        sock.connect(("127.0.0.1", 8080))


def test_smoke_verifier_contract(tmp_path, monkeypatch):
    from test_v040_service import service

    runner = service.__wrapped__(tmp_path, monkeypatch)
    result = runner.run(RunRequest(benchmark_id="demo-full"))
    repository = RunRepository(runner.runs_dir)
    assert verify(repository)["llm_requests"] == 0
    path = repository.path(result.run_id, "summary.json")
    data = json.loads(path.read_text())
    data["llm_usage"]["total"]["requests"] = 1
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="LLM"):
        verify(repository)
