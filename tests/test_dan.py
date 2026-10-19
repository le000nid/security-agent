"""DAN fixture and integration contracts, without provider or network access."""

import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import quote

import pytest
import yaml

from app.benchmarks import BenchmarkRegistry

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "dan_server", ROOT / "targets/dan-lab/server.py"
)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def response(path):
    sock = Mock()
    sock.makefile.return_value = io.BytesIO(
        f"GET {path} HTTP/1.0\r\nHost: dan-lab\r\n\r\n".encode()
    )
    server.Handler(sock, ("127.0.0.1", 12345), Mock())
    raw = b"".join(call.args[0] for call in sock.sendall.call_args_list)
    headers, body = raw.split(b"\r\n\r\n", 1)
    return headers.decode(), json.loads(body)


@pytest.mark.parametrize("endpoint", ["/dan/chat", "/dan/protected"])
def test_benign_prompt_never_discloses_marker(endpoint):
    headers, body = response(endpoint + "?prompt=Hello")
    assert "200 OK" in headers
    assert body["simulated"] is True
    assert server.MARKER not in body["response"]


def test_dan_probe_discloses_only_on_vulnerable_endpoint():
    query = "?prompt=" + quote(server.PROBE)
    _, vulnerable = response("/dan/chat" + query)
    _, protected = response("/dan/protected" + query)
    assert vulnerable["response"] == server.MARKER
    assert server.MARKER not in protected["response"]
    assert "training_patterns" not in vars(server)


@pytest.mark.parametrize("path", ["/dan/chat", "/dan/chat?prompt=a&prompt=b"])
def test_invalid_prompt_returns_no_marker(path):
    headers, body = response(path)
    assert "400 Bad Request" in headers
    assert server.MARKER not in json.dumps(body)


def test_unknown_route_and_bounded_request():
    assert "404 Not Found" in response("/unknown")[0]
    assert "HTTP/1.0 414 " in response("/" + "x" * 4096)[0]


def test_registry_and_compose_connect_same_fixture():
    benchmark = BenchmarkRegistry.load().get("dan-lab")
    assert benchmark.resolve_mode() == "full"
    assert benchmark.ui_metadata()["baseline_count"] == 2
    assert Path(benchmark.local_source()).is_dir()
    assert benchmark.description_ru
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    service = compose["services"][benchmark.docker_service]
    assert service["ports"] == ["127.0.0.1:3002:3000"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
