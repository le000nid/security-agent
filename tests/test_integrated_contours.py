"""Contracts for the integrated local-only training contours."""

import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from app.benchmarks import BenchmarkRegistry

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "sample-sast",
    "juice-shop",
    "demo-full",
    "sast-contours",
    "dan-lab",
    "nosqli-sast",
    "nosqli-dast",
    "nosqli-mongo-full",
    "ssrf-lab",
    "spoofing-sast",
    "security-key-lab",
    "nosqli-profile-catalog",
    "nosqli-profile-catalog-safe",
    "nosqli-profile-inventory",
    "nosqli-profile-inventory-safe",
    "nosqli-sast-matrix",
}


def load_server(name):
    path = ROOT / "targets" / name / "server.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(module, path):
    sock = Mock()
    sock.makefile.return_value = io.BytesIO(
        f"GET {path} HTTP/1.0\r\nHost: local-lab\r\n\r\n".encode()
    )
    module.Handler(sock, ("127.0.0.1", 12345), Mock())
    raw = b"".join(call.args[0] for call in sock.sendall.call_args_list)
    headers, body = raw.split(b"\r\n\r\n", 1)
    return headers.decode(), json.loads(body)


def test_registry_is_complete_unique_and_same_project_full():
    registry = BenchmarkRegistry.load()
    assert {item.id for item in registry.list()} == EXPECTED
    for benchmark_id in (
        "demo-full",
        "dan-lab",
        "nosqli-mongo-full",
        "ssrf-lab",
        "security-key-lab",
    ):
        benchmark = registry.get(benchmark_id)
        assert benchmark.resolve_mode() == "full"
        assert "same-application" in benchmark.tags
        assert Path(benchmark.local_source()).is_dir()
        assert benchmark.target_url.startswith(
            "http://" + benchmark.docker_service + ":"
        )
    data = yaml.safe_load((ROOT / "config/benchmarks.yaml").read_text(encoding="utf-8"))
    assert len({item["id"] for item in data}) == len(data)


def test_rule_and_template_ids_are_unique():
    rules = yaml.safe_load((ROOT / "config/semgrep.yaml").read_text(encoding="utf-8"))[
        "rules"
    ]
    assert len({rule["id"] for rule in rules}) == len(rules)
    ids = []
    for path in (ROOT / "config/nuclei").glob("*.yaml"):
        ids.append(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])
    assert len(ids) == len(set(ids))


def test_ssrf_simulation_has_vulnerable_and_safe_controls():
    server = load_server("ssrf-lab")
    vulnerable_headers, vulnerable = response(server, "/ssrf/fetch?resource=internal")
    safe_headers, safe = response(server, "/ssrf/safe?resource=internal")
    assert vulnerable["content"] == server.MARKER
    assert server.MARKER not in json.dumps(safe)
    for headers in (vulnerable_headers, safe_headers):
        assert "Content-Security-Policy:" in headers
        assert "X-Content-Type-Options: nosniff" in headers
        assert "Server:" not in headers
    source = (ROOT / "targets/ssrf-lab/server.py").read_text(encoding="utf-8")
    assert "urllib.request.urlopen(" not in source and "\nrequests." not in source
    assert (
        "169.254.169.254"
        not in (ROOT / "targets/ssrf-lab/training_patterns.py").read_text()
    )


def test_security_key_is_synthetic_and_safe_control_hides_it(monkeypatch):
    monkeypatch.delenv("TRAINING_RUNTIME_KEY", raising=False)
    server = load_server("security-key-lab")
    exposed_headers, exposed = response(server, "/key/exposed")
    safe_headers, safe = response(server, "/key/safe")
    assert exposed["training_key"] == server.api_key
    assert server.api_key.startswith("TRAINING_KEY_")
    assert server.api_key not in json.dumps(safe)
    for headers in (exposed_headers, safe_headers):
        assert "Content-Security-Policy:" in headers
        assert "X-Content-Type-Options: nosniff" in headers
        assert "Server:" not in headers
    source = (ROOT / "targets/security-key-lab/server.py").read_text(encoding="utf-8")
    assert ".env" not in source and ".aws" not in source


def test_spoofing_fixture_is_static_only_and_compose_has_no_packet_capabilities():
    source = (ROOT / "targets/spoofing-sast/vulnerable.py").read_text(encoding="utf-8")
    assert "ARP(op=2" in source and "DNSRR(" in source
    assert "send(" not in source and "sendp(" not in source
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    serialized = json.dumps(compose)
    for forbidden in ("NET_ADMIN", "NET_RAW", "host_network", "/var/run/docker.sock"):
        assert forbidden not in serialized
    assert compose["services"]["nosqli-mongo"]["user"] == "999:999"
    assert compose["services"]["nosqli-mongo"]["cap_drop"] == ["ALL"]


def test_scanner_runtime_home_is_chowned_after_build_time_version_checks():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    version_checks = dockerfile.index("semgrep --version && nuclei -version")
    runtime_chown = dockerfile.index(
        "chown -R agent:agent logs reports runs /tmp/agent-home"
    )
    assert version_checks < runtime_chown


@pytest.mark.parametrize(
    "benchmark_id", ["ssrf-lab", "spoofing-sast", "security-key-lab"]
)
def test_new_baselines_are_present(benchmark_id):
    benchmark = BenchmarkRegistry.load().get(benchmark_id)
    baseline = json.loads(
        (ROOT / "config/expected" / benchmark.expected_findings).read_text(
            encoding="utf-8"
        )
    )
    assert baseline and benchmark.ui_metadata()["baseline_count"] == len(baseline)


def test_registered_labs_do_not_share_host_ports():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    published = {}
    for name, service in compose["services"].items():
        for value in service.get("ports", []):
            host, port, _ = value.split(":")
            endpoint = (host, port)
            assert endpoint not in published, (name, published.get(endpoint), endpoint)
            published[endpoint] = name
    assert published[("127.0.0.1", "3006")] == "ssrf-lab"
    assert published[("127.0.0.1", "3008")] == "nosqli-portable-api"


def test_nosqli_overlay_contains_only_test_service():
    overlay = yaml.safe_load((ROOT / "docker-compose.nosqli.yml").read_text())
    assert set(overlay["services"]) == {"nosqli-mongo-tests"}
    assert (
        overlay["services"]["nosqli-mongo-tests"]["image"]
        == "ai-security-nosqli-lab:0.4.1"
    )
