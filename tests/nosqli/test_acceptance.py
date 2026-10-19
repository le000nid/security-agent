"""Test rejection paths of the HTTP acceptance checker without network access."""

import json
from pathlib import Path

import httpx
import pytest

from app.benchmarks import BenchmarkRegistry
from benchmark.verify_nosqli import load_scenarios, response_ids, verify

HEADERS = {"X-NoSQLi-Lab": "mongodb-v1", "Content-Type": "application/json"}


def response(ids=(), *, status=200, headers=None, body=None):
    return httpx.Response(
        status,
        headers=HEADERS if headers is None else headers,
        json=body
        if body is not None
        else {"status": "success", "data": [{"_id": key} for key in ids]},
    )


@pytest.mark.parametrize(
    "value",
    [
        response(status=500),
        response(headers={"Content-Type": "application/json"}),
        response(headers={"X-NoSQLi-Lab": "mongodb-v1", "Content-Type": "text/html"}),
        response(body=[]),
        response(body={"status": "success", "data": "not an array"}),
        response(body={"status": "success", "data": [{"message": "reflected input"}]}),
        response(body={"status": "error", "data": []}),
        response(["duplicate", "duplicate"]),
    ],
)
def test_invalid_response_cannot_confirm_query_manipulation(value):
    with pytest.raises(ValueError):
        response_ids(value)


def test_same_response_for_all_requests_is_rejected():
    transport = httpx.MockTransport(lambda _: response(["catalog-apple"]))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="baseline/control"):
            verify(client, "http://localhost:3005", load_scenarios())


def test_inventory_verification_requires_all_safe_and_vulnerable_variants():
    scenarios = load_scenarios()

    def handle(request):
        scenario = next(
            s for s in scenarios if request.url.path.endswith("/" + s["route"])
        )
        body = json.loads(request.content)
        if body == scenario["probe"]:
            if request.url.path.startswith("/safe/"):
                return response(
                    status=400, body={"status": "error", "error": "Rejected"}
                )
            return response(scenario["probe_ids"])
        if body == scenario["baseline"]:
            return response(scenario["baseline_ids"])
        return response([])

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = verify(client, "http://localhost:3005", scenarios)
    assert result["checked_variants"] == 6
    assert {s["id"] for s in result["scenarios"]} == {s["id"] for s in scenarios}


def test_mongo_benchmark_uses_same_source_and_api():
    benchmark = BenchmarkRegistry.load().get("nosqli-mongo-full")
    assert benchmark.resolve_mode() == "full"
    assert benchmark.target_url == "http://nosqli-mongo-api:3000"
    assert Path(benchmark.local_source()).joinpath("routes/operator.js").is_file()


def test_database_is_not_published_and_api_is_local_only():
    import yaml

    root = Path(__file__).resolve().parents[2]
    config = yaml.safe_load((root / "docker-compose.nosqli.yml").read_text())
    mongo = config["services"]["nosqli-mongo"]
    api = config["services"]["nosqli-mongo-api"]
    assert "ports" not in mongo
    assert mongo["networks"] == ["nosqli-db"]
    assert config["networks"]["nosqli-db"]["internal"] is True
    assert api["ports"] == ["127.0.0.1:3005:3000"]
    assert api["depends_on"]["nosqli-mongo"]["condition"] == "service_healthy"
