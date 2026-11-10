"""Read-only HTTP acceptance checks against the real NoSQLi MongoDB lab."""

import argparse
import json
from pathlib import Path

import httpx

from app.resources import config_directory
from app.validation import validate_target_url


def load_scenarios() -> list[dict]:
    scenarios = json.loads(
        (config_directory() / "nosqli-scenarios.json").read_text(encoding="utf-8")
    )
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Missing NoSQLi scenario inventory")
    ids = [item["id"] for item in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate NoSQLi scenario ID")
    return scenarios


def response_ids(response: httpx.Response) -> list[str]:
    if response.status_code != 200:
        raise ValueError(f"Expected HTTP 200, received {response.status_code}")
    if response.headers.get("X-NoSQLi-Lab") != "mongodb-v1":
        raise ValueError("Response is not from the expected MongoDB lab")
    if "application/json" not in response.headers.get("Content-Type", ""):
        raise ValueError("Expected a JSON response")
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise ValueError("Response does not report a successful query")
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("Query result must be an array")
    ids = []
    for record in data:
        if not isinstance(record, dict) or not isinstance(record.get("_id"), str):
            raise ValueError("Query record has no string ID")
        ids.append(record["_id"])
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate record IDs in response")
    return sorted(ids)


def verify(client: httpx.Client, target: str, scenarios: list[dict]) -> dict:
    results = []
    for scenario in scenarios:
        entry = {"id": scenario["id"], "mechanism": scenario["mechanism"]}
        for prefix in ("vulnerable", "safe"):
            path = f"{target}/{prefix}/{scenario['route']}"
            baseline = response_ids(client.post(path, json=scenario["baseline"]))
            control = response_ids(client.post(path, json=scenario["control"]))
            if baseline != sorted(scenario["baseline_ids"]) or control:
                raise ValueError(f"{scenario['id']}: invalid {prefix} baseline/control")
            probe = client.post(path, json=scenario["probe"])
            if prefix == "vulnerable":
                changed = response_ids(probe)
                if changed != sorted(scenario["probe_ids"]):
                    raise ValueError(f"{scenario['id']}: unexpected query result")
                entry["baseline_ids"] = baseline
                entry["probe_ids"] = changed
                entry["control_ids"] = control
            else:
                body = probe.json()
                if (
                    probe.status_code != 400
                    or probe.headers.get("X-NoSQLi-Lab") != "mongodb-v1"
                    or not isinstance(body, dict)
                    or body.get("status") != "error"
                    or "data" in body
                ):
                    raise ValueError(f"{scenario['id']}: safe route accepted the probe")
                entry["safe_probe_status"] = probe.status_code
        entry["status"] = "passed"
        results.append(entry)
    return {
        "status": "passed",
        "scenarios": results,
        "checked_variants": len(results) * 2,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-url", default="http://nosqli-mongo-api:3000")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        target = validate_target_url(args.target_url)
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            result = verify(client, target, load_scenarios())
    except (ValueError, KeyError, TypeError, httpx.HTTPError) as error:
        raise SystemExit(f"NoSQLi verification failed: {error}") from error
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
