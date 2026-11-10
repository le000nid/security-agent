"""Run real Nuclei against bounded HTTP fixtures; this does not test MongoDB."""

import argparse
import json
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.parser import parse_nuclei_jsonl
from app.report import generate_markdown_report
from app.resources import config_directory
from app.scanner_env import scanner_environment
from benchmark.verify_nosqli import load_scenarios


def verify(nuclei: str) -> list[dict]:
    scenarios = load_scenarios()
    expected_ids = {case["nuclei_id"] for case in scenarios}
    templates = [
        config_directory() / "nuclei" / f"{name}.yaml" for name in sorted(expected_ids)
    ]
    results = []
    for mode in (
        "positive-fixture",
        "safe-fixture",
        "identical",
        "empty",
        "http-error",
        "malformed-json",
        "reflection",
        "unmarked",
        "wrong-content-type",
    ):

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 8192:
                    self.send_error(413)
                    return
                raw = self.rfile.read(length)
                case = next(
                    (s for s in scenarios if self.path.endswith("/" + s["route"])), None
                )
                if case is None:
                    self.send_error(404)
                    return
                value = json.loads(raw)
                status = 200
                ids = case["baseline_ids"]
                if value == case["probe"]:
                    ids = case["probe_ids"]
                    if mode == "safe-fixture":
                        status = 400
                elif value == case["control"]:
                    ids = []
                body = {"status": "success", "data": [{"_id": item} for item in ids]}
                if mode == "identical":
                    body["data"] = [{"_id": item} for item in case["baseline_ids"]]
                elif mode == "empty":
                    body["data"] = []
                elif mode == "http-error":
                    status = 500
                elif mode == "reflection":
                    body = {"status": "success", "data": [], "reflected": value}
                encoded = json.dumps(body, separators=(",", ":")).encode()
                if mode == "malformed-json":
                    encoded = encoded[:-1]
                self.send_response(status)
                content_type = (
                    "text/html" if mode == "wrong-content-type" else "application/json"
                )
                self.send_header("Content-Type", content_type)
                if mode != "unmarked":
                    self.send_header("X-NoSQLi-Lab", "mongodb-v1")
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="nosqli-nuclei-") as temporary:
                output = Path(temporary) / "results.jsonl"
                command = [
                    nuclei,
                    "-u",
                    f"http://127.0.0.1:{server.server_port}",
                    "-jsonl",
                    "-o",
                    str(output),
                    "-silent",
                    "-disable-update-check",
                    "-no-interactsh",
                    "-disable-redirects",
                ]
                for template in templates:
                    command.extend(["-t", str(template)])
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=45,
                    env=scanner_environment(temporary),
                )
                if completed.returncode:
                    raise ValueError(
                        f"Nuclei failed for {mode}: {completed.stderr[-500:]}"
                    )
                records = (
                    [
                        json.loads(line)
                        for line in output.read_text().splitlines()
                        if line.strip()
                    ]
                    if output.exists()
                    else []
                )
                detected = {record["template-id"] for record in records}
                expected = expected_ids if mode == "positive-fixture" else set()
                if detected != expected or len(records) != len(expected):
                    raise ValueError(
                        f"{mode}: expected {expected}, received {detected}"
                    )
                if mode == "positive-fixture" and any(
                    not record.get("extracted-results") for record in records
                ):
                    raise ValueError("Nuclei did not preserve comparison evidence")
                if mode == "positive-fixture":
                    findings = parse_nuclei_jsonl(output)
                    report = Path(temporary) / "report.md"
                    generate_markdown_report(
                        findings, "HTTP acceptance fixture", report
                    )
                    if (
                        not all(
                            all(
                                token in finding.evidence
                                for token in ("baseline=", "changed=", "control=")
                            )
                            for finding in findings
                        )
                        or "changed=" not in report.read_text()
                    ):
                        raise ValueError(
                            "Comparison evidence was lost in normalization/reporting"
                        )
                results.append(
                    {"fixture": mode, "findings": len(records), "status": "passed"}
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nuclei", default="nuclei")
    args = parser.parse_args()
    print(
        json.dumps(
            {"scope": "HTTP fixtures, not MongoDB", "results": verify(args.nuclei)},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
