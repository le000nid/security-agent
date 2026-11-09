"""Optional real-scanner smoke check: run inside the agent image with --network none."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from app.main import run
from app.semgrep import parse_semgrep_json, run_semgrep
from benchmark.evaluator import evaluate


class LocalHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()
        self.wfile.write(b"Local HTTP fixture")

    def log_message(self, *_args):
        pass


def main():
    original = Path.cwd()
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TemporaryDirectory(prefix="agent-smoke-") as folder:
            os.chdir(folder)
            source = Path(folder) / "fixture.py"
            source.write_text(
                "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
            )
            assert (
                run(
                    [
                        "--mode",
                        "full",
                        "--target-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--source-path",
                        str(source),
                        "--no-llm",
                    ]
                )
                == 0
            )
            results = json.loads(Path("reports/findings.json").read_text())
            assert {finding["source"] for finding in results} == {"SAST", "DAST"}
            assert all("raw" not in finding for finding in results)
            assert Path("logs/raw_semgrep.json").is_file()
            assert Path("logs/raw_nuclei.jsonl").is_file()
            print("Real Semgrep + Nuclei smoke check passed with network disabled")
            os.chdir(original)

        with TemporaryDirectory(prefix="benchmark-smoke-") as folder:
            os.chdir(folder)
            raw = Path("raw_semgrep.json")
            run_semgrep(Path("/agent/targets/sample-app"), raw)
            actual = [finding.model_dump() for finding in parse_semgrep_json(raw)]
            expected = json.loads(
                Path("/agent/benchmark/expected_findings.json").read_text()
            )
            benchmark = evaluate(actual, expected)
            assert benchmark["recall"] == 1.0, benchmark
            assert benchmark["unexpected_findings"] == [], benchmark
            print("Curated Semgrep benchmark detected every expected fixture")
    finally:
        os.chdir(original)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
