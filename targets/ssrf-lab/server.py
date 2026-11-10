"""Deterministic local SSRF simulation; performs no outbound HTTP requests."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

MARKER = "SSRF_LAB_INTERNAL_4f12"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        resource = parse_qs(parsed.query).get("resource", [""])[0]
        status = 200
        if parsed.path == "/healthz":
            payload = {"status": "ready", "simulation": True}
        elif parsed.path == "/ssrf/fetch" and resource == "internal":
            payload = {"simulation": True, "content": MARKER}
        elif parsed.path == "/ssrf/safe":
            payload = {"simulation": True, "content": "public-status-only"}
        else:
            status, payload = 404, {"error": "fixed_local_resource_required"}
        body = json.dumps(payload).encode()
        self.send_response_only(status)
        for name, value in {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-SSRF-Lab": "local-simulation-v1",
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
