"""Local fixture exposing only a synthetic training key."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

api_key = "TRAINING_KEY_SECURITY_AGENT_74B2"
safe_key = os.getenv("TRAINING_RUNTIME_KEY", "not-configured")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200
        if self.path == "/healthz":
            payload = {"status": "ready"}
        elif self.path == "/key/exposed":
            payload = {"training_key": api_key, "synthetic": True}
        elif self.path == "/key/safe":
            payload = {"configured": safe_key != "not-configured", "synthetic": True}
        else:
            status, payload = 404, {"error": "not_found"}
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
            "X-Security-Key-Lab": "synthetic-v1",
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
