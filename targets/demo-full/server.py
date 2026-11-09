"""Intentionally vulnerable educational fixture. Never use as production code.

Only a constant HTTP response is served. The source-only unsafe examples in
training_patterns.py are never imported or called by this server.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Demo Full: local educational security benchmark\n"
        self.send_response_only(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Access-Control-Allow-Origin", "*")
        # CSP and Referrer-Policy intentionally absent for reviewed GET checks.
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return  # Never echo attacker-controlled request strings.


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
