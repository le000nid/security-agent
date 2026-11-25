#!/usr/bin/env python3
"""v6 part 3: platform hardening — security headers, rate limit, size caps."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
W = ROOT / "app" / "web.py"


def patch(old: str, new: str) -> None:
    s = W.read_text(encoding="utf-8")
    assert old in s, f"anchor not found: {old[:60]!r}"
    s = s.replace(old, new, 1)
    W.write_text(s, encoding="utf-8")


# 1. imports: time + deque for the rate limiter
patch(
    """import secrets
from pathlib import Path""",
    """import secrets
import time
from collections import deque
from pathlib import Path""",
)

# 2. constants next to GUARD_ERRORS
patch(
    """# codes raised by app.http_guard — surfaced as 400, never echoing the input
GUARD_ERRORS = {""",
    """# brute-force resistance: POSTs are throttled per sliding window
POST_RATE_LIMIT = 30  # max POSTs ...
POST_RATE_WINDOW = 60.0  # ... per this many seconds
MAX_QUERY_CHARS = 2_000  # a longer query string is an attack, not a filter
MAX_HEADERS = 60  # header-count cap (request smuggling / parser abuse)

# codes raised by app.http_guard — surfaced as 400, never echoing the input
GUARD_ERRORS = {""",
)

# 3. add rate-limit error code + guards in the middleware
patch(
    """    "input_too_long",
    "path_outside_base",
}""",
    """    "input_too_long",
    "path_outside_base",
    "rate_limited",
    "query_too_long",
    "too_many_headers",
}""",
)

patch(
    """        if not valid_host:
            return JSONResponse({"error": "host_not_allowed"}, status_code=403)
        if request.method == "POST":""",
    """        if not valid_host:
            return JSONResponse({"error": "host_not_allowed"}, status_code=403)
        # header-count cap: parser abuse and smuggling helpers
        if len(request.headers) > MAX_HEADERS:
            return JSONResponse({"error": "too_many_headers"}, status_code=400)
        # query budget: long encoded chains are traversal probes, not filters
        if len(request.url.query) > MAX_QUERY_CHARS:
            return JSONResponse({"error": "query_too_long"}, status_code=414)
        if request.method == "POST":
            now = time.monotonic()
            bucket = request.app.state.post_times
            while bucket and now - bucket[0] > POST_RATE_WINDOW:
                bucket.popleft()
            if len(bucket) >= POST_RATE_LIMIT:
                return JSONResponse({"error": "rate_limited"}, status_code=429)
            bucket.append(now)""",
)

# 4. init the bucket on app.state
patch(
    """    app.state.jobs, app.state.repository, app.state.chat = jobs, repository, chat""",
    """    app.state.jobs, app.state.repository, app.state.chat = jobs, repository, chat
    app.state.post_times = deque()""",
)

# 5. richer security headers
patch(
    """        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response""",
    """        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response""",
)

print("web.py hardened for v6")
