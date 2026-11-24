#!/usr/bin/env python3
"""v7 part 3: RFI defense — scheme detection in the request guard.

Adds ``no_scheme()``: decodes the value to its fixpoint and rejects any
URI-scheme shape, scheme-relative URL, backslash-URL or drive-letter form —
both in the RAW value and in the DECODED form, so ``%68ttp://``,
``php%3a//``, ``ht%74p://`` and ``data%3a`` all die regardless of how many
encoding layers the client used.

Applied to:
  * artifact filename (safe_segment already whitelists charset — belt) ;
  * findings filters severity/source/category (suspenders: clean_text only
    strips control bytes today, a scheme string would flow into equality
    filters — harmless there, but the guard must still say NO, because the
    next endpoint may not be an equality filter).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G = ROOT / "app" / "http_guard.py"


def patch(old: str, new: str) -> None:
    s = G.read_text(encoding="utf-8")
    assert old in s, f"anchor not found: {old[:70]!r}"
    s = s.replace(old, new, 1)
    G.write_text(s, encoding="utf-8")


patch(
    """ABSOLUTE_HINT = re.compile(r"^[a-zA-Z]:|^[\\\\/]|\\\\\\\\|(^|/)proc/self|^~")
# the only characters that may appear in a path segment on this platform
SEGMENT_CHARSET = re.compile(r"[A-Za-z0-9._-]+")""",
    """ABSOLUTE_HINT = re.compile(r"^[a-zA-Z]:|^[\\\\/]|\\\\\\\\|(^|/)proc/self|^~")
# the only characters that may appear in a path segment on this platform
SEGMENT_CHARSET = re.compile(r"[A-Za-z0-9._-]+")
# URI scheme at the start of a value (RFC 3986: ALPHA *( ALPHA / DIGIT /
# "+" / "-" / "." ) ":" ), allowing for leading whitespace/backslashes the
# client may smuggle past a naive regex
SCHEME_LEAD = re.compile(
    r"^[\\\\\\s]*[a-zA-Z][a-zA-Z0-9+.-]*\\s*:"
)
# known dangerous wrappers anywhere in the value (filter chains, expect,
# phar, data) — a legit filter/filename never contains them
WRAPPER_HINT = re.compile(
    r"(?i)php://|data:|expect://|phar://|zip://|file:|compress\\.|"
    r"glob://|ssh2\\.|ftp://|web://|svn://|mailto:|gopher://|"
    r"\\\\\\\\attacker|169\\.254\\.169\\.254|metadata\\.google|"
    r"kubernetes\\.default|\\.svc/|127\\.0\\.0\\.1|localhost:|0\\.0\\.0\\.0"
)""",
)

patch(
    """def clean_text(value: str, *, code: str = "invalid_text") -> str:""",
    '''def no_scheme(value: str, *, code: str = "invalid_uri_scheme") -> str:
    """Reject values that try to act as a URL/URI inclusion payload.

    Checks BOTH the raw value and the fully-decoded fixpoint: encoded
    colons (``php%3a//``), tab/space-padded schemes, double-encoded
    wrappers and scheme-relative ``//host`` forms are all scheme-bearing
    values no filter or filename parameter should ever carry.
    """
    raw = str(value)
    decoded = fully_decode(raw)
    for candidate in (raw, decoded):
        if SCHEME_LEAD.match(candidate):
            raise GuardError(code)
        if candidate.startswith("//") or candidate.startswith("\\\\\\\\"):
            raise GuardError(code)
        if WRAPPER_HINT.search(candidate):
            raise GuardError(code)
        # a single leading backslash before a scheme is a classic filter
        # dodge on Windows-adjacent stacks
        stripped = candidate.lstrip("\\\\ \\t")
        if SCHEME_LEAD.match(stripped):
            raise GuardError(code)
    return decoded


def clean_text(value: str, *, code: str = "invalid_text") -> str:''',
)

print("no_scheme() added to http_guard")
