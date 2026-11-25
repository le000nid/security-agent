"""Request guard: one containment and validation seam for the web layer.

The CTF profiles demonstrate how naive request handling is bypassed in
practice — filter checks a raw value while the server reads a decoded one,
a duplicated parameter slips past validation, a null byte truncates a path
check, an absolute path discards the base directory. This module applies
the countermeasures to the platform's own HTTP surface, in one place:

* **Decode-then-validate.** Every path-ish input is percent-decoded
  (repeatedly, until stable) BEFORE any pattern check, so ``%2e%2e%2f`` and
  ``%252e%252e%252f`` never reach a validator as different strings than the
  ones the filesystem will eventually see.
* **No control bytes, no NUL.** A truncated path check (``...flag.txt\x00``
  ) is rejected outright.
* **Containment after canonicalization.** The final path must be a real
  descendant of the base directory (``Path.resolve`` + parent walk); an
  absolute input can never discard the base, symlink hops are resolved
  first and checked after.
* **Single-valued parameters.** HTTP parameter pollution (``?a=safe&a=evil``)
  is defused by refusing duplicated keys: the caller sees one value or a
  400, never a silently chosen "other" copy.
* **Header-safe output.** Reflected values used in response headers are
  checked for CR/LF to stop header injection.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

MAX_INPUT_CHARS = 512
MAX_DECODE_PASSES = 8

# Every character that can alter path/header semantics once decoded.
FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Characters that act as a path separator or query/fragment delimiter on
# SOME server stack once decoded: solidus lookalikes, fullwidth and math
# slashes, URL delimiters, path-parameter separators.
SEPARATOR_LOOKALIKES = (
    "\u2215"  # ∕ division slash
    "\u2216"  # ∖ set minus
    "\u2044"  # ⁄ fraction slash
    "\u2571"  # ╱ box light diagonal
    "\uff0f"  # ／ fullwidth solidus
    "\uff3c"  # ＼ fullwidth reverse solidus
    "\u27f8"  # ⟸ long leftwards double arrow (rare, but used)
    ";"  # path parameter injection (Tomcat ;jsessionid=)
    "&"  # query parameter separator smuggling
    "="  # assignment smuggling inside a segment
    "?"  # query start
    "#"  # fragment start
)
SEGMENT_TRUTH = re.compile(r"(^|/)\.\.?(\/|$)")
ABSOLUTE_HINT = re.compile(r"^[a-zA-Z]:|^[\\/]|\\\\|(^|/)proc/self|^~")
# the only characters that may appear in a path segment on this platform
SEGMENT_CHARSET = re.compile(r"[A-Za-z0-9._-]+")
# URI scheme at the start of a value (RFC 3986: ALPHA *( ALPHA / DIGIT /
# "+" / "-" / "." ) ":" ), allowing for leading whitespace/backslashes the
# client may smuggle past a naive regex
SCHEME_LEAD = re.compile(r"^[\\\s]*[a-zA-Z][a-zA-Z0-9+.-]*\s*:")
# known dangerous wrappers anywhere in the value (filter chains, expect,
# phar, data) — a legit filter/filename never contains them
WRAPPER_HINT = re.compile(
    r"(?i)php://|data:|expect://|phar://|zip://|file:|compress\.|"
    r"glob://|ssh2\.|ftp://|web://|svn://|mailto:|gopher://|"
    r"\\\\attacker|169\.254\.169\.254|metadata\.google|"
    r"kubernetes\.default|\.svc/|127\.0\.0\.1|localhost:|0\.0\.0\.0"
)


class GuardError(ValueError):
    """A request input violated the guard contract.

    The message is a stable machine code (never echoes the input), safe to
    surface in API responses and logs.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def fully_decode(value: str) -> str:
    """Percent-decode until the value is stable (bounded).

    Double encoding (``%252e`` -> ``%2e`` -> ``.``) only bites validators
    that decode once; the loop runs until fixpoint or MAX_DECODE_PASSES, so
    the validator always sees the final form.

    Nested encodings (``%25%2532%3566``) decode in STAGES: each pass peels
    one layer off inner sequences, so a pass limit that is too low leaves a
    still-encoded traversal in the result. The pass budget is therefore 8
    and a residual ``%XX`` pattern after the fixpoint keeps the value
    suspect (see ``safe_segment``).
    """
    current = value
    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote(current)
        if decoded == current:
            return current
        current = decoded
    return current


def no_scheme(value: str, *, code: str = "invalid_uri_scheme") -> str:
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
        if candidate.startswith("//") or candidate.startswith("\\\\"):
            raise GuardError(code)
        if WRAPPER_HINT.search(candidate):
            raise GuardError(code)
        # whitespace-folding dodge: some stacks fold internal whitespace in
        # the scheme token, so judge the whitespace-stripped form too
        folded = re.sub(r"\s+", "", candidate)
        if SCHEME_LEAD.match(folded) or WRAPPER_HINT.search(folded):
            raise GuardError(code)
    return decoded


def clean_text(value: str, *, code: str = "invalid_text") -> str:
    """Decode, strip control bytes and bound the length of a text input.

    Unicode "other/format" (C*) categories are rejected too: overlong
    encodings and exotic separators (%u2215, %c0%ae) decode into them, and a
    path validator must never have to reason about their shape.
    """
    decoded = fully_decode(str(value))
    if len(decoded) > MAX_INPUT_CHARS:
        raise GuardError("input_too_long")
    if FORBIDDEN_CHARS.search(decoded):
        raise GuardError(code)
    if "\ufffd" in decoded:
        # percent-decoding yielded invalid UTF-8 (overlong encodings,
        # truncated sequences) — the raw bytes can never be a legitimate
        # filename or id
        raise GuardError(code)
    if any(unicodedata.category(ch).startswith("C") for ch in decoded):
        raise GuardError(code)
    return decoded


def safe_segment(value: str, *, code: str = "invalid_path_segment") -> str:
    """Validate ONE path segment (no separators, no traversal, no absolute).

    Use for values that become a single component of a filesystem path —
    e.g. a run id or an artifact filename. After decoding, the value must
    contain no ``/`` or ``\\`` (so it cannot smuggle extra segments), no
    ``..`` segment, and no drive/UNC/absolute hints.
    """
    decoded = clean_text(value, code=code)
    if "/" in decoded or "\\" in decoded:
        raise GuardError(code)
    if decoded in {".", ".."}:
        raise GuardError(code)
    if ABSOLUTE_HINT.search(decoded):
        raise GuardError(code)
    if "%" in decoded:
        # a residual percent after bounded decoding means exotic encodings
        # (%u2215, unterminated %) — never a legitimate path segment
        raise GuardError(code)
    if any(ch in SEPARATOR_LOOKALIKES for ch in decoded):
        # solidus lookalikes and URL delimiters act as separators on some
        # stack after normalization — a segment never contains them
        raise GuardError(code)
    if not SEGMENT_CHARSET.fullmatch(decoded):
        # whitelist: ASCII letters, digits, dot, underscore, dash. Unicode
        # lookalikes (þ, 。, ／) defeat charset-agnostic filters only; a
        # segment in THIS platform is always plain ASCII
        raise GuardError(code)
    return decoded


def contained_path(base: Path, *segments: str) -> Path:
    """Resolve ``base / segments`` and PROVE containment after resolution.

    The check runs on the canonical (symlink-resolved) result, not on the
    raw input: ``os.path.join``-style quirks (an absolute segment discarding
    the base) and symlink hops cannot escape it. Raises GuardError otherwise.
    """
    if not segments:
        raise GuardError("invalid_path_segment")
    base_resolved = Path(base).resolve()
    candidate = base_resolved.joinpath(*segments)
    resolved = candidate.resolve()
    if resolved == base_resolved or base_resolved in resolved.parents:
        return resolved
    raise GuardError("path_outside_base")


def single_param(query_params, name: str) -> str | None:
    """Read ONE value for a parameter, rejecting pollution outright.

    ``?sev=high&sev=low`` is not a choice the server should make silently:
    the filter that validated the first copy is not the code that used the
    second. Duplicated keys are rejected with GuardError.
    """
    values = query_params.getlist(name)
    if not values:
        return None
    if len(values) > 1:
        raise GuardError("duplicate_parameter")
    return clean_text(values[0])


def header_safe(value: str) -> str:
    """Reject values that could inject CR/LF into a response header."""
    if "\r" in value or "\n" in value:
        raise GuardError("invalid_header_value")
    return value


@dataclass(frozen=True)
class QueryFilters:
    """Validated query filters shared by the findings endpoint."""

    severity: str | None = None
    source: str | None = None
    category: str | None = None


def read_filters(query_params) -> QueryFilters:
    """Read and validate the findings filters from request query params.

    Filter values are equality-compared in memory, but the guard still
    rejects URI-scheme shapes: an ``include``-looking value must never be
    normalized into "accepted" by any endpoint, present or future.
    """
    severity = single_param(query_params, "severity")
    source = single_param(query_params, "source")
    category = single_param(query_params, "category")
    for value in (severity, source, category):
        if value is not None:
            no_scheme(value)
    return QueryFilters(severity=severity, source=source, category=category)
