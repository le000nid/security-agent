"""Safety checks for scan targets."""

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "juice-shop"})
ALLOWED_SCHEMES = frozenset({"http", "https"})


class TargetValidationError(ValueError):
    """Raised when a target is outside the local-only allowlist."""


def validate_target_url(value: str) -> str:
    """Validate and normalize a URL for an explicitly allowed local host."""

    candidate = value.strip()
    if any(ord(c) < 33 for c in candidate) or any(c in candidate for c in "\\,"):
        raise TargetValidationError(
            "Whitespace, backslashes and target lists are forbidden"
        )
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(f"Invalid target URL: {exc}") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetValidationError("Target URL must use http or https")
    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a hostname")
    if parsed.hostname.lower() not in ALLOWED_HOSTS:
        allowed = ", ".join(sorted(ALLOWED_HOSTS))
        raise TargetValidationError(
            f"Target host is not allowed; use one of: {allowed}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("Credentials in target URLs are not allowed")
    if parsed.fragment:
        raise TargetValidationError("URL fragments are not allowed")

    host = parsed.hostname.lower()
    netloc = f"{host}:{port}" if port is not None else host
    path = parsed.path or ""
    normalized = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    return normalized[:-1] if parsed.path == "/" and not parsed.query else normalized


def validate_source_path(value: str) -> Path:
    """Accept an existing readable local file/directory, never URLs or UNC paths."""
    if not value or "://" in value or value.startswith(("\\\\", "//")):
        raise ValueError("Source must be a local file or directory")
    path = Path(value).expanduser().resolve(strict=True)
    if str(path).startswith(("\\\\", "//")) or path == Path(path.anchor):
        raise ValueError("Network shares and filesystem roots are forbidden")
    if not (path.is_file() or path.is_dir()) or not os.access(path, os.R_OK):
        raise ValueError("Source must be a readable file or directory")
    return path
