"""Arsenal SAST fixture: guarded outbound fetch with an egress allowlist."""

from urllib.parse import urlsplit

from app.agent.arsenal.rfi import safe_remote_url

ALLOWED_HOSTS = {"trusted.example"}


def fetch_title(url: str, fetcher) -> str:
    checked = safe_remote_url(url, allowlist=ALLOWED_HOSTS)
    if urlsplit(checked).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return fetcher.fetch(checked)
