"""Bounded HTTP probe without proxy inheritance or redirect following."""

import http.client
from urllib.parse import urlsplit

from app.validation import validate_target_url


def check_target_reachable(target: str, timeout: float = 5) -> None:
    parsed = urlsplit(validate_target_url(target))
    cls = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = cls(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request("HEAD", parsed.path or "/")
        connection.getresponse().close()  # Even 401/404/500 prove HTTP reachability.
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError(
            "Target is unreachable; start the local Juice Shop lab"
        ) from exc
    finally:
        connection.close()
