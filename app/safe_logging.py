"""Small structured logger; raw provider/scanner exceptions are never logged."""

import json
import logging
import os
import re


def redact(value: str) -> str:
    for name, secret in os.environ.items():
        if any(part in name.upper() for part in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
            if secret and len(secret) >= 4:
                value = value.replace(secret, "[REDACTED]")
    return re.sub(
        r"(?i)(authorization\s*[:=]\s*|bearer\s+)[^\r\n,]+",
        r"\1[REDACTED]",
        value,
    )


def redact_data(value):
    """Redact values before JSON encoding, so quotes/braces cannot be corrupted."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_data(item) for key, item in value.items()}
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {"level": record.levelname, "message": redact(record.getMessage())},
            ensure_ascii=False,
        )


def configure_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("security_agent")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger
