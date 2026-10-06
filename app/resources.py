"""Locate reviewed rules in a checkout or an installed wheel."""

import sys
from pathlib import Path


def config_directory() -> Path:
    checkout = Path(__file__).resolve().parent.parent / "config"
    if checkout.is_dir():
        return checkout
    return Path(sys.prefix) / "share" / "ai-security-agent" / "config"
