"""Unit tests must never make real network requests, including LLM discovery."""

import socket
import sys

import pytest


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    original_connect = socket.socket.connect

    def reject(*_args, **_kwargs):
        # Windows asyncio builds its internal wake-up socket pair via loopback.
        # Permit only that stdlib implementation, not general localhost traffic.
        caller = sys._getframe(1)
        if (
            caller.f_globals.get("__name__") == "socket"
            and caller.f_code.co_name == "_fallback_socketpair"
            and len(_args) == 2
            and _args[1][0] in {"127.0.0.1", "::1"}
        ):
            return original_connect(*_args, **_kwargs)
        raise AssertionError("Real network access is forbidden in unit tests")

    monkeypatch.setattr(socket.socket, "connect", reject)
