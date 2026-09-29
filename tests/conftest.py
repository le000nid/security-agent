"""Unit tests must never make real network requests, including LLM discovery."""

import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def reject(*_args, **_kwargs):
        raise AssertionError("Real network access is forbidden in unit tests")

    monkeypatch.setattr(socket.socket, "connect", reject)
