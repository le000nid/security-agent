"""Allow stdlib wake-up socket pairs while rejecting ordinary connections."""

import socket
from types import SimpleNamespace
from unittest.mock import Mock

import conftest
import pytest


def install_guard(monkeypatch, caller):
    original = Mock()
    monkeypatch.setattr(socket.socket, "connect", original)
    conftest.forbid_network.__wrapped__(monkeypatch)
    monkeypatch.setattr(conftest.sys, "_getframe", lambda _: caller)
    return original


@pytest.mark.parametrize("name", ["socketpair", "_fallback_socketpair"])
def test_stdlib_socketpair_loopback_is_allowed(monkeypatch, name):
    function = getattr(socket, name, None)
    code = getattr(function, "__code__", None)
    if code is None:
        pytest.skip("This Python does not implement this socketpair function in Python")
    caller = SimpleNamespace(f_globals=vars(socket), f_code=code)
    original = install_guard(monkeypatch, caller)
    sock = Mock()
    socket.socket.connect(sock, ("127.0.0.1", 12345))
    original.assert_called_once_with(sock, ("127.0.0.1", 12345))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "example.com"])
def test_ordinary_connections_still_blocked(monkeypatch, host):
    caller = SimpleNamespace(
        f_globals=globals(), f_code=test_ordinary_connections_still_blocked.__code__
    )
    original = install_guard(monkeypatch, caller)
    with pytest.raises(AssertionError, match="Real network access"):
        socket.socket.connect(Mock(), (host, 12345))
    original.assert_not_called()


def test_socket_module_name_alone_does_not_allow_network(monkeypatch):
    caller = SimpleNamespace(
        f_globals={"__name__": "socket"},
        f_code=test_socket_module_name_alone_does_not_allow_network.__code__,
    )
    original = install_guard(monkeypatch, caller)
    with pytest.raises(AssertionError, match="Real network access"):
        socket.socket.connect(Mock(), ("127.0.0.1", 12345))
    original.assert_not_called()
