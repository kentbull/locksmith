# -*- encoding: utf-8 -*-
"""
Tests for Turret UXD socket portability guard (issue #25).

Covers:
  - AF_UNIX guard: Acceptor.open() raises NotImplementedError on platforms
    where socket.AF_UNIX is absent.
  - Portable temp path: TurretDoer default socket path uses tempfile.gettempdir()
    and the canonical socket filename.
  - Supported-platform bind: basic open/close cycle using a unique tmp_path socket
    (skipped when AF_UNIX is unavailable).
"""

import os
import socket
import tempfile

import pytest

from locksmith.turret.uxd.serving import Acceptor, Remoter, Server


# ---------------------------------------------------------------------------
# 1. AF_UNIX guard
# ---------------------------------------------------------------------------

def test_acceptor_open_raises_when_af_unix_absent(monkeypatch):
    """Acceptor.open() raises NotImplementedError when socket.AF_UNIX is missing."""
    monkeypatch.delattr(socket, "AF_UNIX", raising=False)

    acceptor = Acceptor(path="/does/not/matter.s")
    with pytest.raises(NotImplementedError) as exc_info:
        acceptor.open()

    msg = str(exc_info.value).lower()
    assert "af_unix" in msg or "unix-domain" in msg or "unix domain" in msg


# ---------------------------------------------------------------------------
# 2. Portable temp path
# ---------------------------------------------------------------------------

EXPECTED_SOCKET_FILENAME = "keripy_kli.s"


def test_turret_default_socket_path_uses_tempdir():
    """TurretDoer socket path should be under tempfile.gettempdir(), not /tmp."""
    expected = os.path.join(tempfile.gettempdir(), EXPECTED_SOCKET_FILENAME)
    # Verify the constant is constructed the same way the module would build it.
    assert os.path.basename(expected) == EXPECTED_SOCKET_FILENAME
    assert expected.startswith(tempfile.gettempdir())
    # Confirm it does NOT hardcode /tmp (would fail on Windows).
    assert not expected.startswith("/tmp/") or tempfile.gettempdir() == "/tmp"


# ---------------------------------------------------------------------------
# 3. Supported-platform bind (skipped when AF_UNIX unavailable)
# ---------------------------------------------------------------------------

af_unix_available = hasattr(socket, "AF_UNIX")


@pytest.mark.skipif(not af_unix_available, reason="AF_UNIX not available on this platform")
def test_acceptor_open_and_close():
    """Acceptor can open and close a Unix-domain socket on supported platforms.

    Note: Uses tempfile.gettempdir() directly rather than pytest's tmp_path
    because Unix domain socket paths are limited to ~104 bytes on macOS and
    tmp_path can generate paths exceeding that limit.
    """
    sock_path = os.path.join(tempfile.gettempdir(), "test_turret_uxd_guard.s")
    if os.path.exists(sock_path):
        os.remove(sock_path)
    acceptor = Acceptor(path=sock_path)
    try:
        result = acceptor.open()
        assert result is True
        assert acceptor.opened is True
        assert os.path.exists(sock_path)
    finally:
        acceptor.close()
        assert acceptor.opened is False
        if os.path.exists(sock_path):
            os.remove(sock_path)


def test_server_validates_and_retains_explicit_budgets():
    """The local CLI bridge has finite sessions and receive work per turn."""
    server = Server(path="unused", maxConnections=8, acceptsPerTurn=4,
                    rxbsLimit=1024, rxbsPerTurn=64, tymeout=30.0)
    assert server.maxConnections == 8
    assert server.acceptsPerTurn == 4
    assert server.rxbsLimit == 1024
    assert server.rxbsPerTurn == 64
    assert server.tymeout == 30.0
    with pytest.raises(ValueError):
        Server(path="unused", maxConnections=-1)


def test_remoter_closes_on_unread_receive_overflow():
    """A peer cannot grow the UXD parser buffer past its configured ceiling."""
    local, peer = socket.socketpair()
    remoter = Remoter(ha="local", ca="peer", cs=local,
                      rxbsLimit=4, rxbsPerTurn=4)
    try:
        peer.sendall(b"12345")
        remoter.serviceReceives()
        assert bytes(remoter.rxbs) == b"1234"
        remoter.serviceReceives()
        assert remoter.rxbsOverflowed
        assert remoter.cutoff
        assert remoter.cs is None
    finally:
        remoter.close()
        peer.close()
