"""Shared fixtures: every test runs with a private HOME and XDG dirs and no network.

Scope of the guard, stated honestly:

- It covers this process only. Environment variables and password-database lookups
  (``pwd.getpwuid``, ``pwd.getpwnam``) are redirected to a private temp home, and the common
  socket and name-resolution entry points raise ``NetworkRefused``.
- Child processes are NOT guarded: a test that spawns one must give it a private HOME and XDG
  environment itself (and its own no-config flags).
- The gateway's home directory and uid are faked through the fake gateway added in issue #5;
  until then, code under test must not rely on the real password entry.
- Tests marked ``live`` keep the HOME isolation but are not network-blocked.
"""

from __future__ import annotations

import _socket
import pwd
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest


class NetworkRefused(BaseException):  # noqa: N818  (BaseException so `except Exception` cannot swallow it)
    """Raised when a test touches the network."""


def refuse_network(*_args: Any, **_kwargs: Any) -> Any:
    raise NetworkRefused("tests must not touch the network")


_SOCKET_METHODS = ("connect", "connect_ex", "sendto", "sendmsg")
_RESOLVERS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "getnameinfo")


@pytest.fixture(autouse=True)
def isolated_environment(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Point HOME, XDG dirs and pwd lookups at a private temp dir; refuse network access."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))

    real_getpwuid = pwd.getpwuid
    real_getpwnam = pwd.getpwnam

    def with_home(entry: pwd.struct_passwd) -> pwd.struct_passwd:
        fields = list(entry)
        fields[5] = str(home)
        return pwd.struct_passwd(fields)

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: with_home(real_getpwuid(uid)))
    monkeypatch.setattr(pwd, "getpwnam", lambda name: with_home(real_getpwnam(name)))

    if request.node.get_closest_marker("live") is None:
        for name in _SOCKET_METHODS:
            monkeypatch.setattr(socket.socket, name, refuse_network)
        monkeypatch.setattr(socket, "create_connection", refuse_network)
        for name in _RESOLVERS:
            monkeypatch.setattr(socket, name, refuse_network)
            monkeypatch.setattr(_socket, name, refuse_network)
    yield
