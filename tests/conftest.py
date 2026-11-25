"""Shared fixtures: every test runs with a private HOME and XDG dirs and no network.

Scope of the guard, stated honestly:

- It covers this process only. Environment variables and password-database lookups
  (``pwd.getpwuid``, ``pwd.getpwnam``) are redirected to a private temp home, and the common
  socket and name-resolution entry points raise ``NetworkRefused``.
- Child processes are NOT guarded: a test that spawns one must give it a private HOME and XDG
  environment itself (and its own no-config flags).
- The gateway's home directory and uid come from ``tests/fake_gateway.py`` (the
  ``fake_gateway`` fixture): code under test must never rely on the real password entry.
- Tests marked ``live`` keep the HOME isolation but are not network-blocked.
"""

from __future__ import annotations

import _socket
import pwd
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from tests.fake_gateway import FakeGateway


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


@pytest.fixture
def fake_gateway(tmp_path: Path) -> Iterator[FakeGateway]:
    """A fake gateway with a private home (mode 0700) and no stalls left behind.

    Teardown fails the test on a recorded contract violation or an unconsumed scripted attempt
    (set ``allow_unconsumed_script`` to leave attempts on purpose)."""
    from tests.fake_gateway import FakeGateway  # lazy: scaffold tests copy this conftest alone

    home = tmp_path / "gwhome"
    home.mkdir(mode=0o700)
    gateway = FakeGateway(home=str(home))
    yield gateway
    gateway.release_stalls()  # a daemon worker blocked in a stall must not outlive the test
    # A contract violation inside a worker thread would only surface as an exit 1 "internal".
    gateway.assert_clean()


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Iterator[None]:
    """Keep each phase's report on the item (``item.rep_call``): the live suite's report reads
    the outcome of its tests from it. No effect on any other test."""
    outcome = yield
    report = outcome.get_result()
    setattr(item, "rep_" + report.when, report)
