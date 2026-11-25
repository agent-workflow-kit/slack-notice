from __future__ import annotations

import importlib
import importlib.metadata
import os
import pwd
import re
import socket
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import slack_notice
from tests.conftest import NetworkRefused

early_getaddrinfo = socket.getaddrinfo
ROOT = Path(__file__).resolve().parent.parent
STUB_MODULES = ["config", "log", "payload", "render", "spacing", "webhook"]


def test_version_matches_installed_metadata_and_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", slack_notice.__version__)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert slack_notice.__version__ == project["version"], (
        "run `uv sync` to refresh installed metadata"
    )


def test_version_falls_back_when_metadata_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("slack-notice")

    with monkeypatch.context() as patch:
        patch.setattr(importlib.metadata, "version", missing)
        importlib.reload(slack_notice)
        assert slack_notice.__version__ == "0.0.0+unknown"
    importlib.reload(slack_notice)


@pytest.mark.parametrize("name", STUB_MODULES)
def test_module_map_stub_imports(name: str) -> None:
    module = importlib.import_module(f"slack_notice.{name}")
    assert module.__doc__


def _run_pytest(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    sample_home = tmp_path / "subhome"
    sample_home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(sample_home),
        "XDG_CONFIG_HOME": str(sample_home / ".config"),
        "XDG_STATE_HOME": str(sample_home / ".state"),
        "XDG_CACHE_HOME": str(sample_home / ".cache"),
        "XDG_DATA_HOME": str(sample_home / ".data"),
    }
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-c",
            str(ROOT / "pyproject.toml"),
            *args,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _write_sample(tmp_path: Path, body: str) -> Path:
    sample = tmp_path / "sample"
    sample.mkdir()
    (sample / "conftest.py").write_text((ROOT / "tests" / "conftest.py").read_text())
    (sample / "test_sample.py").write_text(body)
    return sample


LIVE_SAMPLE = """\
import os
import socket

import pytest


@pytest.mark.live
def test_live_is_not_network_blocked():
    assert socket.create_connection.__name__ != "refuse_network"
    assert socket.socket.connect.__name__ != "refuse_network"
    assert "pytest" in os.environ["HOME"] or "tmp" in os.environ["HOME"]
"""


def test_live_marker_is_deselected_by_default_and_registered(tmp_path: Path) -> None:
    sample = _write_sample(tmp_path, LIVE_SAMPLE)
    default = _run_pytest(tmp_path, str(sample))
    assert "1 deselected" in default.stdout, default.stdout + default.stderr
    selected = _run_pytest(tmp_path, str(sample), "-m", "live")
    assert selected.returncode == 0, selected.stdout + selected.stderr
    assert "1 passed" in selected.stdout


def test_unregistered_marker_is_an_error(tmp_path: Path) -> None:
    sample = _write_sample(
        tmp_path, "import pytest\n\n@pytest.mark.bogus\ndef test_x():\n    pass\n"
    )
    result = _run_pytest(tmp_path, str(sample))
    assert result.returncode != 0
    assert "bogus" in result.stdout + result.stderr


def test_environment_is_isolated(tmp_path: Path) -> None:
    home = tmp_path / "home"
    assert os.environ["HOME"] == str(home)
    for var in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        assert Path(os.environ[var]).is_relative_to(home), var
    assert Path.home() == home
    assert os.path.expanduser("~") == str(home)
    assert pwd.getpwuid(os.getuid()).pw_dir == str(home)
    assert pwd.getpwnam(pwd.getpwuid(os.getuid()).pw_name).pw_dir == str(home)


def _socket_connect() -> None:
    socket.socket().connect(("127.0.0.1", 9))


def _socket_connect_ex() -> None:
    socket.socket().connect_ex(("127.0.0.1", 9))


def _socket_sendto() -> None:
    socket.socket(type=socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))


def _socket_sendmsg() -> None:
    socket.socket(type=socket.SOCK_DGRAM).sendmsg([b"x"], [], 0, ("127.0.0.1", 9))


NETWORK_PATHS = {
    "create_connection": lambda: socket.create_connection(("example.invalid", 80)),
    "connect": _socket_connect,
    "connect_ex": _socket_connect_ex,
    "sendto": _socket_sendto,
    "sendmsg": _socket_sendmsg,
    "getaddrinfo": lambda: socket.getaddrinfo("example.invalid", 80),
    "early_bound_getaddrinfo": lambda: early_getaddrinfo("example.invalid", 80),
    "gethostbyname": lambda: socket.gethostbyname("example.invalid"),
    "gethostbyname_ex": lambda: socket.gethostbyname_ex("example.invalid"),
    "getnameinfo": lambda: socket.getnameinfo(("127.0.0.1", 80), 0),
}


@pytest.mark.parametrize("path", sorted(NETWORK_PATHS))
def test_network_is_refused(path: str) -> None:
    with pytest.raises(NetworkRefused):
        NETWORK_PATHS[path]()


def test_network_refusal_is_not_an_exception() -> None:
    assert not issubclass(NetworkRefused, Exception)
