from __future__ import annotations

import importlib
import os
import re
import tomllib
from pathlib import Path

import pytest

import slack_notice

ROOT = Path(__file__).resolve().parent.parent
STUB_MODULES = ["config", "log", "payload", "render", "spacing", "webhook"]


def test_version_matches_installed_metadata_and_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", slack_notice.__version__)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert slack_notice.__version__ == project["version"]


@pytest.mark.parametrize("name", STUB_MODULES)
def test_module_map_stub_imports(name: str) -> None:
    module = importlib.import_module(f"slack_notice.{name}")
    assert module.__doc__


def test_live_marker_is_registered_and_deselected_by_default() -> None:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("live:") for m in cfg["markers"])
    assert "not live" in cfg["addopts"]


def test_environment_is_isolated() -> None:
    assert "tmp" in os.environ["HOME"] or "pytest" in os.environ["HOME"]
    assert os.environ["XDG_CONFIG_HOME"].startswith(os.environ["HOME"])


def test_network_is_refused() -> None:
    import socket

    with pytest.raises(AssertionError, match="network"):
        socket.create_connection(("example.invalid", 80))
