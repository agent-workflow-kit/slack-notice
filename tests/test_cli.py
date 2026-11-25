from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from slack_notice.cli import main


def test_version_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    # Golden: exactly one line, `slack-notice <version>`, newline-terminated; the version comes
    # from pyproject.toml so the test stays valid across releases.
    root = Path(__file__).resolve().parent.parent
    expected = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert capsys.readouterr().out == f"slack-notice {expected}\n"


def test_no_arguments_returns_usage_exit_code() -> None:
    assert main([]) == 2
