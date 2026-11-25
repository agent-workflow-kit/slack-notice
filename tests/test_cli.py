from __future__ import annotations

import re

import pytest

from slack_notice.cli import main


def test_version_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    # Golden: exactly one line, `slack-notice <semver>`, newline-terminated.
    assert re.fullmatch(r"slack-notice \d+\.\d+\.\d+\n", capsys.readouterr().out)


def test_no_arguments_returns_usage_exit_code() -> None:
    assert main([]) == 2
