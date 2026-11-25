"""Home lookup from the password database (interface.md, Config; issue #9).

HOME and the XDG variables are never read; a home that cannot be used is exit 2 config_invalid
with details.key `home`, before any input is read or anything is sent.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from slack_notice import cli
from slack_notice.cli import Context, Streams, main
from slack_notice.config import HomeUnusable, resolve_home
from tests.fake_gateway import FakeGateway

FIXED_LINE = "config_invalid: configuration is invalid\n"


def gateway_with(
    home: str,
    *,
    home_error: bool = False,
    login_name: str | None = "tester",
    home_is_directory: bool | None = None,
) -> FakeGateway:
    return FakeGateway(
        home=home,
        home_error=home_error,
        login_name=login_name,
        home_is_directory=home_is_directory,
    )


# --- resolve_home -------------------------------------------------------------------------


def test_an_existing_absolute_directory_is_returned_as_found(tmp_path: Path) -> None:
    assert resolve_home(gateway_with(str(tmp_path))) == str(tmp_path)


def test_trailing_slashes_are_kept_and_accepted(tmp_path: Path) -> None:
    home = f"{tmp_path}//"
    assert resolve_home(gateway_with(home)) == home


def test_a_symlink_to_a_directory_is_a_directory(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    assert resolve_home(gateway_with(str(link))) == str(link)


def test_a_non_utf8_directory_name_is_accepted_when_it_exists(tmp_path: Path) -> None:
    raw = os.fsencode(tmp_path) + b"/caf\xe9"
    os.mkdir(raw)
    assert resolve_home(gateway_with(os.fsdecode(raw))) == os.fsdecode(raw)


@pytest.mark.parametrize(
    "home",
    ["", " ", "relative", ".", "..", "./x", "~", "~/x", "$HOME", "a\x00b", "\x00", "/tmp\ud800"],
)
def test_empty_relative_and_odd_values_are_refused(home: str) -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(home))


def test_an_absolute_path_with_a_nul_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(f"{tmp_path}\x00/x"))


def test_a_missing_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(str(tmp_path / "missing")))


def test_a_regular_file_is_refused(tmp_path: Path) -> None:
    file = tmp_path / "file"
    file.write_text("x")
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(str(file)))


def test_a_dangling_symlink_is_refused(tmp_path: Path) -> None:
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nowhere")
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(str(link)))


def test_a_very_long_path_is_refused_not_crashed(tmp_path: Path) -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(str(tmp_path) + "/" + "a" * 100_000))


def test_the_directory_check_goes_through_the_gateway() -> None:
    # "/nonexistent-dir" is not a directory on disk; only the gateway's answer can accept it.
    assert resolve_home(gateway_with("/nonexistent-dir", home_is_directory=True)) == (
        "/nonexistent-dir"
    )


def test_a_gateway_that_says_not_a_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with(str(tmp_path), home_is_directory=False))


def test_a_failed_lookup_is_refused() -> None:
    with pytest.raises(HomeUnusable):
        resolve_home(gateway_with("/", home_error=True))


def test_the_error_message_is_fixed_and_has_no_cause_or_path(tmp_path: Path) -> None:
    secret = str(tmp_path / "SECRET-missing")
    with pytest.raises(HomeUnusable) as info:
        resolve_home(gateway_with(secret))
    assert str(info.value) == "home directory cannot be used"
    assert secret not in repr(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


def test_a_failed_lookup_hides_its_context() -> None:
    with pytest.raises(HomeUnusable) as info:
        resolve_home(gateway_with("/", home_error=True))
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_the_environment_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "other"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "other"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "other"))
    assert resolve_home(gateway_with(str(tmp_path))) == str(tmp_path)
    monkeypatch.delenv("HOME")
    assert resolve_home(gateway_with(str(tmp_path))) == str(tmp_path)


# --- through the CLI ----------------------------------------------------------------------


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[Context]:
    recorded: list[Context] = []

    def handler(ctx: Context) -> int:
        recorded.append(ctx)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    return recorded


def invoke(
    argv: list[str], gateway: FakeGateway, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    out, err = io.BytesIO(), io.BytesIO()
    streams = Streams(out=out, err=err, stdin_is_tty=lambda: False)
    code = main(argv, {} if env is None else env, gateway, streams)
    return code, out.getvalue().decode(), err.getvalue().decode()


@pytest.mark.parametrize("command", ["send", "validate"])
def test_the_home_is_looked_up_once_and_passed_on(
    command: str, seen: list[Context], tmp_path: Path
) -> None:
    gateway = gateway_with(str(tmp_path))
    assert invoke([command], gateway)[0] == 0
    assert gateway.home_lookups == 1
    assert seen[0].home == str(tmp_path)


def test_home_unset_uses_the_gateway_home(
    seen: list[Context], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HOME", raising=False)
    assert invoke(["send"], gateway_with(str(tmp_path)))[0] == 0
    assert seen[0].home == str(tmp_path)


def test_home_and_xdg_in_env_and_process_are_ignored(
    seen: list[Context], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = tmp_path / "hostile"
    (hostile / ".config" / "slack-notice").mkdir(parents=True)
    (hostile / ".config" / "slack-notice" / "config.yaml").write_text("enabled: false\n")
    real = tmp_path / "real"
    real.mkdir()
    env = {
        "HOME": str(hostile),
        "XDG_CONFIG_HOME": str(hostile / ".config"),
        "XDG_STATE_HOME": str(hostile / "state"),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert invoke(["send"], gateway_with(str(real)), env)[0] == 0
    assert seen[0].home == str(real)
    assert not (hostile / "state").exists()


@pytest.mark.parametrize(
    "bad",
    ["", "relative/LEAKMARK", "/tmp/LEAKMARK\x00b", "MISSING", "FILE"],
)
@pytest.mark.parametrize("command", ["send", "validate"])
def test_an_unusable_home_is_config_invalid_with_key_home(
    bad: str, command: str, seen: list[Context], tmp_path: Path
) -> None:
    (tmp_path / "FILE").write_text("x")
    home = str(tmp_path / bad) if bad in ("MISSING", "FILE") else bad
    code, out, err = invoke([command, "--json"], gateway_with(home))
    assert code == 2
    assert err == FIXED_LINE
    error = json.loads(out)["error"]
    assert error["code"] == "config_invalid"
    assert error["details"] == {"key": "home"}
    assert error["message"] == "configuration is invalid"
    # A NUL is escaped in JSON, so check a marker substring and the parsed fields as well.
    assert "LEAKMARK" not in out + err
    assert "MISSING" not in out + err
    assert "FILE" not in out + err
    assert home not in json.dumps(json.loads(out)) or home == ""
    assert seen == []


def test_a_failed_lookup_is_config_invalid_with_key_home(
    seen: list[Context], tmp_path: Path
) -> None:
    code, out, err = invoke(["send", "--json"], gateway_with(str(tmp_path), home_error=True))
    assert code == 2
    assert json.loads(out)["error"]["details"] == {"key": "home"}
    assert err == FIXED_LINE
    assert seen == []


def test_nothing_is_read_or_sent_when_the_home_is_unusable(tmp_path: Path) -> None:
    gateway = gateway_with(str(tmp_path / "missing"))
    streams = Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: False)
    assert main(["send", "--stdin-json"], {}, gateway, streams) == 2
    assert gateway.connections == []
    assert gateway.events == []
    assert gateway.source_reads == 0


def test_dry_run_with_config_needs_no_home(seen: list[Context], tmp_path: Path) -> None:
    gateway = gateway_with("", home_error=True)
    assert invoke(["send", "--dry-run", "--config", str(tmp_path / "c.yaml")], gateway)[0] == 0
    assert gateway.home_lookups == 0
    assert seen[0].home is None


def test_dry_run_with_an_empty_config_path_still_skips_the_lookup(
    seen: list[Context],
) -> None:
    gateway = gateway_with("", home_error=True)
    assert invoke(["send", "--dry-run", "--config="], gateway)[0] == 0
    assert gateway.home_lookups == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--dry-run"],
        ["send", "--config", "c.yaml"],
        ["validate", "--config", "c.yaml"],
        ["validate", "--dry-run", "--config", "c.yaml"],
    ],
)
def test_every_other_combination_needs_the_home(argv: list[str], seen: list[Context]) -> None:
    code, _out, err = invoke(argv, gateway_with("relative"))
    assert code == 2
    assert err == FIXED_LINE
    assert seen == []


def test_version_and_help_do_not_look_up_the_home() -> None:
    gateway = gateway_with("", home_error=True)
    assert invoke(["--version"], gateway)[0] == 0
    assert invoke(["--help"], gateway)[0] == 0
    assert gateway.home_lookups == 0


def test_a_usage_error_comes_before_the_lookup() -> None:
    gateway = gateway_with("", home_error=True)
    code, _out, err = invoke(["send", "--bogus"], gateway)
    assert code == 2
    assert err.startswith("usage")
    assert gateway.home_lookups == 0


# --- actor name ---------------------------------------------------------------------------


def test_actor_is_unknown_when_the_entry_has_no_name(seen: list[Context], tmp_path: Path) -> None:
    gateway = gateway_with(str(tmp_path), login_name=None)
    streams = Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: True)
    assert main(["send", "--message=m"], {}, gateway, streams) == 0
    assert seen[0].actor == "human:unknown"
