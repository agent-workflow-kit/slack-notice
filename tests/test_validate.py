"""`validate`: the config and credential checks (#31), end to end through ``cli.main``.

Every test drives the real entry point with the fake gateway (no connection, no DNS). The
expected texts are written out here from docs/interface.md (validate, Output), not imported from
the source, so a changed message fails a test on purpose.
"""

from __future__ import annotations

import json
import os
import signal
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import FrameType
from typing import Any

import pytest

from slack_notice import cli
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid
from tests.secret_scan import Corpus, Secret
from tests.send_harness import ENV_NAME, Sent, go, state_path, write_config
from tests.test_secrets_env import Recording, crowded

SECRET = Secret()
URL = SECRET.url
VALIDATE = ["validate", "--json"]

CONFIG_OK = "configuration is valid"
CREDENTIAL_OK = "the webhook credential is set and has the form of a workflow trigger URL"
CREDENTIAL_BAD = "the webhook credential is unset or not a workflow trigger URL"


def check(name: str, ok: bool, message: str) -> dict[str, Any]:
    return {"name": name, "ok": ok, "message": message}


DEFAULT_LIMITS = {"max_chars": 3000, "max_bytes": 12000, "timeout_s": 10.0, "spacing_s": 1.0}


def document(
    *checks: dict[str, Any],
    ok: bool,
    enabled: bool = True,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "enabled": enabled,
        "checks": list(checks),
        "limits": DEFAULT_LIMITS if limits is None else limits,
    }


GOOD = [check("config", True, CONFIG_OK), check("credential", True, CREDENTIAL_OK)]
BAD = [check("config", True, CONFIG_OK), check("credential", False, CREDENTIAL_BAD)]


def assert_untouched(sent: Sent, gateway: FakeGateway) -> None:
    """No network, no state directory, no log, no stdin, no lock, no spawn."""
    assert gateway.connections == []
    assert gateway.source_reads == 0
    assert not state_path(gateway).exists()
    assert sent.state_files == {} and sent.records == []
    assert not any(e.startswith(("open_state", "resolve", "read_source")) for e in gateway.events)
    assert gateway.exit_codes == [] and not sent.exited  # a plain return, never exit_now


# --- the outcomes -------------------------------------------------------------------------------


def test_a_good_config_and_credential_is_ok_and_exits_0(fake_gateway: FakeGateway) -> None:
    sent = go(VALIDATE, fake_gateway)
    assert sent.code == 0 and sent.err == b""
    assert sent.stdout.endswith("\n") and sent.stdout.count("\n") == 1
    assert assert_valid("cli/validate", sent.out) == document(*GOOD, ok=True)
    # key order of the interface
    assert list(sent.document) == ["ok", "enabled", "checks", "limits"]
    assert_untouched(sent, fake_gateway)


def test_a_disabled_tool_with_plain_validate_exits_0_and_reports_enabled_false(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, config=write_config(tmp_path, "enabled: false\n"))
    assert sent.code == 0
    assert assert_valid("cli/validate", sent.out) == document(*GOOD, ok=True, enabled=False)
    assert_untouched(sent, fake_gateway)


def test_a_disabled_tool_with_a_broken_credential_exits_12(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, env={}, config=write_config(tmp_path, "enabled: false\n"))
    assert sent.code == 12
    assert assert_valid("cli/validate", sent.out) == document(*BAD, ok=False, enabled=False)
    assert_untouched(sent, fake_gateway)


def test_a_broken_credential_prints_the_document_not_the_error_envelope(
    fake_gateway: FakeGateway,
) -> None:
    sent = go(VALIDATE, fake_gateway, env={})
    assert sent.code == 12
    assert "error" not in sent.document
    assert sent.document == document(*BAD, ok=False)


LONG_OK = "https://hooks.slack.com/triggers/" + "a" * (
    1024 - len("https://hooks.slack.com/triggers/")
)


@pytest.mark.parametrize(
    "value",
    [
        URL,
        "  " + URL + " \t\r\n\x0b\x0c",
        LONG_OK,
        "https://hooks.slack.com/triggers/A_b-1/B/C/D",
    ],
)
def test_a_well_formed_credential_passes_whatever_its_surrounding_whitespace(
    value: str, fake_gateway: FakeGateway
) -> None:
    assert len(value.strip()) <= 1024
    sent = go(VALIDATE, fake_gateway, env={ENV_NAME: value})
    assert (sent.code, sent.document["ok"]) == (0, True)


def hostile() -> list[tuple[str, str | None]]:
    path = SECRET.path
    host = "hooks.slack.com"
    return [
        ("unset", None),
        ("empty", ""),
        ("blank", " \t\r\n\x0b\x0c"),
        ("other host", "https://example.com" + path),
        ("subdomain", "https://x." + host + path),
        ("lookalike", "https://" + host + ".example.com" + path),
        ("http", "http://" + host + path),
        ("port", "https://" + host + ":443" + path),
        ("userinfo", "https://u@" + host + path),
        ("query", URL + "?x=1"),
        ("fragment", URL + "#x"),
        ("trailing dot", "https://" + host + "." + path),
        ("empty segment", URL + "//x"),
        ("trailing slash", URL + "/"),
        ("too many segments", URL + "/a/b/c/d/e"),
        ("classic webhook", "https://" + host + "/services/" + "/".join(SECRET.segments)),
        ("inner space", "https://" + host + "/triggers/a b"),
        ("embedded newline", URL + "\nextra"),
        ("nul", URL + "\x00"),
        ("non-ascii", "https://" + host + "/triggers/caf\u00e9"),
        ("fullwidth", "https://" + host + "/triggers/\uff21"),
        ("uppercase scheme", "HTTPS://" + host + path),
        ("uppercase host", "https://HOOKS.SLACK.COM" + path),
        ("over 1024", LONG_OK + "a"),
        ("giant", "https://hooks.slack.com/triggers/" + "a" * 100_000),
        ("just the host", "https://" + host),
        ("only a segment", SECRET.segments[0]),
        ("nbsp padded", "\u00a0" + URL),  # only the six ASCII whitespace characters are trimmed
    ]


@pytest.mark.parametrize(("label", "value"), hostile(), ids=[h[0] for h in hostile()])
def test_every_wrong_credential_fails_the_credential_check_and_exits_12(
    label: str, value: str | None, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = {} if value is None else {ENV_NAME: value}
    sent = go(VALIDATE, fake_gateway, env=env)
    assert sent.code == 12, label
    assert assert_valid("cli/validate", sent.out) == document(*BAD, ok=False)
    assert_untouched(sent, fake_gateway)
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    corpus.add_tree(tmp_path)
    corpus.add("gateway.events", "\n".join(fake_gateway.events))
    corpus.add("gateway.calls", "\n".join(fake_gateway.calls))
    assert corpus.hits(SECRET) == []


def test_a_non_string_credential_value_is_a_failed_check(fake_gateway: FakeGateway) -> None:
    sent = go(VALIDATE, fake_gateway, env={ENV_NAME: 7})  # type: ignore[dict-item]
    assert sent.code == 12 and sent.document == document(*BAD, ok=False)


def test_a_hostile_environment_mapping_is_a_failed_check_with_no_context_kept(
    fake_gateway: FakeGateway,
) -> None:
    class Hostile(Mapping[str, str]):
        def __getitem__(self, key: str) -> str:
            raise RuntimeError(URL)

        def __iter__(self) -> Iterator[str]:
            raise AssertionError("iterated")

        def __len__(self) -> int:
            raise AssertionError("measured")

    sent = go(VALIDATE, fake_gateway, env=Hostile())
    assert sent.code == 12 and sent.document == document(*BAD, ok=False)
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    assert corpus.hits(SECRET) == []


def test_the_configured_variable_name_is_the_one_checked(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "webhook_env: OTHER_HOOK\n")
    assert go(VALIDATE, fake_gateway, config=config).code == 12  # SLACK_WEBHOOK is not read
    ok = go(VALIDATE, fake_gateway, config=config, env={"OTHER_HOOK": URL})
    assert ok.code == 0


# --- config failures ----------------------------------------------------------------------------


def test_an_unloadable_config_prints_the_error_envelope_and_exits_2(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "max_chars: 5\n")
    env = Recording(crowded(tmp_path))
    sent = go(VALIDATE, fake_gateway, env=env, config=config)
    assert sent.code == 2
    error = sent.error
    assert (error["code"], error["details"]) == ("config_invalid", {"key": "max_chars"})
    assert error["message"] == "max_chars must be an integer from 2000 to 12000"
    assert "checks" not in sent.document and "ok" not in sent.document
    assert sent.err == b"config_invalid: max_chars must be an integer from 2000 to 12000\n"
    assert env.log == []  # the credential is not read when the config fails
    assert "environ" not in fake_gateway.calls
    assert_untouched(sent, fake_gateway)


def test_a_missing_config_file_is_the_config_error(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, config=str(tmp_path / "absent.yaml"))
    assert sent.code == 2
    assert (sent.error["code"], sent.error["details"]) == ("config_invalid", {"key": "--config"})
    assert str(tmp_path) not in sent.stdout + sent.stderr


def test_an_unreadable_config_file_is_the_config_error_with_the_fixed_message(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path)
    fake_gateway.file_errors[config] = PermissionError(13, "denied " + URL)
    env = Recording(crowded(tmp_path))
    sent = go(VALIDATE, fake_gateway, env=env, config=config)
    assert sent.code == 2
    assert sent.error["code"] == "config_invalid"
    assert sent.error["message"] == "configuration is invalid"
    assert sent.error["details"] == {"key": config}
    assert env.log == []
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    assert corpus.hits(SECRET) == []


def test_a_home_directory_that_cannot_be_used_is_the_config_error(tmp_path: Path) -> None:
    gateway = FakeGateway(home=str(tmp_path / "gwhome"), home_error=True)
    env = Recording(crowded(tmp_path))
    sent = go(VALIDATE, gateway, env=env)
    assert sent.code == 2
    assert (sent.error["code"], sent.error["details"]) == ("config_invalid", {"key": "home"})
    assert env.log == []


def test_a_broken_config_wins_over_a_broken_credential(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, env={}, config=write_config(tmp_path, "max_chars: 5\n"))
    assert sent.code == 2 and sent.error["code"] == "config_invalid"


def test_a_broken_config_of_a_disabled_tool_is_still_exit_2(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "enabled: false\nmax_chars: 5\n")
    assert go(VALIDATE, fake_gateway, config=config).code == 2


# --- the environment rules ----------------------------------------------------------------------


def test_only_the_configured_credential_variable_is_read(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    sent = go(VALIDATE, fake_gateway, env=env)
    assert sent.code == 0
    assert env.log == [("getitem", ENV_NAME)]  # no iteration, length or other key


def test_a_custom_variable_name_is_the_only_one_read(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    config = write_config(tmp_path, "webhook_env: OTHER_HOOK\n")
    sent = go(VALIDATE, fake_gateway, env=env, config=config)
    assert sent.code == 0 and env.log == [("getitem", "OTHER_HOOK")]


@pytest.mark.parametrize("value", [None, "", "  ", URL + "?x"])
def test_a_failed_credential_check_still_reads_only_the_credential_variable(
    value: str | None, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    values = crowded(tmp_path)
    values.pop(ENV_NAME)
    if value is not None:
        values[ENV_NAME] = value
    env = Recording(values)
    assert go(VALIDATE, fake_gateway, env=env).code == 12
    assert env.log == [("getitem", ENV_NAME)]


def test_the_default_environment_comes_from_the_gateway_only_when_the_credential_is_reached(
    tmp_path: Path,
) -> None:
    good_home = tmp_path / "g1"
    good_home.mkdir(mode=0o700)
    good = FakeGateway(home=str(good_home), environment={ENV_NAME: URL})
    sent = go(VALIDATE, good, env=None)
    assert sent.code == 0 and good.calls.count("environ") == 1
    broken_home = tmp_path / "g2"
    broken_home.mkdir(mode=0o700)
    broken = FakeGateway(home=str(broken_home), environment={ENV_NAME: URL})
    sent = go(VALIDATE, broken, env=None, config=write_config(tmp_path, "max_chars: 5\n"))
    assert sent.code == 2 and "environ" not in broken.calls


# --- human output -------------------------------------------------------------------------------


def test_without_json_one_line_per_check_goes_to_stderr_and_stdout_is_empty(
    fake_gateway: FakeGateway,
) -> None:
    sent = go(["validate"], fake_gateway)
    assert sent.code == 0 and sent.out == b""
    assert sent.err == (f"config: ok ({CONFIG_OK})\ncredential: ok ({CREDENTIAL_OK})\n".encode())


def test_a_failed_check_prints_its_line_without_json(fake_gateway: FakeGateway) -> None:
    sent = go(["validate"], fake_gateway, env={})
    assert sent.code == 12 and sent.out == b""
    assert sent.err == (
        f"config: ok ({CONFIG_OK})\ncredential: failed ({CREDENTIAL_BAD})\n".encode()
    )


def test_a_config_failure_without_json_is_the_one_error_line(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(["validate"], fake_gateway, config=write_config(tmp_path, "max_chars: 5\n"))
    assert sent.code == 2 and sent.out == b""
    assert sent.err == b"config_invalid: max_chars must be an integer from 2000 to 12000\n"


def test_quiet_suppresses_the_ok_lines_but_not_a_failure(fake_gateway: FakeGateway) -> None:
    ok = go(["validate", "--quiet"], fake_gateway)
    assert (ok.code, ok.out, ok.err) == (0, b"", b"")
    bad = go(["validate", "--quiet"], fake_gateway, env={})
    assert bad.code == 12 and bad.err == f"credential: failed ({CREDENTIAL_BAD})\n".encode()


def test_quiet_does_not_change_the_json_document(fake_gateway: FakeGateway) -> None:
    sent = go([*VALIDATE, "--quiet"], fake_gateway)
    assert sent.document == document(*GOOD, ok=True) and sent.err == b""


def test_verbose_adds_no_line_and_prints_no_request_detail(fake_gateway: FakeGateway) -> None:
    plain = go(["validate"], fake_gateway)
    verbose = go(["validate", "--verbose"], fake_gateway)
    assert verbose.err == plain.err and verbose.code == 0
    assert go([*VALIDATE, "--verbose"], fake_gateway).document == document(*GOOD, ok=True)


def test_the_flags_may_come_before_the_subcommand(fake_gateway: FakeGateway) -> None:
    sent = go(["--json", "validate"], fake_gateway)
    assert sent.document == document(*GOOD, ok=True)


def test_dry_run_has_no_effect_on_validate(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    base = go(VALIDATE, fake_gateway)
    dry = go([*VALIDATE, "--dry-run"], fake_gateway)
    assert (dry.code, dry.out, dry.err) == (base.code, base.out, base.err)
    bad = go([*VALIDATE, "--dry-run"], fake_gateway, env={})
    assert bad.code == 12  # the credential is still read


def test_actor_and_config_flags_are_accepted(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    sent = go([*VALIDATE, "--actor", "auto:ci"], fake_gateway, config=write_config(tmp_path))
    assert sent.code == 0


# --- usage errors -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["validate", "--json", "--bogus"],
        ["validate", "--json", "extra"],
        ["validate", "--json", "--"],
        ["validate", "--json", "--verbose", "--quiet"],
        ["validate", "--json", "--test-message=1"],
        ["validate", "--json", "--stdin-json"],
        ["validate", "--json", "--message", "hi"],
        ["validate", "--json", "--file", "x"],
        ["validate", "--json", "--config"],
        ["validate", "--json", "--test"],
        ["validate", "--json", "--config=a", "--config=b"],
        ["validate", "--json", "--actor=bad"],
    ],
)
def test_a_usage_error_is_exit_2_with_the_envelope_and_reads_nothing(
    argv: list[str], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    sent = go(argv, fake_gateway, env=env)
    assert sent.code == 2 and sent.error["code"] == "usage"
    assert env.log == []
    assert_untouched(sent, fake_gateway)


def test_validate_never_reads_stdin_even_when_it_is_a_terminal_or_a_pipe(
    fake_gateway: FakeGateway,
) -> None:
    for tty in (True, False):
        sent = go(VALIDATE, fake_gateway, tty=tty, stdin=b'{"message":"x"}')
        assert sent.code == 0
    assert fake_gateway.source_reads == 0
    assert len(fake_gateway.source_script) == 2  # both scripted reads are still unread
    fake_gateway.source_script.clear()


# --- the --test-message flag (#32; the behavior is tested in test_validate_test_message.py) -----


def test_test_message_with_a_broken_credential_never_sends(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording({**crowded(tmp_path), ENV_NAME: "not a url"})
    sent = go([*VALIDATE, "--test-message"], fake_gateway, env=env)
    assert (sent.code, sent.document) == (12, document(*BAD, ok=False))
    assert env.log == [("getitem", ENV_NAME)]
    assert_untouched(sent, fake_gateway)


# --- signals --------------------------------------------------------------------------------------

SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]


@pytest.fixture
def guarded_signals() -> Iterator[None]:
    def unexpected(signum: int, _frame: FrameType | None) -> None:
        raise AssertionError(f"signal {signum} was not handled by main")

    saved = {s: signal.signal(s, unexpected) for s in SIGNALS}
    yield
    for s, handler in saved.items():
        signal.signal(s, handler)


@pytest.mark.usefixtures("guarded_signals")
@pytest.mark.parametrize("sig", SIGNALS)
@pytest.mark.parametrize("flags", [["--json"], []])
def test_a_signal_before_the_result_exits_128_plus_n_with_no_output(
    sig: signal.Signals, flags: list[str], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path)

    def killed(*_: Any) -> bytes:
        os.kill(os.getpid(), sig)
        raise AssertionError("the handler must have raised")

    fake_gateway.read_regular_file = killed  # type: ignore[method-assign]
    sent = go(["validate", *flags], fake_gateway, config=config)
    assert (sent.code, sent.out, sent.err) == (128 + sig, b"", b"")
    assert_untouched(sent, fake_gateway)


@pytest.mark.usefixtures("guarded_signals")
def test_handlers_are_restored_after_validate(fake_gateway: FakeGateway) -> None:
    before = {s: signal.getsignal(s) for s in SIGNALS}
    go(VALIDATE, fake_gateway)
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


# --- failing streams ------------------------------------------------------------------------------


class Broken:
    def write(self, _data: bytes) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError


def test_a_closed_stdout_or_stderr_never_changes_the_exit_code(fake_gateway: FakeGateway) -> None:
    assert go(VALIDATE, fake_gateway, out=Broken()).code == 0
    assert go(["validate"], fake_gateway, err=Broken()).code == 0
    assert go(VALIDATE, fake_gateway, out=Broken(), env={}).code == 12
    assert go(["validate"], fake_gateway, err=Broken(), env={}).code == 12


# --- the leak sweep -------------------------------------------------------------------------------


FLAG_SETS = [[], ["--json"], ["--verbose"], ["--quiet"], ["--json", "--quiet"]]


@pytest.mark.parametrize("flags", FLAG_SETS)
@pytest.mark.parametrize("label", ["good", "wrong shape", "unset", "bad config"])
def test_the_webhook_url_is_in_no_stream_and_no_file(
    flags: list[str], label: str, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env: dict[str, str] = {ENV_NAME: URL}
    config = None
    if label == "wrong shape":
        env = {ENV_NAME: URL + "?x=" + SECRET.segments[1]}
    elif label == "unset":
        env = {}
    elif label == "bad config":
        config = write_config(tmp_path, "max_chars: 5\n")
    sent = go(["validate", *flags], fake_gateway, env=env, config=config)
    assert sent.code == {"good": 0, "wrong shape": 12, "unset": 12, "bad config": 2}[label]
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    corpus.add_tree(tmp_path)
    corpus.add("gateway.events", "\n".join(fake_gateway.events))
    corpus.add("gateway.calls", "\n".join(fake_gateway.calls))
    corpus.add("document", repr(sent.out))
    assert corpus.hits(SECRET) == []
    assert b"hooks.slack.com" not in sent.out + sent.err
    assert fake_gateway.connections == []


def test_the_validate_document_is_a_closed_shape(fake_gateway: FakeGateway) -> None:
    sent = go(VALIDATE, fake_gateway)
    parsed = json.loads(sent.out)
    assert set(parsed) == {"ok", "enabled", "checks", "limits"}
    assert all(set(c) == {"name", "ok", "message"} for c in parsed["checks"])


def test_the_handler_is_registered_for_validate() -> None:
    assert cli.HANDLERS["validate"] is cli.validate


# --- limits (#43) ---------------------------------------------------------------------------------


def test_limits_report_the_defaults_with_their_exact_types(fake_gateway: FakeGateway) -> None:
    sent = go(VALIDATE, fake_gateway)
    limits = assert_valid("cli/validate", sent.out)["limits"]
    assert limits == {"max_chars": 3000, "max_bytes": 12000, "timeout_s": 10.0, "spacing_s": 1.0}
    assert list(limits) == ["max_chars", "max_bytes", "timeout_s", "spacing_s"]
    assert type(limits["max_chars"]) is int and type(limits["max_bytes"]) is int
    assert type(limits["timeout_s"]) is float and type(limits["spacing_s"]) is float


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("max_chars: 12000\n", {"max_chars": 12000}),
        ("max_chars: 2000\n", {"max_chars": 2000}),
        ("timeout: 1m\n", {"timeout_s": 60.0}),
        ("timeout: 3500ms\n", {"timeout_s": 3.5}),
        ("timeout: 120\n", {"timeout_s": 120.0}),
        ("max_chars: 5000\ntimeout: 30s\n", {"max_chars": 5000, "timeout_s": 30.0}),
    ],
)
def test_limits_follow_the_loaded_config(
    fake_gateway: FakeGateway, tmp_path: Path, config: str, expected: dict[str, Any]
) -> None:
    sent = go(VALIDATE, fake_gateway, config=write_config(tmp_path, config))
    assert sent.code == 0
    assert assert_valid("cli/validate", sent.out)["limits"] == {**DEFAULT_LIMITS, **expected}


def test_limits_follow_a_drop_in_over_the_config(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, "max_chars: 4000\n")
    drop_in = Path(config).parent / "config.d"
    drop_in.mkdir()
    (drop_in / "10.yaml").write_text("max_chars: 6000\n", encoding="utf-8")
    sent = go(VALIDATE, fake_gateway, config=config)
    assert assert_valid("cli/validate", sent.out)["limits"]["max_chars"] == 6000


def test_limits_are_present_when_the_credential_check_fails_and_when_disabled(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, env={})
    assert sent.code == 12
    assert assert_valid("cli/validate", sent.out)["limits"] == DEFAULT_LIMITS
    config = write_config(tmp_path, "enabled: false\ntimeout: 20s\n")
    off = go(VALIDATE, fake_gateway, config=config)
    assert assert_valid("cli/validate", off.out)["limits"] == {**DEFAULT_LIMITS, "timeout_s": 20.0}


def test_an_invalid_config_prints_the_envelope_without_limits(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    sent = go(VALIDATE, fake_gateway, config=write_config(tmp_path, "max_chars: 5\n"))
    assert sent.code == 2
    assert "limits" not in assert_valid("cli/error", sent.out)
    assert b"limits" not in sent.out


def test_plain_validate_prints_no_limits_line(fake_gateway: FakeGateway) -> None:
    sent = go(["validate"], fake_gateway)
    assert sent.code == 0 and sent.out == b""
    assert b"limits" not in sent.err and b"3000" not in sent.err
    assert sent.err.count(b"\n") == 2
