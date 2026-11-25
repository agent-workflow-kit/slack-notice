"""`validate --test-message` (#32), end to end through ``cli.main``.

The fake gateway and fake clock only: no connection, no DNS, no real Slack. The expected texts and
bytes are written out here from docs/interface.md (validate, Webhook edge, Log), not imported from
the source. The fake credential is built from parts at run time.
"""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from slack_notice import __version__, cli, log
from tests.fake_gateway import Attempt, FakeGateway
from tests.harness import assert_valid
from tests.secret_scan import Corpus, Secret
from tests.send_harness import ENV_NAME, Sent, go, state_path, write_config
from tests.test_secrets_env import Recording, crowded
from tests.test_send import OK, ROWS, reply
from tests.test_send_runtime import (
    free_the_lock_before_the_log,
    hold_the_response,
    sleeps,
    worker_raising,
)

SECRET = Secret()
URL = SECRET.url
ENV = {ENV_NAME: URL}
VT = ["validate", "--json", "--test-message"]

CONFIG_OK = "configuration is valid"
CREDENTIAL_OK = "the webhook credential is set and has the form of a workflow trigger URL"
CREDENTIAL_BAD = "the webhook credential is unset or not a workflow trigger URL"
TEST_OK = (
    "the test message was accepted by Slack; delivery is not observable, "
    "so look at the destination to confirm it arrived"
)
TEST_FAILED = (
    "the test message failed; delivery is not observable, "
    "so look at the destination to see whether it arrived"
)
BODY = '{"body":"\U0001f535 INFO slack-notice\\nvalidate: test message"}'.encode()


def check(name: str, ok: bool, message: str) -> dict[str, Any]:
    return {"name": name, "ok": ok, "message": message}


PASSED = [check("config", True, CONFIG_OK), check("credential", True, CREDENTIAL_OK)]
GOOD = {"ok": True, "enabled": True, "checks": [*PASSED, check("test_message", True, TEST_OK)]}
FAILED = {
    "ok": False,
    "enabled": True,
    "checks": [*PASSED, check("test_message", False, TEST_FAILED)],
}


def run(argv: list[str], gateway: FakeGateway, **kwargs: Any) -> Sent:
    kwargs.setdefault("env", ENV)
    return go(argv, gateway, **kwargs)


# --- the success path ---------------------------------------------------------------------------


def test_a_test_message_posts_the_fixed_rendered_body_and_prints_the_document(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited, sent.err) == (0, True, b"")
    assert assert_valid("cli/validate", sent.out) == GOOD
    assert sent.stdout.count("\n") == 1 and list(sent.document) == ["ok", "enabled", "checks"]
    (connection,) = fake_gateway.connections
    ((path, body),) = connection.requests
    assert path == SECRET.path
    assert body == BODY  # level info, title slack-notice, message validate: test message


def test_the_send_is_logged_like_a_send(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = run([*VT, "--actor", "auto:doctor"], fake_gateway)
    (record,) = sent.records
    assert record["outcome"] == "sent" and (record["exit"], record["code"]) == (0, None)
    assert record["reason"] is None and record["tool"] == "slack-notice"
    assert (record["level"], record["http_status"], record["truncated"]) == ("info", 200, False)
    assert record["bytes"] == len(BODY)
    assert record["message_sha256"] == log.message_sha256("slack-notice", "validate: test message")
    assert record["dedupe_key_sha256"] is None  # no dedupe key
    assert (record["actor"], record["actor_source"], record["version"]) == (
        "auto:doctor",
        "flag",
        __version__,
    )
    assert isinstance(record["duration_ms"], int)
    assert b"validate: test message" not in sent.state_files["log.jsonl"]
    assert b"slack-notice" not in sent.state_files["log.jsonl"].replace(
        b'"tool":"slack-notice"', b""
    )


def pin_clock_after_stamp(gateway: FakeGateway, lock: Path) -> None:
    """Freeze the wall clock 0.25 s after the lock stamp, so the spacing wait is exactly 0.75 s
    however much real time the first run took."""
    stamp = lock.stat().st_mtime
    gateway.wall_time = lambda: stamp + 0.25  # type: ignore[method-assign]


def test_the_send_lock_is_stamped_and_a_second_run_waits_out_the_spacing(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK, OK)
    first = run(VT, fake_gateway)
    lock = state_path(fake_gateway) / "send.lock"
    assert lock.stat().st_size == 1 and fake_gateway.events.count("set_mtime") == 1
    waited = sleeps(fake_gateway)
    pin_clock_after_stamp(fake_gateway, lock)
    second = run(VT, fake_gateway)
    assert (first.code, second.code) == (0, 0) and waited == 0
    assert sleeps(fake_gateway) - waited == pytest.approx(0.75)
    assert [r["outcome"] for r in second.records] == ["sent", "sent"]


def test_a_test_message_and_a_send_space_each_other(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK, OK)
    assert run(["send", "--message", "hi"], fake_gateway).code == 0
    waited = sleeps(fake_gateway)
    pin_clock_after_stamp(fake_gateway, state_path(fake_gateway) / "send.lock")
    assert run(VT, fake_gateway).code == 0
    assert sleeps(fake_gateway) - waited == pytest.approx(0.75)


def test_dry_run_has_no_effect_on_validate(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = run([*VT, "--dry-run"], fake_gateway)
    assert sent.code == 0 and sent.document == GOOD
    assert len(fake_gateway.connections) == 1 and len(sent.records) == 1


def test_a_429_is_retried_through_the_fake_clock(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(429), reply(429), OK)
    sent = run(VT, fake_gateway)
    assert sent.code == 0 and sent.document == GOOD
    assert "sleep:2.0" in fake_gateway.events and "sleep:4.0" in fake_gateway.events
    assert len(fake_gateway.connections) == 3
    assert fake_gateway.events.count("set_mtime") == 3  # every attempt stamps
    assert [r["outcome"] for r in sent.records] == ["sent"]


def test_a_connection_failure_is_retried_once(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(Attempt(connect_error=ConnectionRefusedError()), OK)
    sent = run(VT, fake_gateway)
    assert sent.code == 0 and "sleep:2.0" in fake_gateway.events
    assert len(fake_gateway.connections) == 2


# --- human output -------------------------------------------------------------------------------


def test_human_lines_are_one_per_check_on_stderr(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = run(["validate", "--test-message"], fake_gateway)
    assert sent.code == 0 and sent.stdout == ""
    assert sent.stderr == (
        f"config: ok ({CONFIG_OK})\ncredential: ok ({CREDENTIAL_OK})\n"
        f"test_message: ok ({TEST_OK})\n"
    )


def test_quiet_keeps_only_the_failed_line(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK, reply(500))
    ok = run(["validate", "--test-message", "--quiet"], fake_gateway)
    failed = run(["validate", "--test-message", "--quiet"], fake_gateway)
    assert (ok.code, ok.stderr) == (0, "")
    assert (failed.code, failed.stderr) == (12, f"test_message: failed ({TEST_FAILED})\n")


def test_verbose_adds_the_send_phase_lines(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = run(["validate", "--test-message", "--verbose"], fake_gateway)
    names = [line.split(":")[0] for line in sent.stderr.splitlines()]
    assert names == ["input", "render", "send", "config", "credential", "test_message", "log"]
    assert URL not in sent.stderr and "hooks.slack.com" not in sent.stderr


def test_a_failed_check_under_json_writes_no_stderr_line(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(500))
    sent = run(VT, fake_gateway)
    assert sent.code == 12 and sent.err == b""


# --- every row of the Webhook edge table --------------------------------------------------------


@pytest.mark.parametrize("name", sorted(ROWS))
def test_every_failure_is_one_failed_check_with_exit_12_and_a_send_record(
    name: str, fake_gateway: FakeGateway
) -> None:
    attempts, code, want = ROWS[name]
    fake_gateway.script(*attempts)
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited) == (code, True)
    # the cause is in the log only: the document and the exit code carry nothing but the failure
    assert assert_valid("cli/validate", sent.out) == FAILED
    assert "error" not in sent.document and sent.err == b""
    assert len(fake_gateway.connections) == len(attempts)
    for sleep in want.get("sleeps", []):
        assert f"sleep:{sleep}" in fake_gateway.events
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"], record["reason"]) == (
        want["log"],
        12,
        want["code"],
        None,
    )
    assert record["http_status"] == want["status"] and record["level"] == "info"
    assert record["bytes"] == len(BODY)
    assert record["message_sha256"] == log.message_sha256("slack-notice", "validate: test message")
    assert SECRET.segments[0].encode() not in sent.everything


def test_a_failed_check_in_human_form_is_one_error_line(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(500))
    sent = run(["validate", "--test-message"], fake_gateway)
    assert sent.code == 12 and sent.stdout == ""
    assert sent.stderr == (
        f"config: ok ({CONFIG_OK})\ncredential: ok ({CREDENTIAL_OK})\n"
        f"test_message: failed ({TEST_FAILED})\n"
    )


def test_a_lock_wait_past_the_deadline_is_a_failed_check_and_a_failed_record(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_the_lock_before_the_log(fake_gateway, monkeypatch)
    fake_gateway.lock_held = True
    sent = run(VT, fake_gateway, config=write_config(tmp_path, "timeout: 3\n"))
    assert (sent.code, sent.document) == (12, FAILED)
    assert fake_gateway.connections == []
    (record,) = sent.records
    assert (record["outcome"], record["code"], record["http_status"]) == (
        "failed",
        "unavailable",
        None,
    )


def test_the_deadline_starts_at_the_check_and_bounds_the_whole_run(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(reply(429), reply(429))  # the 4 s wait after the second does not fit
    sent = run(VT, fake_gateway, config=write_config(tmp_path, "timeout: 3\n"))
    assert sent.code == 12 and sent.document == FAILED
    (record,) = sent.records
    assert record["code"] == "rate_limited" and record["duration_ms"] <= 3000


# --- what comes before the check ----------------------------------------------------------------


def test_a_failed_credential_ends_the_run_with_no_test_message(
    fake_gateway: FakeGateway,
) -> None:
    env = Recording({})
    sent = run(VT, fake_gateway, env=env)
    assert sent.code == 12 and not sent.exited
    assert sent.document == {
        "ok": False,
        "enabled": True,
        "checks": [check("config", True, CONFIG_OK), check("credential", False, CREDENTIAL_BAD)],
    }
    assert_valid("cli/validate", sent.out)
    assert fake_gateway.connections == [] and sent.records == [] and sent.state_files == {}
    assert not state_path(fake_gateway).exists()


@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_a_config_failure_is_exit_2_first(
    flags: list[str], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording({})
    sent = run(
        ["validate", "--test-message", *flags],
        fake_gateway,
        env=env,
        config=write_config(tmp_path, "max_chars: 5\n"),
    )
    assert sent.code == 2 and env.log == []
    if flags:
        assert sent.error["code"] == "config_invalid"
    assert fake_gateway.connections == [] and not state_path(fake_gateway).exists()


@pytest.mark.parametrize("flags", [["--json"], []])
@pytest.mark.parametrize("env", [{}, ENV, {ENV_NAME: "nonsense"}])
def test_disabled_is_exit_22_before_any_check_and_before_reading_the_credential(
    flags: list[str], env: dict[str, str], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    recording = Recording(env)
    sent = run(
        ["validate", "--test-message", *flags],
        fake_gateway,
        env=recording,
        config=write_config(tmp_path, "enabled: false\n"),
    )
    assert (sent.code, sent.exited) == (22, False)
    assert recording.log == []  # the credential variable is not even looked at
    if flags:
        assert sent.out == b'{"outcome":"disabled"}\n' and sent.err == b""
        assert_valid("cli/validate", sent.out)
        assert_valid("cli/send", sent.out)
    else:
        assert (sent.out, sent.err) == (b"", b"disabled in config\n")
    assert fake_gateway.connections == [] and not state_path(fake_gateway).exists()
    assert sent.records == [] and fake_gateway.calls.count("environ") == 0


def test_disabled_plus_dry_run_is_still_22(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    sent = run([*VT, "--dry-run"], fake_gateway, config=write_config(tmp_path, "enabled: false\n"))
    assert sent.code == 22 and fake_gateway.connections == []


def test_exit_2_beats_disabled(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, "enabled: false\nmax_chars: 5\n")
    assert run(VT, fake_gateway, config=config).code == 2


def test_only_the_configured_variable_is_read_and_only_once(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    fake_gateway.script(OK)
    sent = run(VT, fake_gateway, env=env)
    assert sent.code == 0
    assert env.log == [("getitem", ENV_NAME)]


def test_the_environment_is_read_lazily_through_the_gateway(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    home = tmp_path / "h2"
    home.mkdir(mode=0o700)
    gateway = FakeGateway(home=str(home), environment=dict(ENV))
    gateway.script(OK)
    assert go(["validate", "--test-message"], gateway, env=None).code == 0
    assert gateway.calls.count("environ") == 1


def test_plain_validate_is_unchanged(fake_gateway: FakeGateway) -> None:
    sent = run(["validate", "--json"], fake_gateway)
    assert sent.code == 0 and sent.document["checks"] == PASSED
    assert (
        fake_gateway.connections == [] and not sent.exited and not state_path(fake_gateway).exists()
    )


# --- signals ------------------------------------------------------------------------------------

SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]


@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_before_the_send_is_armed_exits_128_plus_n_with_nothing_sent(
    sig: int, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = cli.render

    def killed(*args: Any, **kwargs: Any) -> Any:
        os.kill(os.getpid(), sig)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "render", killed)
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited, sent.out, sent.err) == (128 + sig, False, b"", b"")
    assert fake_gateway.connections == [] and sent.records == []
    assert not state_path(fake_gateway).exists()


@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_during_the_lock_wait_is_a_failed_check_and_nothing_is_sent(
    sig: int, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_the_lock_before_the_log(fake_gateway, monkeypatch)
    fake_gateway.lock_held = True
    real = fake_gateway.try_lock

    def kill_then_poll(fd: int) -> bool:
        os.kill(os.getpid(), sig)
        return real(fd)

    fake_gateway.try_lock = kill_then_poll  # type: ignore[method-assign]
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.document) == (12, FAILED)
    assert fake_gateway.connections == []
    (record,) = sent.records
    assert (record["outcome"], record["code"]) == ("failed", "unavailable")


@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_while_the_gate_is_writing_is_a_failed_check_logged_outcome_unknown(
    sig: int, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gateway.script(OK)
    fake_gateway.allow_unconsumed_script = True
    hold_the_response(monkeypatch, sig)
    before = {s: signal.getsignal(s) for s in SIGNALS}
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited, sent.document) == (12, True, FAILED)
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"]) == (
        "outcome_unknown",
        12,
        "outcome_unknown",
    )
    assert {s: signal.getsignal(s) for s in SIGNALS} == before
    fake_gateway.release_stalls()


def test_a_signal_during_the_log_step_changes_nothing(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = log.log_result

    def kill_then_log(*args: Any, **kwargs: Any) -> bool:
        os.kill(os.getpid(), signal.SIGTERM)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "log_result", kill_then_log)
    fake_gateway.script(OK)
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.document) == (0, GOOD) and len(sent.records) == 1


# --- exit 1 -------------------------------------------------------------------------------------


def test_an_exception_after_the_gate_moved_to_writing_is_the_exit_1_envelope_and_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "attempt_work", worker_raising(after_writing=True))
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited) == (1, True)
    assert sent.error["code"] == "internal" and sent.error["unknown_outcome"] is True
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"]) == ("outcome_unknown", 1, "internal")
    assert SECRET.segments[0].encode() not in sent.everything


def test_an_exception_before_the_gate_moved_to_writing_is_exit_1_known_and_not_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "attempt_work", worker_raising(after_writing=False))
    sent = run(VT, fake_gateway)
    assert sent.code == 1 and sent.error["unknown_outcome"] is False and sent.records == []


def test_a_bug_in_the_render_is_exit_1_by_return_and_not_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError(URL)

    monkeypatch.setattr(cli, "render", boom)
    sent = run(VT, fake_gateway)
    assert (sent.code, sent.exited, sent.records) == (1, False, [])
    assert fake_gateway.connections == [] and SECRET.segments[0].encode() not in sent.everything


# --- no secret anywhere -------------------------------------------------------------------------

SCENARIOS = {
    "sent": ([OK], ENV, 0),
    "rejected": ([reply(401)], ENV, 12),
    "429": ([reply(429)] * 3, ENV, 12),
    "refused": ([Attempt(connect_error=ConnectionRefusedError(URL))] * 2, ENV, 12),
    "unset": ([], {}, 12),
}


@pytest.mark.parametrize("flags", [[], ["--json"], ["--verbose"], ["--quiet"]])
@pytest.mark.parametrize("label", sorted(SCENARIOS))
def test_the_webhook_url_is_in_no_stream_and_no_file(
    flags: list[str], label: str, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    attempts, env, code = SCENARIOS[label]
    fake_gateway.script(*attempts)
    sent = run(["validate", "--test-message", *flags], fake_gateway, env=env)
    assert sent.code == code
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    corpus.add_tree(tmp_path)
    corpus.add("state", sent.everything)
    corpus.add("gateway.events", "\n".join(fake_gateway.events))
    corpus.add("gateway.calls", "\n".join(fake_gateway.calls))
    assert corpus.hits(SECRET) == []
    assert b"hooks.slack.com" not in sent.out + sent.err + b"".join(sent.state_files.values())
    assert json.dumps(sent.records).count("slack.com") == 0
