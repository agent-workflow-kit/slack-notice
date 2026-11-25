"""Spacing, signals, exit 1, state failures and secrecy of the real `send` (#28).

Companion of ``test_send.py``: the same in-process harness, fake gateway and fake clock.
"""

from __future__ import annotations

import os
import signal
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, log, webhook
from slack_notice.gateway import SourceRead, StateUnusable
from slack_notice.log import STATE_WARNING
from tests.fake_gateway import Attempt, FakeConnection, FakeGateway, Reply
from tests.send_harness import (
    CANARY,
    SEND,
    URL,
    Sent,
    go,
    state_path,
    stdin_json,
    write_config,
)
from tests.test_send import HELLO, OK, reply

SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]


def free_the_lock_before_the_log(gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    """The fake's ``lock_held`` blocks every flock: let the log lock through (a held send lock is
    another process's, the log lock is free)."""
    real = log.log_result

    def freed(*args: Any, **kwargs: Any) -> bool:
        gateway.lock_held = False
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "log_result", freed)


def sleeps(gateway: FakeGateway) -> float:
    return sum(float(e.split(":")[1]) for e in gateway.events if e.startswith("sleep:"))


# --- spacing ------------------------------------------------------------------------------------


def test_a_send_with_spacing_queues_a_second_caller_one_second_after_the_first(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK, OK)
    first = go(SEND, fake_gateway, stdin=HELLO)
    lock = state_path(fake_gateway) / "send.lock"
    stamped = lock.stat().st_mtime
    waited = sleeps(fake_gateway)
    second = go(SEND, fake_gateway, stdin=HELLO)
    assert (first.code, second.code) == (0, 0)
    assert waited == 0  # the first send found an empty lock file: no wait
    assert 0.9 < sleeps(fake_gateway) - waited <= 1.0  # the second waited out the spacing
    assert lock.stat().st_mtime - stamped >= 0.99  # and stamped one second later
    assert lock.stat().st_size == 1
    assert [r["outcome"] for r in second.records] == ["sent", "sent"]


def test_every_attempt_stamps_the_send_lock_again(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(429), reply(429), OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert sent.code == 0
    assert fake_gateway.events.count("set_mtime") == 3


def test_a_stamp_that_raises_on_a_retry_does_not_turn_a_known_429_into_exit_1(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(reply(429), OK)
    calls: list[int] = []
    real = fake_gateway.set_mtime

    def flaky(fd: int, seconds: float) -> None:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError(URL)  # not an OSError: the stamp itself does not absorb it
        real(fd, seconds)

    fake_gateway.set_mtime = flaky  # type: ignore[method-assign]
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.document["outcome"]) == (0, "sent")
    assert len(fake_gateway.connections) == 2 and len(calls) == 2
    assert sent.stderr.count(STATE_WARNING) == 1
    assert CANARY.encode() not in sent.everything


def test_a_stamp_that_raises_after_a_429_leaves_rate_limited_not_internal(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(reply(429), reply(429), reply(429))

    def always(_fd: int, _seconds: float) -> None:
        raise RuntimeError("x")

    fake_gateway.set_mtime = always  # type: ignore[method-assign]
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.error["code"]) == (12, "rate_limited")


def test_a_lock_wait_that_outlasts_the_deadline_is_unavailable_lock_and_failed(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_the_lock_before_the_log(fake_gateway, monkeypatch)
    fake_gateway.lock_held = True
    sent = go(SEND, fake_gateway, stdin=HELLO, config=write_config(tmp_path, "timeout: 3\n"))
    assert (sent.code, sent.exited) == (12, True)
    error = sent.error
    assert error["code"] == "unavailable" and error["details"] == {"phase": "lock"}
    assert (error["retryable"], error["unknown_outcome"]) == (True, False)
    assert error == webhook.unavailable("lock").envelope()["error"]
    assert fake_gateway.connections == []
    (record,) = sent.records
    assert (record["outcome"], record["code"], record["http_status"]) == (
        "failed",
        "unavailable",
        None,
    )
    assert record["bytes"] is not None  # the body was rendered before the lock wait


def test_a_spacing_wait_not_shorter_than_the_time_left_ends_at_once_without_sleeping(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    go(SEND, fake_gateway, stdin=HELLO)  # leaves a fresh stamp on the lock file
    stamp = (state_path(fake_gateway) / "send.lock").stat().st_mtime
    fake_gateway.wall_time = lambda: stamp + 0.1  # type: ignore[method-assign]
    real = fake_gateway.read_source

    def slow_input(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        fake_gateway._advance(2.5)  # pyright: ignore[reportPrivateUsage]
        return real(source, max_bytes, remaining)

    fake_gateway.read_source = slow_input  # type: ignore[method-assign]
    before = sleeps(fake_gateway)
    sent = go(SEND, fake_gateway, stdin=HELLO, config=write_config(tmp_path, "timeout: 3\n"))
    assert (sent.code, sent.error["code"], sent.error["details"]) == (
        12,
        "unavailable",
        {"phase": "lock"},
    )
    assert sleeps(fake_gateway) == before  # 0.5 s left, 0.9 s to wait: no sleeping
    assert len(fake_gateway.connections) == 1  # only the first send's


def test_the_lock_is_released_after_every_outcome(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(500), OK)
    go(SEND, fake_gateway, stdin=HELLO)
    second = go(SEND, fake_gateway, stdin=HELLO)
    assert second.code == 0  # a stuck lock would have timed out


def test_an_unusable_state_dir_means_no_spacing_one_warning_and_the_same_exit_code(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.state_dir_error = StateUnusable("x")
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert sent.code == 0 and sent.records == []
    assert sent.stderr.count(STATE_WARNING) == 1 and sent.stderr.endswith("\n")


def test_a_log_failure_never_changes_the_exit_code_and_warns_once(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.state_file_errors["log.lock"] = StateUnusable("x")
    fake_gateway.script(reply(500))
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO)
    assert sent.code == 12 and sent.records == []
    assert sent.stderr.count(STATE_WARNING) == 1


def test_log_false_writes_nothing_and_never_opens_the_log(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO, config=write_config(tmp_path, "log: false\n"))
    assert sent.code == 0 and "log.jsonl" not in sent.state_files
    assert "open_state_file:log.lock" not in fake_gateway.events


def test_a_caller_bug_in_the_log_call_is_skipped_with_the_one_warning(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    impossible = webhook.Outcome(12, "upstream_error", "m", None, False, True)  # no status

    def fake_work(*_a: Any, **_k: Any) -> Any:
        return lambda deadline: (deadline.enter_writing(), impossible)[1]

    monkeypatch.setattr(cli, "attempt_work", fake_work)
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO)
    assert sent.code == 12 and sent.records == []
    assert sent.stderr.count(STATE_WARNING) == 1


# --- exit 1 -------------------------------------------------------------------------------------


def worker_raising(*, after_writing: bool) -> Any:
    def make(*_a: Any, **_k: Any) -> Any:
        def work(deadline: Any) -> Any:
            if after_writing:
                assert deadline.enter_writing()
            raise RuntimeError(URL)

        return work

    return make


def test_an_exception_after_the_gate_moved_to_writing_is_exit_1_unknown_and_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "attempt_work", worker_raising(after_writing=True))
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (1, True)
    error = sent.error
    assert (error["code"], error["message"], error["retryable"], error["unknown_outcome"]) == (
        "internal",
        "internal error",
        False,
        True,
    )
    assert sent.stderr == "internal: internal error (RuntimeError)\n"
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"]) == ("outcome_unknown", 1, "internal")
    assert CANARY.encode() not in sent.everything


def test_an_exception_before_the_gate_moved_to_writing_is_exit_1_known_and_not_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "attempt_work", worker_raising(after_writing=False))
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert sent.code == 1 and sent.error["unknown_outcome"] is False
    assert sent.records == []


def test_a_bug_in_the_main_thread_before_step_5_is_exit_1_by_return_and_not_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError(URL)

    monkeypatch.setattr(cli, "render", boom)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (1, False)
    assert sent.error["unknown_outcome"] is False and sent.records == []
    assert "environ" not in fake_gateway.calls
    assert CANARY.encode() not in sent.everything


# --- signals ------------------------------------------------------------------------------------


def hold_the_response(monkeypatch: pytest.MonkeyPatch, sig: int) -> None:
    """The request is written, a real signal arrives, and the response never does."""
    real_post = FakeConnection.post

    def post(self: FakeConnection, path: str, body: bytes) -> None:
        real_post(self, path, body)
        os.kill(os.getpid(), sig)

    def getresponse(self: FakeConnection) -> Any:
        self._gateway._block_until_released()  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(FakeConnection, "post", post)
    monkeypatch.setattr(FakeConnection, "getresponse", getresponse)


@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_while_the_gate_is_writing_is_outcome_unknown_not_128_plus_n(
    sig: int, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gateway.script(OK)
    fake_gateway.allow_unconsumed_script = True
    hold_the_response(monkeypatch, sig)
    before = {s: signal.getsignal(s) for s in SIGNALS}
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (12, True)
    error = sent.error
    assert (error["code"], error["unknown_outcome"]) == ("outcome_unknown", True)
    (record,) = sent.records
    assert (record["outcome"], record["exit"]) == ("outcome_unknown", 12)
    assert {s: signal.getsignal(s) for s in SIGNALS} == before
    fake_gateway.release_stalls()


def test_a_signal_during_the_lock_wait_is_unavailable_lock_and_logged_failed(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_the_lock_before_the_log(fake_gateway, monkeypatch)
    fake_gateway.lock_held = True
    real = fake_gateway.try_lock

    def kill_then_poll(fd: int) -> bool:
        os.kill(os.getpid(), signal.SIGTERM)
        return real(fd)

    fake_gateway.try_lock = kill_then_poll  # type: ignore[method-assign]
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.error["code"], sent.error["details"]) == (
        12,
        "unavailable",
        {"phase": "lock"},
    )
    (record,) = sent.records
    assert (record["outcome"], record["code"]) == ("failed", "unavailable")
    assert fake_gateway.connections == []


@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_during_input_exits_128_plus_n_with_no_output_and_no_record(
    sig: int, fake_gateway: FakeGateway
) -> None:
    real = fake_gateway.read_source

    def kill_during_read(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        os.kill(os.getpid(), sig)
        return real(source, max_bytes, remaining)

    fake_gateway.read_source = kill_during_read  # type: ignore[method-assign]
    fake_gateway.source_script.append(SourceRead(HELLO))
    sent = go(SEND, fake_gateway)
    assert (sent.code, sent.exited) == (128 + sig, False)
    assert (sent.out, sent.err, sent.records) == (b"", b"", [])
    assert fake_gateway.connections == [] and "environ" not in fake_gateway.calls


def test_a_signal_during_the_log_step_changes_nothing(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = log.log_result

    def kill_then_log(*args: Any, **kwargs: Any) -> bool:
        os.kill(os.getpid(), signal.SIGTERM)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "log_result", kill_then_log)
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.document["outcome"]) == (0, "sent")
    assert len(sent.records) == 1


# --- no secret anywhere -------------------------------------------------------------------------

LEAKY = [
    Attempt(connect_error=ValueError(URL)),
    Attempt(tls_error=OSError(URL)),
    Attempt(write_error=OSError(URL)),
    Attempt(reply=OSError(URL)),
    Attempt(reply=Reply(status=400, body=URL.encode())),
    Attempt(reply=Reply(status=200, body=URL.encode())),
    Attempt(reply=Reply(status=500, body=b'{"error":"' + URL.encode() + b'"}')),
]


@pytest.mark.parametrize("index", range(len(LEAKY)))
@pytest.mark.parametrize("flags", [["--json"], ["--verbose"], ["--json", "--verbose"]])
def test_a_secret_in_an_exception_or_a_response_reaches_no_stream_and_no_file(
    index: int, flags: list[str], fake_gateway: FakeGateway
) -> None:
    fake_gateway.script(LEAKY[index], LEAKY[index])
    fake_gateway.allow_unconsumed_script = True
    sent = go(["send", *flags, "--stdin-json", "--dedupe-key=k"], fake_gateway, stdin=HELLO)
    assert sent.code == 12
    assert CANARY.encode() not in sent.everything
    assert b"hooks.slack.com" not in sent.everything
    for connection in fake_gateway.connections:
        assert CANARY not in repr(vars(connection).get("host", "")) + connection.user_agent
        assert all(path == "/triggers/" + CANARY + "/seg" for path, _ in connection.requests)
        assert all(CANARY.encode() not in body for _, body in connection.requests)


def test_the_context_repr_holds_neither_the_environment_nor_the_url(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    real = cli.send

    def spy(ctx: cli.Context) -> int:
        seen.append(repr(ctx))
        return real(ctx)

    monkeypatch.setitem(cli.HANDLERS, "send", spy)
    fake_gateway.script(OK)
    go(SEND, fake_gateway, stdin=HELLO)
    assert seen and CANARY not in seen[0] and "hooks.slack.com" not in seen[0]


def test_no_exception_chain_of_the_credential_failure_holds_the_value(
    fake_gateway: FakeGateway,
) -> None:
    ctx_errors: list[BaseException] = []
    real = webhook.read_webhook

    def capture(env: Any, name: str) -> Any:
        try:
            return real(env, name)
        except webhook.CredentialInvalid as exc:
            ctx_errors.append(exc)
            raise

    import slack_notice.cli as module

    original = module.webhook.read_webhook
    module.webhook.read_webhook = capture  # type: ignore[assignment]
    try:
        go(SEND, fake_gateway, stdin=HELLO, env={"SLACK_WEBHOOK": "bad " + CANARY})
    finally:
        module.webhook.read_webhook = original
    (exc,) = ctx_errors
    assert exc.__cause__ is None and exc.__context__ is None
    assert CANARY not in repr(exc) and CANARY not in str(exc.args)


def test_every_scenario_leaves_the_state_directory_mode_0700_and_files_0600(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    go(SEND, fake_gateway, stdin=HELLO)
    directory = state_path(fake_gateway)
    assert (directory.stat().st_mode & 0o777) == 0o700
    assert {(p.stat().st_mode & 0o777) for p in directory.iterdir()} == {0o600}


def test_the_record_for_a_dedupe_key_and_a_refusal_never_carry_text(
    fake_gateway: FakeGateway,
) -> None:
    sent: Sent = go([*SEND, "--dedupe-key=" + CANARY], fake_gateway, stdin=stdin_json(title=CANARY))
    assert sent.code == 20 and sent.records[0]["dedupe_key_sha256"] is None
    assert CANARY.encode() not in sent.state_files["log.jsonl"]
    assert replace  # keep the import used


def test_a_state_warning_raised_in_the_worker_is_written_by_the_main_thread_after_the_result(
    fake_gateway: FakeGateway,
) -> None:
    """A stderr nobody reads must not block the worker under the gate's lock."""
    import threading

    threads: list[tuple[str, bytes]] = []

    class Sink:
        def write(self, data: bytes) -> int:
            threads.append((threading.current_thread().name, data))
            return len(data)

        def flush(self) -> None:
            pass

    def always(_fd: int, _seconds: float) -> None:
        raise RuntimeError("x")

    fake_gateway.set_mtime = always  # type: ignore[method-assign]
    fake_gateway.script(OK)
    go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, err=Sink())
    warned = [name for name, data in threads if STATE_WARNING.encode() in data]
    assert warned == ["slack-notice-stderr"]  # never the worker, which holds the gate's lock
    order = [data for _, data in threads]
    sent_at = next(i for i, d in enumerate(order) if d.startswith(b"sent ("))
    warning_at = next(i for i, d in enumerate(order) if STATE_WARNING.encode() in d)
    assert sent_at < warning_at  # the result first, the deferred warning with the log step
