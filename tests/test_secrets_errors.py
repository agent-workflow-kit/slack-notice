"""Exceptions that carry the credential, and the chains they leave behind (#29).

``InvalidURL`` and ``ValueError`` raised with the fake URL from the gateway, the worker, the
state directory, the lock and the log writer end as a class name or a fixed text: nothing of
their message reaches stdout, stderr or the log, and the exceptions the tool itself raises hold
no part of the credential on ``__cause__`` or ``__context__`` either.
"""

from __future__ import annotations

import http.client
import io
import ssl
import threading
import traceback
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, webhook
from slack_notice.gateway import SystemGateway
from slack_notice.log import STATE_WARNING
from tests.fake_gateway import Attempt, FakeGateway, Reply
from tests.secret_scan import Corpus, Secret
from tests.send_harness import go
from tests.test_send import HELLO, OK

SECRET = Secret()
URL = SECRET.url
CARRIERS: dict[str, BaseException] = {
    "InvalidURL": http.client.InvalidURL(URL),
    "ValueError": ValueError(URL),
}


def chain(exc: BaseException | None) -> list[BaseException]:
    found: list[BaseException] = []
    while exc is not None and exc not in found:
        found.append(exc)
        exc = exc.__cause__ or exc.__context__
    return found


def text_of(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + repr(exc) + str(exc.args)


@pytest.mark.parametrize("name", sorted(CARRIERS))
def test_an_exception_carrying_the_url_in_the_worker_is_a_class_name_on_stderr_and_nothing_else(
    name: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exc = CARRIERS[name]

    def make(*_a: Any, **_k: Any) -> Any:
        def work(deadline: Any) -> Any:
            assert deadline.enter_writing()
            raise exc

        return work

    monkeypatch.setattr(cli, "attempt_work", make)
    sent = go(["send", "--json", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.code == 1
    assert sent.stderr == f"internal: internal error ({name})\n"
    assert sent.error["message"] == "internal error" and sent.error["details"] is None
    (record,) = sent.records
    assert record["code"] == "internal" and record["outcome"] == "outcome_unknown"
    corpus = Corpus()
    corpus.add_tree(tmp_path)
    corpus.add("out", sent.out + sent.err)
    assert corpus.hits(SECRET) == []


@pytest.mark.parametrize("name", sorted(CARRIERS))
def test_a_worker_exception_is_not_printed_by_the_thread_machinery(
    name: str,
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    hooked: list[Any] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: hooked.append(args))
    monkeypatch.setattr("sys.excepthook", lambda *args: hooked.append(args))
    fake_gateway.script(Attempt(write_error=CARRIERS[name]))
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.code == 12
    assert hooked == []  # the worker handed it to the main thread: nobody printed it
    seen = capfd.readouterr()
    assert seen.out == "" and seen.err == ""  # nothing went to the real descriptors either


@pytest.mark.parametrize("name", sorted(CARRIERS))
@pytest.mark.parametrize(
    "hook",
    [
        "state_dir_error",
        "write_error",
        "truncate_error",
        "mtime_error",
        "set_mtime_error",
        "lock_error",
    ],
)
def test_the_state_lock_and_log_paths_print_only_the_fixed_warning(
    name: str, hook: str, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    setattr(fake_gateway, hook, CARRIERS[name])
    fake_gateway.allow_unconsumed_script = True
    fake_gateway.script(OK)
    sent = go(
        ["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env, validate_log=False
    )
    assert sent.code in (0, 1)
    assert sent.stderr in ("", STATE_WARNING + "\n") or sent.stderr.startswith(
        ("sent (", "internal: internal error (")
    )
    corpus = Corpus()
    corpus.add_tree(tmp_path)
    corpus.add("out", sent.out + sent.err)
    assert corpus.hits(SECRET) == []
    assert name not in sent.stderr or sent.stderr.startswith("internal")


@pytest.mark.parametrize("phase", ["connect_error", "tls_error", "write_error"])
@pytest.mark.parametrize("name", sorted(CARRIERS))
def test_a_connection_exception_with_the_url_is_a_fixed_envelope(
    name: str, phase: str, fake_gateway: FakeGateway
) -> None:
    fields: dict[str, Any] = {phase: CARRIERS[name]}
    fake_gateway.script(Attempt(**fields), Attempt(**fields))
    sent = go(["send", "--json", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.code == 12
    assert set(sent.error["details"] or {}) <= {"tls", "timeout"}
    assert Corpus(blobs={"o": sent.out + sent.err}).hits(SECRET) == []
    fake_gateway.allow_unconsumed_script = True


def test_a_response_body_that_is_the_url_never_reaches_the_envelope(
    fake_gateway: FakeGateway,
) -> None:
    body = b'{"error":"' + URL.encode() + b'"}'
    fake_gateway.script(Attempt(reply=Reply(status=400, body=body)))
    sent = go(["send", "--json", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.error["details"] == {"host_error": None, "http_status": 400}
    assert Corpus(blobs={"o": sent.out + sent.err}).hits(SECRET) == []


# --- the chains the tool itself raises --------------------------------------------------------


def real_connection() -> Any:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return SystemGateway().https_connection(
        "hooks.slack.com", 443, timeout=3.0, context=context, user_agent="slack-notice/0.0.0"
    )


@pytest.mark.parametrize(
    "path",
    [
        SECRET.path + " x",  # a space: http.client refuses it with the target in its message
        SECRET.path + "\x00",
        SECRET.path + "é",  # not encodable: UnicodeEncodeError holds the target
        SECRET.path + "\n",
    ],
    ids=["space", "nul", "non-ascii", "newline"],
)
def test_the_real_connection_refuses_a_bad_target_with_a_fixed_error_and_a_clean_chain(
    path: str,
) -> None:
    connection = real_connection()  # constructed only: nothing connects before the refusal
    with pytest.raises(http.client.InvalidURL) as caught:
        connection.post(path, b"{}")
    exc = caught.value
    assert str(exc) == "invalid request"
    assert chain(exc) == [exc]  # no cause, no context: nothing else holds the target
    assert exc.__cause__ is None and exc.__context__ is None
    for piece in chain(exc):
        assert Corpus(blobs={"t": text_of(piece).encode()}).hits(SECRET) == []


def test_a_bad_target_met_inside_a_handler_keeps_only_the_callers_own_context() -> None:
    """The exception is raised outside the library's handler, so the one context it may have is
    whatever the caller was already handling, never the library's message."""
    connection = real_connection()
    with pytest.raises(http.client.InvalidURL) as caught:
        try:
            raise RuntimeError("caller")
        except RuntimeError:
            connection.post(SECRET.path + " x", b"{}")
    assert [type(e) for e in chain(caught.value)] == [http.client.InvalidURL, RuntimeError]
    assert Corpus(blobs={"t": text_of(caught.value).encode()}).hits(SECRET) == []


def test_the_credential_failure_holds_nothing_on_its_chain() -> None:
    for value in (URL + "?x", SECRET.path, "  ", "", URL + "a" * 1100):
        with pytest.raises(webhook.CredentialInvalid) as caught:
            webhook.read_webhook({"SLACK_WEBHOOK": value}, "SLACK_WEBHOOK")
        assert chain(caught.value) == [caught.value]
        assert Corpus(blobs={"t": text_of(caught.value).encode()}).hits(SECRET) == []


def test_a_hostile_stream_that_raises_the_url_is_not_echoed_back(fake_gateway: FakeGateway) -> None:
    """The exception from a failing output stream is swallowed with its class only."""

    class Broken:
        def write(self, data: Any) -> int:
            raise OSError(URL)

        def flush(self) -> None:
            raise OSError(URL)

    kept = io.BytesIO()
    fake_gateway.script(OK)
    sent = go(
        ["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env, out=Broken(), err=kept
    )
    assert sent.code in (0, 1, 12)
    assert Corpus(blobs={"e": kept.getvalue()}).hits(SECRET) == []
