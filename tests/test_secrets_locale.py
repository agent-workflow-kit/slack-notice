"""No locale or other variable is read by a send, not even by the standard library (#29).

``argparse`` looks up its texts through ``gettext``, which reads ``LANGUAGE``, ``LC_ALL``,
``LC_MESSAGES`` and ``LANG``; with a ``messages`` catalog installed those variables changed the
``--help`` text. The CLI turns the translation off, so no variable reaches the output.
"""

from __future__ import annotations

import gettext
import io
import os
import struct
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.gateway import NoUsableCA, SystemGateway
from tests.fake_gateway import FakeGateway
from tests.send_harness import go
from tests.test_secrets_env import CASES, Recording, decoys, gateway_in


class RecordingEnviron(MutableMapping[str, str]):
    """A stand-in for ``os.environ`` that logs every access made through it."""

    def __init__(self, values: dict[str, str]) -> None:
        self.store = dict(values)
        self.log: list[tuple[str, Any]] = []

    def __getitem__(self, key: str) -> str:
        self.log.append(("getitem", key))
        return self.store[key]

    def __setitem__(self, key: str, value: str) -> None:
        self.log.append(("setitem", key))
        self.store[key] = value

    def __delitem__(self, key: str) -> None:
        self.log.append(("delitem", key))
        del self.store[key]

    def __iter__(self) -> Iterator[str]:
        self.log.append(("iter", None))
        return iter(self.store)

    def __len__(self) -> int:
        self.log.append(("len", None))
        return len(self.store)

    def copy(self) -> dict[str, str]:
        self.log.append(("copy", None))
        return dict(self.store)


@pytest.mark.parametrize(
    "case",
    [
        "sent",
        "429 then sent",
        "500",
        "network error",
        "certificate",
        "unset credential",
        "refusal",
        "dry run",
        "verbose",
    ],
)
def test_the_code_never_touches_os_environ_during_a_send(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts, flags, env, stdin = CASES[case]
    spy = RecordingEnviron({**os.environ, **decoys(tmp_path)})
    monkeypatch.setattr(os, "environ", spy)
    gateway = gateway_in(tmp_path, "g", *attempts)
    sent = go(["send", *flags, "--stdin-json"], gateway, stdin=stdin, env=env)
    assert spy.log == [], (case, spy.log)
    assert sent.code in (0, 12, 20)


def test_the_ca_paths_and_the_tls_context_never_touch_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ssl.get_default_verify_paths`` reads SSL_CERT_FILE and SSL_CERT_DIR through os.environ;
    the compiled defaults are taken without it. Nothing connects: only a context is built."""
    spy = RecordingEnviron({"SSL_CERT_FILE": "/nowhere/f", "SSL_CERT_DIR": "/nowhere/d"})
    monkeypatch.setattr(os, "environ", spy)
    gateway = SystemGateway()
    candidates = gateway.ca_candidates()
    try:
        gateway.tls_context()
    except NoUsableCA:
        pass  # a host without any bundle: still no environment read
    assert spy.log == []
    assert "/nowhere/f" not in (candidates.cafile, candidates.capath)
    assert "/nowhere/d" not in (candidates.cafile, candidates.capath)


def test_the_recording_environ_can_see_a_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Self-check: the spy records ``os.getenv`` and ``os.environ[...]``."""
    spy = RecordingEnviron({"A": "1"})
    monkeypatch.setattr(os, "environ", spy)
    assert os.getenv("A") == "1" and os.environ["A"] == "1"
    assert [kind for kind, _ in spy.log] == ["getitem", "getitem"]


def test_the_recording_mapping_can_see_every_kind_of_read() -> None:
    env = Recording({"A": "1"})
    _ = env["A"], "A" in env, env.get("A"), list(env), len(env), list(env.items())
    assert {kind for kind, _ in env.log} >= {"getitem", "contains", "get", "iter", "len", "items"}


def write_catalog(root: Path) -> None:
    """A ``messages`` catalog for the language ``xx`` that translates the help headings."""
    messages = {"usage: ": "ZZUSAGE: ", "options": "ZZOPTIONS", "positional arguments": "ZZPOS"}
    keys = sorted(messages)
    ids = b"".join(k.encode() + b"\0" for k in keys)
    strings = b"".join(messages[k].encode() + b"\0" for k in keys)
    count = len(keys)
    key_start = 28 + 16 * count
    value_start = key_start + len(ids)
    header = struct.pack("Iiiiiii", 0x950412DE, 0, count, 28, 28 + 8 * count, 0, 0)
    table = b""
    position = 0
    for k in keys:
        table += struct.pack("ii", len(k.encode()), key_start + position)
        position += len(k.encode()) + 1
    position = 0
    for k in keys:
        table += struct.pack("ii", len(messages[k].encode()), value_start + position)
        position += len(messages[k].encode()) + 1
    target = root / "xx" / "LC_MESSAGES"
    target.mkdir(parents=True)
    (target / "messages.mo").write_bytes(header + table + ids + strings)


def test_an_installed_catalog_and_the_locale_variables_cannot_change_the_help_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_catalog(tmp_path / "locale")
    monkeypatch.setattr(gettext, "_localedirs", dict(gettext._localedirs))  # pyright: ignore
    gettext.bindtextdomain("messages", str(tmp_path / "locale"))
    for name in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(name, raising=False)
    assert gettext.gettext("positional arguments") == "positional arguments"  # no language yet

    def help_text(label: str) -> bytes:
        home = tmp_path / label
        home.mkdir(mode=0o700)
        out = io.BytesIO()
        try:
            cli.main(
                ["send", "--help"],
                {},
                FakeGateway(home=str(home)),
                cli.Streams(out, io.BytesIO(), lambda: False),
            )
        except BaseException:  # the help action ends the run
            pass
        return out.getvalue()

    plain = help_text("plain")
    monkeypatch.setenv("LANGUAGE", "xx")
    monkeypatch.setenv("LC_ALL", "xx")
    monkeypatch.setenv("LANG", "xx")
    assert gettext.gettext("positional arguments") == "ZZPOS"  # the catalog really is active
    assert plain.startswith(b"usage: ") and b"ZZ" not in plain
    assert help_text("noisy") == plain


def test_argparse_is_left_translated_outside_a_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    """The untranslated texts apply only while ``cli.parse`` runs, never at import time."""
    import argparse

    seen: list[object] = []
    for argv in (["send", "--help"], ["send", "--bogus"], ["validate"], ["--version"]):
        try:
            cli.parse(argv)
        except BaseException as end:
            seen.append(type(end))
        assert argparse._ is gettext.gettext  # pyright: ignore
        assert argparse.ngettext is gettext.ngettext  # pyright: ignore
    assert len(seen) == 3  # help, error and version end the parse; "validate" returns
