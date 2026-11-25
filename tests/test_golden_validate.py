"""Golden files for `validate` (#31, #32): every ``--json`` document and human line, as raw bytes.

For scenario ``name`` the files under ``tests/golden/validate/`` are, when non-empty,
``name.stdout`` and ``name.stderr``. They were written by hand from docs/interface.md (validate,
Output) and schemas/cli/validate.json, never generated from the code. Plain validate opens no state
directory, so there is no log or body file; `--test-message` does send, but its log and lock are
checked in test_validate_test_message.py, not here. The leak and path sweeps of
tests/test_golden_send.py cover this directory too (they walk every golden file).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from slack_notice import cli
from tests.fake_gateway import Attempt, FakeGateway, Reply
from tests.harness import assert_valid
from tests.send_harness import ENV, go, write_config
from tests.test_golden_send import compare

DIR = Path(__file__).resolve().parent / "golden" / "validate"
SUFFIXES = (".stdout", ".stderr")


@dataclass
class Scenario:
    name: str
    exit: int
    argv: list[str] = field(default_factory=lambda: ["validate", "--json"])
    config: str | None = None
    env: dict[str, str] | None = None  # None: the fake webhook environment
    attempts: list[Attempt] = field(default_factory=list)  # the scripted answers of a send


TM = ["validate", "--json", "--test-message"]
SERVER_ERROR = Attempt(reply=Reply(status=500, body=b"{}"))
UNSET: dict[str, str] = {}
WRONG = {"SLACK_WEBHOOK": "https://example.invalid/not-a-trigger"}
SCENARIOS = [
    Scenario("ok", 0),
    Scenario("ok_human", 0, ["validate"]),
    Scenario("ok_disabled", 0, config="enabled: false\n"),
    Scenario("ok_disabled_human", 0, ["validate"], config="enabled: false\n"),
    Scenario("credential_unset", 12, env=UNSET),
    Scenario("credential_wrong_shape_human", 12, ["validate"], env=WRONG),
    Scenario("credential_disabled_broken", 12, config="enabled: false\n", env=UNSET),
    Scenario("config_invalid", 2, config="max_chars: 5\n"),
    Scenario("config_invalid_human", 2, ["validate"], config="max_chars: 5\n"),
    Scenario("usage_unknown_flag", 2, ["validate", "--json", "--bogus"]),
    Scenario("test_message_ok", 0, TM, attempts=[Attempt()]),
    Scenario("test_message_ok_human", 0, ["validate", "--test-message"], attempts=[Attempt()]),
    Scenario("test_message_failed", 12, TM, attempts=[SERVER_ERROR]),
    Scenario(
        "test_message_failed_human", 12, ["validate", "--test-message"], attempts=[SERVER_ERROR]
    ),
    Scenario("test_message_credential_unset", 12, TM, env=UNSET),
    Scenario("test_message_disabled", 22, TM, config="enabled: false\n", env=UNSET),
    Scenario(
        "test_message_disabled_human",
        22,
        ["validate", "--test-message"],
        config="enabled: false\n",
        env=UNSET,
    ),
]
NAMES = [s.name for s in SCENARIOS]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=NAMES)
def test_golden_validate_outputs(
    scenario: Scenario, fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "__version__", "1.2.3")
    config = None if scenario.config is None else write_config(tmp_path, scenario.config)
    env = ENV if scenario.env is None else scenario.env
    fake_gateway.script(*scenario.attempts)
    sent = go(scenario.argv, fake_gateway, config=config, env=env)
    assert sent.code == scenario.exit, (sent.stdout, sent.stderr)
    assert len(fake_gateway.connections) == len(scenario.attempts)
    # only a real send of the test message opens the state directory (lock and log)
    assert bool(sent.state_files) == bool(scenario.attempts)
    compare(DIR / f"{scenario.name}.stdout", sent.out)
    compare(DIR / f"{scenario.name}.stderr", sent.err)


@pytest.mark.parametrize("name", NAMES)
def test_golden_validate_files_match_the_schemas(name: str) -> None:
    stdout = DIR / f"{name}.stdout"
    if stdout.exists():
        document = json.loads(stdout.read_bytes())
        assert_valid("cli/error" if "error" in document else "cli/validate", stdout.read_bytes())


def test_every_golden_file_belongs_to_a_scenario_and_none_is_empty() -> None:
    files = sorted(DIR.iterdir())
    assert {p.stem for p in files} == set(NAMES)
    for path in files:
        assert path.suffix in SUFFIXES and path.stat().st_size > 0, path
    for name in NAMES:
        assert (DIR / f"{name}.stdout").exists() or (DIR / f"{name}.stderr").exists()


def test_the_goldens_cover_every_check_outcome() -> None:
    documents = [
        json.loads(p.read_bytes()) for p in DIR.glob("*.stdout") if "checks" in p.read_text()
    ]
    shapes = {(d["ok"], d["enabled"], len(d["checks"])) for d in documents}
    assert shapes == {
        (True, True, 2),
        (True, False, 2),
        (False, True, 2),
        (False, False, 2),
        (True, True, 3),
        (False, True, 3),
    }
    assert {s.exit for s in SCENARIOS} == {0, 2, 12, 22}
