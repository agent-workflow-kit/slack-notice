"""Issue #82: the statements that docs/interface.md makes about behavior the code already has."""

from __future__ import annotations

import json

from tests.harness import ROOT

INTERFACE = (ROOT / "docs" / "interface.md").read_text(encoding="utf-8")
GOLDEN = ROOT / "tests" / "golden" / "send"


def test_retries_paragraph_says_as_long_as_or_longer_than_the_time_that_remains() -> None:
    wording = "as long as or longer than the time that remains to the deadline ends the send"
    assert wording in INTERFACE
    assert "longer than the time left" not in INTERFACE
    assert "counts as longer" not in INTERFACE


def test_closed_standard_descriptors_are_documented_as_reopened() -> None:
    # The behavior itself is pinned by test_send_bounds.py::test_reserve_std_fds_reopens_*.
    assert "`reserve_std_fds` in gateway.py reopens each of the descriptors 0, 1 and 2" in INTERFACE
    assert "never changes the exit code" in INTERFACE


def test_details_key_order_stated_in_the_interface_is_the_order_the_goldens_pin() -> None:
    order = "host_error before http_status (host_rejected), tls before timeout (network_error)"
    assert order in INTERFACE
    assert "must not rely on the order of keys" in INTERFACE
    orders = {
        "host_rejected.stdout": ["host_error", "http_status"],
        "network_error.stdout": ["tls", "timeout"],
    }
    for name, keys in orders.items():
        envelope = json.loads((GOLDEN / name).read_text(encoding="utf-8"))
        assert list(envelope["error"]["details"]) == keys
