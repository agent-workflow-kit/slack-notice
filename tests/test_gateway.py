from __future__ import annotations

import ast
import http.client
import os
import signal
import socket
import ssl
import stat
import threading
import time
from pathlib import Path

import pytest

from slack_notice import gateway as gw_module
from slack_notice.gateway import (
    CaCandidates,
    Gateway,
    HomeLookupError,
    NotRegularFile,
    NoUsableCA,
    SourceRead,
    StateUnusable,
    SystemGateway,
    build_tls_context,
    is_cert_verification_error,
    is_malformed_response,
    is_timeout,
    is_tls_error,
)
from tests.conftest import NetworkRefused

SRC = Path(__file__).resolve().parent.parent / "src" / "slack_notice"

# A public root CA certificate (ISRG Root X1), used only as a loadable CA fixture.
ROOT_CA_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""

# A certificate that is not a CA (a bundle of it loads but adds no CA).
GARBAGE_PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"


@pytest.fixture
def gateway() -> Gateway:
    return SystemGateway()


# --- import rule ----------------------------------------------------------------------------


BANNED_ROOTS = frozenset(
    {"urllib", "http", "time", "fcntl", "subprocess", "importlib", "posix", "nt"}
)
ENVIRONMENT_NAMES = frozenset({"environ", "environb", "getenv", "putenv"})
PROCESS_NAMES = frozenset({"system", "popen"})
PROCESS_PREFIXES = ("spawn", "exec", "fork", "posix_spawn")


def _banned_os_name(name: str) -> bool:
    return name in ENVIRONMENT_NAMES or name in PROCESS_NAMES or name.startswith(PROCESS_PREFIXES)


def banned_references(source: str) -> list[str]:
    """Banned modules, dynamic imports, environment access and process creation in the source.

    Roots in ``BANNED_ROOTS`` are banned whole, so an alias (``import http as h``) is caught at
    the import; ``__import__`` and any ``importlib`` use are banned. Names on the ``os`` module
    (environment: ``environ`` and friends; processes: ``system``, ``popen``, ``spawn*``,
    ``exec*``, ``fork*``, ``posix_spawn*``) are caught by attribute, by ``from os import x``
    and by ``getattr(os, "x")``, but only when the base is the ``os`` module (tracked through
    ``import os`` and ``import os as x``), so ``self.environ`` is not flagged.
    """
    tree = ast.parse(source)
    os_aliases = {
        (a.asname or a.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for a in node.names
        if a.name == "os"
    }
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [
                a.name
                for a in node.names
                if a.name.split(".")[0] in BANNED_ROOTS and a.name != "importlib.metadata"
            ]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if base.split(".")[0] in BANNED_ROOTS and not (
                # Reading the installed version is a static, harmless use of importlib.
                base == "importlib.metadata"
                or (base == "importlib" and all(a.name == "metadata" for a in node.names))
            ):
                found.append(base)
            if base == "os" and node.level == 0:
                found += [
                    f"os.{a.name}" for a in node.names if a.name == "*" or _banned_os_name(a.name)
                ]
        elif isinstance(node, ast.Name) and node.id == "__import__":
            found.append("__import__")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and _banned_os_name(node.attr)
        ):
            found.append(f"os.{node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "__getattribute__")
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in os_aliases
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and _banned_os_name(node.args[1].value)
        ):
            found.append(f"os.{node.args[1].value}")
    return found


@pytest.mark.parametrize(
    "source",
    [
        "import urllib",
        "import urllib.request",
        "import urllib as u\nu.request",
        "from urllib import request",
        "from urllib.parse import quote",
        "from urllib import *",
        "import http.client",
        "import http as h\nh.client.HTTPSConnection",
        "from http.client import HTTPSConnection",
        "from http import client",
        "from http import *",
        "import http\nhttp.client.HTTPSConnection",
        "import time",
        "import time as t",
        "from time import monotonic",
        "from time import *",
        "import fcntl",
        "import posix",
        "import posix as p\np.environ",
        "from posix import environ",
        "import nt",
        "from nt import environ",
        "from fcntl import flock",
        "import subprocess",
        "import subprocess as sp",
        "from subprocess import run",
        "from subprocess import *",
        "__import__('time')",
        "__import__(name)",
        "f = __import__\nf('time')",
        "import importlib\nimportlib.import_module('fcntl')",
        "import importlib\nimportlib.import_module(name)",
        "from importlib import import_module as load\nload('time')",
        "import importlib.util",
        "import os\nos.environ['A']",
        "import os\nos.getenv('A')",
        "import os as o\no.environ",
        "from os import environ",
        "from os import environ as e",
        "from os import getenv",
        "import os\ngetattr(os, 'environ')",
        "import os as o\ngetattr(o, 'getenv')",
        "import os\nos.system('x')",
        "import os\nos.popen('x')",
        "import os\nos.spawnv(0, 'x', [])",
        "import os\nos.execvp('x', [])",
        "import os\nos.fork()",
        "import os\nos.forkpty()",
        "import os\nos.posix_spawn('x', [], {})",
        "import os as o\no.system('x')",
        "from os import system",
        "from os import fork as f",
        "from os import execv",
        "from os import *",
    ],
)
def test_import_checker_detects_banned_references(source: str) -> None:
    assert banned_references(source)


@pytest.mark.parametrize(
    "source",
    [
        "import os",
        "from importlib.metadata import version",
        "from importlib import metadata",
        "import datetime",
        "import ssl",
        "from os import path",
        "import os\nos.getcwd()",
        "class A:\n    def f(self):\n        return self.environ",
        "def f(ctx):\n    return ctx.getenv('A'), ctx.system, getattr(ctx, 'environ')",
        "import os\nclass A:\n    def f(self):\n        return self.environ",
    ],
)
def test_import_checker_accepts_other_references(source: str) -> None:
    assert banned_references(source) == []


@pytest.mark.parametrize("snippet", ["import subprocess", "import http.client", "import time"])
def test_import_checker_reads_files_the_way_the_scan_does(tmp_path: Path, snippet: str) -> None:
    path = tmp_path / "module.py"
    path.write_text(snippet)
    assert banned_references(path.read_text())


def test_only_the_gateway_references_network_clock_lock_or_process_modules() -> None:
    sources = sorted(SRC.rglob("*.py"))
    assert (SRC / "gateway.py") in sources
    offenders = {
        str(path.relative_to(SRC)): banned_references(path.read_text())
        for path in sources
        if path.name != "gateway.py"
    }
    assert {name: found for name, found in offenders.items() if found} == {}


# Outside the gateway only these `os` / `os.path` attributes are allowed (pure string helpers and
# the terminal check, `write` to the output descriptors); everything else (remove, rename,
# makedirs, walk, getcwd, expanduser, abspath, realpath, stat, ...) is filesystem or process-state
# access and belongs to the gateway.
OS_ALLOWED = frozenset({"path", "isatty", "write", "fspath", "fsencode", "fsdecode", "sep"})
OS_PATH_ALLOWED = frozenset({"join", "dirname", "basename", "isabs", "sep"})
BANNED_FS_MODULES = frozenset({"pathlib", "shutil", "glob", "tempfile", "fileinput"})
BANNED_OPENERS = frozenset({("io", "open"), ("codecs", "open")})


def filesystem_references(source: str) -> list[str]:
    """Direct filesystem access outside the gateway: builtin ``open(``, imports of pathlib,
    shutil, glob, tempfile and fileinput, ``io.open`` / ``codecs.open``, and any ``os`` /
    ``os.path`` attribute outside the allowlists above (tracked through ``import os`` /
    ``import os.path`` and aliases, and ``from os import x`` / ``from os.path import x``)."""
    tree = ast.parse(source)
    os_aliases = {
        (a.asname or a.name.split(".")[0])
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for a in node.names
        if a.name in ("os", "os.path") and (a.asname or a.name == "os" or a.name == "os.path")
    }
    # Names bound directly to the os.path module: ``import os.path as p``, ``from os import path``.
    path_aliases = {
        a.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for a in node.names
        if a.name == "os.path" and a.asname
    } | {
        (a.asname or a.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "os"
        for a in node.names
        if a.name == "path"
    }
    opener_modules = {
        (a.asname or a.name): a.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for a in node.names
        if a.name in ("io", "codecs")
    }
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [
                f"import {a.name}" for a in node.names if a.name.split(".")[0] in BANNED_FS_MODULES
            ]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            module = node.module or ""
            if module.split(".")[0] in BANNED_FS_MODULES:
                found.append(f"from {module} import ...")
            elif module == "os":
                found += [f"os.{a.name}" for a in node.names if a.name not in OS_ALLOWED]
            elif module == "os.path":
                found += [f"os.path.{a.name}" for a in node.names if a.name not in OS_PATH_ALLOWED]
            elif module in ("io", "codecs"):
                found += [
                    f"{module}.open" for a in node.names if (module, a.name) in BANNED_OPENERS
                ]
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                found.append("open")
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in path_aliases:
                if node.attr not in OS_PATH_ALLOWED:
                    found.append(f"os.path.{node.attr}")
            elif isinstance(base, ast.Name) and base.id in os_aliases:
                if node.attr not in OS_ALLOWED:
                    found.append(f"os.{node.attr}")
            elif (
                isinstance(base, ast.Attribute)
                and base.attr == "path"
                and isinstance(base.value, ast.Name)
                and base.value.id in os_aliases
                and node.attr not in OS_PATH_ALLOWED
            ):
                found.append(f"os.path.{node.attr}")
            elif (
                isinstance(base, ast.Name)
                and base.id in opener_modules
                and (opener_modules[base.id], node.attr) in BANNED_OPENERS
            ):
                found.append(f"{opener_modules[base.id]}.{node.attr}")
    return found


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.path.isdir('x')",
        "import os as o\no.path.exists('x')",
        "import os\nos.stat('x')",
        "import os\nos.open('x', 0)",
        "from os import stat",
        "from os.path import isfile",
        "import os.path as p\np.isdir('x')",
        "from os import path\npath.isdir('x')",
        "from os import path as q\nq.exists('x')",
        "import pathlib",
        "import pathlib as pl",
        "from pathlib import Path",
        "import pathlib\npathlib.Path('x').is_dir()",
        "open('x')",
        "import shutil",
        "from shutil import rmtree",
        "import glob",
        "import tempfile",
        "from tempfile import mkstemp",
        "import fileinput",
        "import io\nio.open('x')",
        "import io as i\ni.open('x')",
        "import codecs\ncodecs.open('x')",
        "from io import open",
        "import os\nos.fdopen(3)",
        "import os\nos.remove('x')",
        "import os\nos.unlink('x')",
        "import os\nos.rename('a', 'b')",
        "import os\nos.makedirs('x')",
        "import os\nos.chmod('x', 0)",
        "import os\nos.walk('x')",
        "import os\nos.getcwd()",
        "import os\nos.path.expanduser('~')",
        "import os\nos.path.abspath('x')",
        "import os\nos.path.realpath('x')",
        "from os import getcwd",
        "from os.path import realpath",
        "import os.path as p\np.abspath('x')",
    ],
)
def test_filesystem_checker_detects_probes(source: str) -> None:
    assert filesystem_references(source)


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.path.join('a', 'b')",
        "import os\nos.path.isabs('/x')",
        "class A:\n    def f(self):\n        return self.stat",
        "def f(g):\n    return g.is_directory('x')",
        "import os.path as p\np.join('a', 'b')",
        "from os import path\npath.join('a', 'b')",
        "def f(x):\n    return x.open('y')",
        "def open(x):\n    return x\n",
        "import pathlib_like",
        "import os\nos.isatty(0)",
        "import os\nos.path.dirname('a/b')",
        "from os.path import join, dirname",
        "import io\nio.StringIO()",
    ],
)
def test_filesystem_checker_accepts_other_references(source: str) -> None:
    assert filesystem_references(source) == []


def test_only_the_gateway_probes_the_filesystem() -> None:
    offenders = {
        str(path.relative_to(SRC)): filesystem_references(path.read_text())
        for path in sorted(SRC.rglob("*.py"))
        if path.name != "gateway.py"
    }
    assert {name: found for name, found in offenders.items() if found} == {}


ENV_MAPPING_NAMES = frozenset({"env", "environ", "environment"})
ENV_READ_METHODS = frozenset({"get", "pop", "setdefault"})


def _is_env_mapping(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in ENV_MAPPING_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in ENV_MAPPING_NAMES
    return False


def _is_str_literal(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def literal_env_keys(source: str) -> list[str]:
    """Reads of an environment mapping (``env``, ``environ``, ``environment``, or an attribute of
    that name) with a string-literal key: ``env["X"]``, ``env.get("X")`` and the like. The
    credential's name comes from the config (``webhook_env``), never from the code."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Subscript) and _is_env_mapping(node.value):
            if _is_str_literal(node.slice):
                found.append(ast.unparse(node))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ENV_READ_METHODS
            and _is_env_mapping(node.func.value)
            and node.args
            and _is_str_literal(node.args[0])
        ):
            found.append(ast.unparse(node))
    return found


@pytest.mark.parametrize(
    "source",
    [
        "env['SLACK_WEBHOOK']",
        "ctx.env['SLACK_WEBHOOK']",
        "env.get('SLACK_WEBHOOK')",
        "self.env.get('X', '')",
        "environ.pop('X')",
        "environment.setdefault('X', 'y')",
    ],
)
def test_literal_env_key_checker_detects_reads(source: str) -> None:
    assert literal_env_keys(source)


@pytest.mark.parametrize(
    "source",
    [
        "env[name]",
        "ctx.env.get(config.webhook_env)",
        "env.get(name, 'default')",
        "other['X']",
        "settings.get('X')",
        "env == {}",
    ],
)
def test_literal_env_key_checker_accepts_other_code(source: str) -> None:
    assert literal_env_keys(source) == []


def test_no_module_reads_an_environment_mapping_with_a_literal_key() -> None:
    offenders = {
        str(path.relative_to(SRC)): literal_env_keys(path.read_text())
        for path in sorted(SRC.rglob("*.py"))
    }
    assert {name: found for name, found in offenders.items() if found} == {}


def environ_call_sites(source: str) -> list[str]:
    """The enclosing function of every ``<expr>.environ(...)`` call (``<module>`` at top level)."""
    tree = ast.parse(source)
    sites: list[str] = []

    def visit(node: ast.AST, scope: str) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            scope = node.name
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "environ"
        ):
            sites.append(scope)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, "<module>")
    return sites


def test_environ_call_checker_reports_the_enclosing_function() -> None:
    source = "def main(g):\n    return g.environ()\n\nx = g.environ()\n"
    assert environ_call_sites(source) == ["main", "<module>"]
    assert environ_call_sites("def f(g):\n    return g.environ\n") == []


def test_the_gateway_environment_is_read_only_by_the_lazy_env_of_cli_main() -> None:
    """``_LazyEnv._load`` is the one site: ``main`` hands it out and a dry run never loads it."""
    sites = {
        str(path.relative_to(SRC)): environ_call_sites(path.read_text())
        for path in sorted(SRC.rglob("*.py"))
    }
    assert {name: found for name, found in sites.items() if found} == {"cli.py": ["_load"]}


def test_gateway_itself_is_scanned_and_uses_the_modules() -> None:
    assert set(banned_references((SRC / "gateway.py").read_text())) >= {
        "time",
        "fcntl",
        "http.client",
    }


def test_gateway_has_no_subprocess_or_dynamic_imports() -> None:
    found = banned_references((SRC / "gateway.py").read_text())
    assert not {name for name in found if name.split(".")[0] in {"subprocess", "importlib"}}
    assert "__import__" not in found
    assert not hasattr(gw_module, "run")


def test_gateway_never_touches_the_environment_except_to_hand_it_to_the_cli() -> None:
    found = banned_references((SRC / "gateway.py").read_text())
    # Exactly one reference: `environ()` returns a copy; nothing in the gateway consults it.
    assert [name for name in found if name.startswith("os.")] == ["os.environ"]
    assert dict(gateway_environ_copy()) == dict(os.environ)


def gateway_environ_copy() -> dict[str, str]:
    return SystemGateway().environ()


def test_gateway_matches_the_protocol(gateway: Gateway) -> None:
    assert isinstance(gateway, SystemGateway)


# --- home directory and uid -----------------------------------------------------------------


def test_home_dir_comes_from_the_password_database_not_home(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "somewhere-else"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "other"))
    assert gateway.home_dir() == str(tmp_path / "home")
    assert gateway.home_dir() != os.environ["HOME"]


def test_home_dir_lookup_failure_is_a_fixed_error(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(_uid: int) -> None:
        raise KeyError("getpwuid(): uid not found: 4242 /secret")

    monkeypatch.setattr("pwd.getpwuid", missing)
    with pytest.raises(HomeLookupError) as info:
        gateway.home_dir()
    assert "secret" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__
    assert gateway.login_name() is None


@pytest.mark.parametrize("exc", [RuntimeError("boom /secret"), TypeError("x"), OverflowError("y")])
def test_home_dir_any_lookup_exception_is_the_fixed_error(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    def broken(_uid: int) -> None:
        raise exc

    monkeypatch.setattr("pwd.getpwuid", broken)
    with pytest.raises(HomeLookupError) as info:
        gateway.home_dir()
    assert "secret" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_is_directory(gateway: Gateway, tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    (tmp_path / "file").write_text("x")
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    (tmp_path / "linkdir").symlink_to(tmp_path / "dir")
    assert gateway.is_directory(str(tmp_path / "dir"))
    assert gateway.is_directory(str(tmp_path / "linkdir"))
    assert not gateway.is_directory(str(tmp_path / "file"))
    assert not gateway.is_directory(str(tmp_path / "missing"))
    assert not gateway.is_directory(str(tmp_path / "dangling"))
    assert not gateway.is_directory(f"{tmp_path}\x00/dir")
    assert not gateway.is_directory(str(tmp_path) + "/" + "a" * 100_000)
    assert not gateway.is_directory("/tmp\ud800")


def test_uid_and_login_name(gateway: Gateway) -> None:
    assert gateway.uid() == os.getuid()
    assert gateway.login_name()


# --- clock and names ------------------------------------------------------------------------


def test_clocks(gateway: Gateway) -> None:
    first = gateway.monotonic()
    gateway.sleep(0.01)
    gateway.sleep(-1)
    assert gateway.monotonic() > first
    assert abs(gateway.wall_time() - time.time()) < 5


def test_name_resolution_goes_through_the_guarded_resolver(gateway: Gateway) -> None:
    with pytest.raises(NetworkRefused):
        gateway.resolve("example.invalid", 443)


# --- read_source ----------------------------------------------------------------------------


def test_read_source_times_out_when_no_byte_arrives(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    try:
        start = time.monotonic()
        result = gateway.read_source(read_end, 100, 0.25)
        elapsed = time.monotonic() - start
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result == SourceRead(b"", timed_out=True)
    assert 0.2 <= elapsed < 1.0


def test_read_source_waits_in_slices_of_at_most_100_ms(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[float] = []
    real_poll = gw_module.select.poll

    class Recording:
        def __init__(self) -> None:
            self._poller = real_poll()

        def register(self, fd: int, events: int) -> None:
            self._poller.register(fd, events)

        def poll(self, timeout_ms: float) -> list[tuple[int, int]]:
            waits.append(timeout_ms)
            return self._poller.poll(timeout_ms)

    monkeypatch.setattr(gw_module.select, "poll", Recording)
    read_end, write_end = os.pipe()
    try:
        assert gateway.read_source(read_end, 10, 0.35).timed_out
    finally:
        os.close(read_end)
        os.close(write_end)
    assert len(waits) >= 3
    assert all(0 < wait <= 100 for wait in waits)


@pytest.mark.parametrize("remaining", [0.0, -5.0])
def test_read_source_with_no_time_left_times_out_at_once(
    gateway: Gateway, remaining: float
) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b"data")
    os.close(write_end)
    try:
        assert gateway.read_source(read_end, 100, remaining).timed_out
    finally:
        os.close(read_end)


def test_read_source_returns_bytes_at_end_of_input_and_leaves_the_fd_open(
    gateway: Gateway,
) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, "héllo \U0001f600".encode())
    os.close(write_end)
    try:
        result = gateway.read_source(read_end, 100, 5)
        assert result == SourceRead("héllo \U0001f600".encode())
        assert os.fstat(read_end)  # still open
    finally:
        os.close(read_end)


def test_read_source_empty_input(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    os.close(write_end)
    try:
        assert gateway.read_source(read_end, 100, 5) == SourceRead(b"")
    finally:
        os.close(read_end)


def test_source_read_repr_does_not_show_the_text() -> None:
    assert "secret-text" not in repr(SourceRead(b"secret-text"))


def test_read_source_nan_remaining_times_out_at_once(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    try:
        start = time.monotonic()
        assert gateway.read_source(read_end, 100, float("nan")).timed_out
        assert time.monotonic() - start < 0.5
    finally:
        os.close(read_end)
        os.close(write_end)


def test_read_source_closed_descriptor_is_empty_input(gateway: Gateway) -> None:
    fd = os.open(os.devnull, os.O_RDONLY)
    os.close(fd)
    assert gateway.read_source(fd, 100, 1) == SourceRead(b"")


def test_read_source_negative_descriptor_is_empty_input(gateway: Gateway) -> None:
    assert gateway.read_source(-1, 100, 1) == SourceRead(b"")


def test_read_source_write_only_descriptor_is_empty_input(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    try:
        assert gateway.read_source(write_end, 100, 1) == SourceRead(b"")
    finally:
        os.close(read_end)
        os.close(write_end)


def test_read_source_directory_descriptor_is_empty_input(gateway: Gateway, tmp_path: Path) -> None:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert gateway.read_source(fd, 100, 1) == SourceRead(b"")
    finally:
        os.close(fd)


def test_read_source_directory_path_is_not_a_regular_file(gateway: Gateway, tmp_path: Path) -> None:
    with pytest.raises(NotRegularFile):
        gateway.read_source(tmp_path, 100, 1)


def test_read_source_stalled_read_is_interrupted_by_a_raising_signal_handler(
    gateway: Gateway,
) -> None:
    class Stop(Exception):  # noqa: N818
        pass

    def handler(_signum: int, _frame: object) -> None:
        raise Stop

    read_end, write_end = os.pipe()
    previous = signal.signal(signal.SIGALRM, handler)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.15)
        start = time.monotonic()
        with pytest.raises(Stop):
            gateway.read_source(read_end, 100, 30)
        assert time.monotonic() - start < 1.0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        os.close(read_end)
        os.close(write_end)


def test_read_source_data_after_several_slices_then_end_is_not_timed_out(
    gateway: Gateway,
) -> None:
    read_end, write_end = os.pipe()

    def late_writer() -> None:
        time.sleep(0.35)  # more than three 100 ms slices
        os.write(write_end, b"late")
        os.close(write_end)

    thread = threading.Thread(target=late_writer)
    thread.start()
    try:
        assert gateway.read_source(read_end, 100, 5) == SourceRead(b"late")
    finally:
        thread.join()
        os.close(read_end)


def test_read_source_partial_input_then_stall_is_timed_out(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b"abc")
    try:
        result = gateway.read_source(read_end, 100, 0.25)
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result.timed_out
    assert result.data == b"abc"


@pytest.mark.parametrize(("size", "too_large"), [(99, False), (100, False), (101, True)])
def test_read_source_size_boundary(
    gateway: Gateway, tmp_path: Path, size: int, too_large: bool
) -> None:
    path = tmp_path / "in.json"
    path.write_bytes(b"x" * size)
    result = gateway.read_source(path, 100, 5)
    assert result.too_large is too_large
    assert len(result.data) == min(size, 100)
    assert not result.timed_out


def test_read_source_large_pipe_overflow_stops_reading(gateway: Gateway) -> None:
    read_end, write_end = os.pipe()
    os.set_blocking(write_end, False)
    try:
        os.write(write_end, b"y" * 50_000)
        result = gateway.read_source(read_end, 1000, 5)
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result.too_large
    assert result.data == b"y" * 1000


def test_read_source_regular_file_is_read_in_64k_chunks_with_deadline_checks(
    gateway: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big"
    path.write_bytes(b"z" * (3 * 65536))
    reads: list[int] = []
    real_read = os.read

    def counting_read(fd: int, size: int) -> bytes:
        reads.append(size)
        return real_read(fd, size)

    monkeypatch.setattr(gw_module.os, "read", counting_read)
    result = gateway.read_source(str(path), 10**9, 5)
    assert len(result.data) == 3 * 65536
    assert max(reads) == 65536


def test_read_source_deadline_is_checked_between_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big"
    path.write_bytes(b"z" * (3 * 65536))
    calls = 0

    def clock() -> float:
        nonlocal calls
        calls += 1
        return 0.0 if calls <= 3 else 10.0  # the deadline passes after the first chunks

    sg = SystemGateway()
    monkeypatch.setattr(sg, "monotonic", clock)
    result = sg.read_source(path, 10**9, 1.0)
    assert result.timed_out
    assert len(result.data) < 3 * 65536


def test_read_source_path_missing(gateway: Gateway, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        gateway.read_source(tmp_path / "nope", 10, 1)


def test_read_source_fifo_path_is_refused_without_blocking(
    gateway: Gateway, tmp_path: Path
) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(NotRegularFile):
        gateway.read_source(fifo, 10, 1)


def test_read_source_path_closes_its_descriptor(gateway: Gateway, tmp_path: Path) -> None:
    path = tmp_path / "in"
    path.write_bytes(b"{}")
    before = set(os.listdir("/proc/self/fd"))
    gateway.read_source(path, 10, 1)
    assert set(os.listdir("/proc/self/fd")) == before


def test_read_regular_file_limits(gateway: Gateway, tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(b"a" * 65536)
    assert len(gateway.read_regular_file(path, 65536)) == 65536
    path.write_bytes(b"a" * 65537)
    with pytest.raises(ValueError):
        gateway.read_regular_file(path, 65536)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(NotRegularFile):
        gateway.read_regular_file(fifo, 10)
    link = tmp_path / "link"
    link.symlink_to(path)
    path.write_bytes(b"ok")
    assert gateway.read_regular_file(link, 10) == b"ok"


def test_list_directory_returns_names_and_follows_a_link(gateway: Gateway, tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.yaml").write_text("x")
    (tmp_path / "d" / "a.yaml").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "d")
    assert sorted(gateway.list_directory(str(tmp_path / "d"))) == ["a.yaml", "b.yaml"]
    assert sorted(gateway.list_directory(str(tmp_path / "link"))) == ["a.yaml", "b.yaml"]


def test_list_directory_failures_are_oserrors(gateway: Gateway, tmp_path: Path) -> None:
    (tmp_path / "f").write_text("x")
    with pytest.raises(FileNotFoundError):
        gateway.list_directory(str(tmp_path / "missing"))
    with pytest.raises(NotADirectoryError):
        gateway.list_directory(str(tmp_path / "f"))
    with pytest.raises(ValueError):
        gateway.list_directory("a\0b")


def test_absolute_path_keeps_an_absolute_path_as_it_is(gateway: Gateway) -> None:
    assert gateway.absolute_path("/a/../b//c") == "/a/../b//c"


def test_absolute_path_joins_a_relative_path_to_the_working_directory(
    gateway: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert gateway.absolute_path("home") == f"{tmp_path}/home"
    assert gateway.absolute_path("--config") == f"{tmp_path}/--config"
    assert gateway.absolute_path("") == f"{tmp_path}/"


def test_absolute_path_without_a_working_directory_is_prefixed(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> str:
        raise FileNotFoundError

    monkeypatch.setattr(os, "getcwd", broken)
    assert gateway.absolute_path("home") == "./home"


# --- TLS ------------------------------------------------------------------------------------


def candidates(
    tmp_path: Path,
    *,
    cafile: str | None = None,
    capath: str | None = None,
    fallbacks: tuple[str, ...] = (),
) -> CaCandidates:
    return CaCandidates(cafile, capath, fallbacks)


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    path = tmp_path / "bundle.pem"
    path.write_text(ROOT_CA_PEM)
    return path


def test_context_verifies_by_default(bundle: Path, tmp_path: Path) -> None:
    context = build_tls_context(candidates(tmp_path, cafile=str(bundle)))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.cert_store_stats()["x509_ca"] == 1


def test_compiled_cafile_and_capath_are_both_used(bundle: Path, tmp_path: Path) -> None:
    capath = tmp_path / "certs"
    capath.mkdir()
    context = build_tls_context(candidates(tmp_path, cafile=str(bundle), capath=str(capath)))
    assert context.cert_store_stats()["x509_ca"] == 1


def test_capath_directory_alone_is_used_unchecked(tmp_path: Path, bundle: Path) -> None:
    capath = tmp_path / "certs"
    capath.mkdir()
    context = build_tls_context(
        candidates(
            tmp_path, cafile=str(tmp_path / "missing"), capath=str(capath), fallbacks=(str(bundle),)
        )
    )
    # The directory counts as usable, so the fallback bundle is not consulted.
    assert context.cert_store_stats()["x509_ca"] == 0


def test_unusable_default_falls_back_to_first_usable_bundle(tmp_path: Path, bundle: Path) -> None:
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    garbage = tmp_path / "garbage.pem"
    garbage.write_text(GARBAGE_PEM)
    directory = tmp_path / "dir"
    directory.mkdir()
    context = build_tls_context(
        candidates(
            tmp_path,
            cafile=str(empty),
            capath=str(tmp_path / "not-a-dir"),
            fallbacks=(
                str(tmp_path / "missing"),
                str(directory),
                str(empty),
                str(garbage),
                str(bundle),
            ),
        )
    )
    assert context.cert_store_stats()["x509_ca"] == 1


def test_no_usable_certificates_is_no_usable_ca(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    with pytest.raises(NoUsableCA) as info:
        build_tls_context(candidates(tmp_path, cafile=str(empty), fallbacks=(str(empty),)))
    assert "no usable CA certificates" in str(info.value)
    assert is_tls_error(info.value)


def test_sslkeylogfile_is_ignored(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    context = build_tls_context(candidates(tmp_path, cafile=str(bundle)))
    assert context.keylog_filename is None


def test_default_candidates_are_the_compiled_paths(gateway: Gateway) -> None:
    found = gateway.ca_candidates()
    compiled = ssl.get_default_verify_paths()
    assert found.cafile == (compiled.openssl_cafile or None)
    assert found.capath == (compiled.openssl_capath or None)
    assert found.fallback_files == (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    )


def test_ssl_cert_variables_are_not_read(
    tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    sg = SystemGateway()
    monkeypatch.setattr(
        sg, "ca_candidates", lambda: CaCandidates(str(tmp_path / "missing"), None, ())
    )
    with pytest.raises(NoUsableCA):
        sg.tls_context()
    # The real defaults never name the variables' values either.
    real = SystemGateway().ca_candidates()
    assert real.cafile != str(bundle)
    assert real.capath != str(tmp_path)


# --- HTTPS connection -----------------------------------------------------------------------


def make_connection(gateway: Gateway, tmp_path: Path, bundle: Path):  # noqa: ANN202
    context = build_tls_context(candidates(tmp_path, cafile=str(bundle)))
    return gateway.https_connection(
        "hooks.slack.com", 443, timeout=3.0, context=context, user_agent="slack-notice/9.9.9"
    )


def test_connection_construction_does_not_touch_the_network(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    make_connection(gateway, tmp_path, bundle)  # would raise NetworkRefused if it connected


def test_connect_resolves_through_the_guard(gateway: Gateway, tmp_path: Path, bundle: Path) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    with pytest.raises(NetworkRefused):
        connection.connect()


def test_proxy_variables_are_ignored(
    gateway: Gateway, tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    connection = make_connection(gateway, tmp_path, bundle)
    inner = connection._conn  # type: ignore[attr-defined]
    assert (inner.host, inner.port) == ("hooks.slack.com", 443)
    with pytest.raises(NetworkRefused) as info:  # the refused address is the target, not a proxy
        connection.connect()
    assert "proxy" not in str(info.value)


def test_post_sends_the_documented_headers(
    gateway: Gateway, tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    inner = connection._conn  # type: ignore[attr-defined]
    seen: dict[str, object] = {}

    def capture(method: str, url: str, body: bytes, headers: dict[str, str]) -> None:
        seen.update(method=method, url=url, body=body, headers=headers)

    monkeypatch.setattr(inner, "request", capture)
    connection.post("/triggers/T1/abc", b'{"text":"hi"}')
    assert seen["method"] == "POST"
    assert seen["url"] == "/triggers/T1/abc"
    assert seen["body"] == b'{"text":"hi"}'
    assert seen["headers"] == {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": "slack-notice/9.9.9",
    }


def test_post_wire_format_on_a_socketpair(gateway: Gateway, tmp_path: Path, bundle: Path) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    inner = connection._conn  # type: ignore[attr-defined]
    client, server = socket.socketpair()
    try:
        inner.sock = client
        connection.post("/triggers/T1/abc", b'{"text":"hi"}')
        server.settimeout(2)
        raw = server.recv(4096).decode()
    finally:
        client.close()
        server.close()
    lines = raw.split("\r\n")
    assert lines[0] == "POST /triggers/T1/abc HTTP/1.1"
    assert "Host: hooks.slack.com" in lines
    assert "Accept-Encoding: identity" in lines
    assert "Content-Length: 13" in lines
    assert sum(line.lower().startswith("accept-encoding") for line in lines) == 1


def test_post_with_an_invalid_target_fails_with_a_fixed_message(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    with pytest.raises(http.client.InvalidURL) as info:
        connection.post("/triggers/T1/SECRET TOKEN", b"{}")
    assert "SECRET" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None  # raised outside the handler: nothing is chained


def test_post_with_a_non_ascii_target_fails_with_a_fixed_message(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    with pytest.raises(http.client.InvalidURL) as info:
        connection.post("/triggers/T1/SECRET\u00e9TOKEN", b"{}")
    assert str(info.value) == "invalid request"
    for text in (str(info.value), repr(info.value)):
        assert "SECRET" not in text
        assert "/triggers" not in text
    assert info.value.__cause__ is None
    assert info.value.__context__ is None  # raised outside the handler: nothing is chained


def served_response(
    gateway: Gateway, tmp_path: Path, bundle: Path, raw: bytes, *, close_server: bool = False
):  # noqa: ANN202
    """A response read through the real connection class after a real ``post`` on a socketpair."""
    connection = make_connection(gateway, tmp_path, bundle)
    inner = connection._conn  # type: ignore[attr-defined]
    client, server = socket.socketpair()
    inner.sock = client
    connection.post("/triggers/T1/abc", b"{}")
    server.sendall(raw)
    if close_server:
        server.shutdown(socket.SHUT_WR)
    return connection, client, server


def test_response_exposes_only_status_and_read(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection, client, server = served_response(
        gateway,
        tmp_path,
        bundle,
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nLocation: https://x.invalid/\r\n"
        b"Content-Length: 11\r\n\r\n"
        b'{"ok":true}',
    )
    try:
        response = connection.getresponse()
        assert {name for name in dir(response) if not name.startswith("_")} == {"status", "read"}
        assert response.status == 429
        assert response.read(4) == b'{"ok'
        assert response.read(1024) == b'":true}'
        assert response.read(1024) == b""
    finally:
        client.close()
        server.close()


def test_truncated_content_length_body_is_incomplete_read(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection, client, server = served_response(
        gateway,
        tmp_path,
        bundle,
        b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok"',
        close_server=True,
    )
    try:
        response = connection.getresponse()
        assert response.status == 200
        with pytest.raises(http.client.IncompleteRead):
            while response.read(1024):
                pass
    finally:
        client.close()


def test_body_without_content_length_ends_normally(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection, client, server = served_response(
        gateway, tmp_path, bundle, b'HTTP/1.1 200 OK\r\n\r\n{"ok":true}', close_server=True
    )
    try:
        response = connection.getresponse()
        assert response.read(1024) == b'{"ok":true}'
        assert response.read(1024) == b""
    finally:
        client.close()


def test_settimeout_updates_connection_and_socket(
    gateway: Gateway, tmp_path: Path, bundle: Path
) -> None:
    connection = make_connection(gateway, tmp_path, bundle)
    inner = connection._conn  # type: ignore[attr-defined]
    client, server = socket.socketpair()
    try:
        inner.sock = client
        connection.settimeout(1.5)
        assert inner.timeout == 1.5
        assert client.gettimeout() == 1.5
    finally:
        connection.close()
        server.close()


# --- failure classification -----------------------------------------------------------------


def test_classification() -> None:
    assert is_timeout(TimeoutError())
    assert not is_timeout(OSError())
    assert is_tls_error(ssl.SSLError())
    assert is_tls_error(ssl.SSLCertVerificationError())
    assert not is_tls_error(OSError())
    assert is_cert_verification_error(ssl.SSLCertVerificationError())
    assert not is_cert_verification_error(ssl.SSLError())
    assert not is_cert_verification_error(OSError())
    assert is_malformed_response(http.client.BadStatusLine("x"))
    assert is_malformed_response(http.client.LineTooLong("status line"))
    assert is_malformed_response(http.client.UnknownProtocol("HTTP/9"))
    assert is_malformed_response(http.client.HTTPException())
    assert not is_malformed_response(http.client.RemoteDisconnected("gone"))
    assert not is_malformed_response(http.client.IncompleteRead(b"x"))
    assert not is_malformed_response(ConnectionResetError())
    assert not is_malformed_response(ValueError())


# --- state files ----------------------------------------------------------------------------


def test_state_dir_is_created_private(gateway: Gateway, tmp_path: Path) -> None:
    home = tmp_path / "home"
    fd = gateway.open_state_dir(str(home))
    try:
        info = os.fstat(fd)
        assert stat.S_ISDIR(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o700
    finally:
        os.close(fd)
    assert (home / ".local" / "state" / "slack-notice").is_dir()


def test_state_dir_reuses_an_existing_private_directory(gateway: Gateway, tmp_path: Path) -> None:
    fd1 = gateway.open_state_dir(str(tmp_path / "home"))
    fd2 = gateway.open_state_dir(str(tmp_path / "home"))
    os.close(fd1)
    os.close(fd2)


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o777, 0o770])
def test_state_dir_with_group_or_other_bits_is_unusable(
    gateway: Gateway, tmp_path: Path, mode: int
) -> None:
    leaf = tmp_path / "home" / ".local" / "state" / "slack-notice"
    leaf.mkdir(parents=True)
    leaf.chmod(mode)
    with pytest.raises(StateUnusable) as info:
        gateway.open_state_dir(str(tmp_path / "home"))
    assert info.value.reason == "mode"


def test_state_dir_that_is_a_symlink_is_unusable(gateway: Gateway, tmp_path: Path) -> None:
    state = tmp_path / "home" / ".local" / "state"
    state.mkdir(parents=True)
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    (state / "slack-notice").symlink_to(target)
    with pytest.raises(StateUnusable):
        gateway.open_state_dir(str(tmp_path / "home"))


def test_state_dir_wrong_owner_is_unusable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sg = SystemGateway()
    monkeypatch.setattr(sg, "uid", lambda: os.getuid() + 1)
    with pytest.raises(StateUnusable) as info:
        sg.open_state_dir(str(tmp_path / "home"))
    assert info.value.reason == "owner"


@pytest.mark.parametrize("home", ["", "relative/home", "a\0b"])
def test_state_dir_with_an_unusable_home_is_unusable(gateway: Gateway, home: str) -> None:
    with pytest.raises(StateUnusable) as info:
        gateway.open_state_dir(home)
    assert info.value.reason == "open"
    assert info.value.__cause__ is None


def test_state_dir_under_a_file_is_unusable(gateway: Gateway, tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    with pytest.raises(StateUnusable) as info:
        gateway.open_state_dir(str(blocker))
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


def test_state_file_flags_and_mode(gateway: Gateway, tmp_path: Path) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    try:
        fd = gateway.open_state_file(dir_fd, "log.jsonl", append=True)
        try:
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
            import fcntl as _fcntl  # test-only: inspect the open flags

            flags = _fcntl.fcntl(fd, _fcntl.F_GETFL)
            assert flags & os.O_APPEND
            assert flags & os.O_NONBLOCK
            assert _fcntl.fcntl(fd, _fcntl.F_GETFD) & _fcntl.FD_CLOEXEC
            os.write(fd, b"a\n")
            os.write(fd, b"b\n")
        finally:
            os.close(fd)
        lock_fd = gateway.open_state_file(dir_fd, "send.lock")
        try:
            assert not os.fstat(lock_fd).st_mode & 0o077
        finally:
            os.close(lock_fd)
    finally:
        os.close(dir_fd)
    leaf = tmp_path / "home" / ".local" / "state" / "slack-notice"
    assert (leaf / "log.jsonl").read_bytes() == b"a\nb\n"


def test_state_file_fifo_symlink_and_directory_are_unusable_not_blocking(
    gateway: Gateway, tmp_path: Path
) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    leaf = tmp_path / "home" / ".local" / "state" / "slack-notice"
    try:
        os.mkfifo(leaf / "fifo")
        with pytest.raises(StateUnusable) as info:
            gateway.open_state_file(dir_fd, "fifo")
        assert info.value.reason == "not_regular"
        (leaf / "target").write_text("x")
        (leaf / "link").symlink_to(leaf / "target")
        with pytest.raises(StateUnusable):
            gateway.open_state_file(dir_fd, "link")
        (leaf / "dir").mkdir()
        with pytest.raises(StateUnusable):
            gateway.open_state_file(dir_fd, "dir")
    finally:
        os.close(dir_fd)


@pytest.mark.parametrize("name", ["", ".", "..", "../x", "a/b", "/etc/passwd", "a\0b"])
def test_state_file_names_must_be_plain(gateway: Gateway, tmp_path: Path, name: str) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    try:
        with pytest.raises(ValueError):
            gateway.open_state_file(dir_fd, name)
    finally:
        os.close(dir_fd)


def test_lock_is_exclusive_and_released(gateway: Gateway, tmp_path: Path) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    first = gateway.open_state_file(dir_fd, "send.lock")
    second = gateway.open_state_file(dir_fd, "send.lock")
    try:
        assert gateway.try_lock(first) is True
        assert gateway.try_lock(second) is False
        gateway.unlock(first)
        assert gateway.try_lock(second) is True
        gateway.unlock(second)
    finally:
        for fd in (first, second, dir_fd):
            os.close(fd)


# --- state file primitives for the log (issue #14) ---------------------------------------------


def test_state_file_write_size_read_at_and_truncate(gateway: Gateway, tmp_path: Path) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    fd = gateway.open_state_file(dir_fd, "log.jsonl", append=True)
    try:
        assert gateway.file_size(fd) == 0
        assert gateway.write_fd(fd, b"abc\n") == 4
        assert gateway.file_size(fd) == 4
        assert gateway.read_at(fd, 1, 3) == b"\n"
        assert gateway.read_at(fd, 5, 100) == b""
        gateway.truncate_fd(fd, 2)
        assert gateway.file_size(fd) == 2
        assert gateway.write_fd(fd, b"Z") == 1  # O_APPEND: lands at the new end
        assert gateway.read_at(fd, 10, 0) == b"abZ"
    finally:
        os.close(fd)
        os.close(dir_fd)


def test_state_file_mtime_is_read_and_set_on_the_descriptor(
    gateway: Gateway, tmp_path: Path
) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    fd = gateway.open_state_file(dir_fd, "send.lock")
    try:
        gateway.set_mtime(fd, 1_700_000_000.5)
        assert gateway.file_mtime(fd) == pytest.approx(1_700_000_000.5, abs=1e-6)
        with pytest.raises(ValueError):
            gateway.set_mtime(fd, float("nan"))
        assert gateway.file_mtime(fd) == pytest.approx(1_700_000_000.5, abs=1e-6)
    finally:
        os.close(fd)
        os.close(dir_fd)


def test_rename_state_file_replaces_the_target_and_never_follows_links(
    gateway: Gateway, tmp_path: Path
) -> None:
    dir_fd = gateway.open_state_dir(str(tmp_path / "home"))
    leaf = tmp_path / "home" / ".local" / "state" / "slack-notice"
    outside = tmp_path / "outside"
    outside.write_text("keep")
    try:
        (leaf / "a").write_text("A")
        (leaf / "b").symlink_to(outside)
        gateway.rename_state_file(dir_fd, "a", "b")
        assert (leaf / "b").read_text() == "A"
        assert not (leaf / "b").is_symlink()
        assert outside.read_text() == "keep"
        with pytest.raises(FileNotFoundError):
            gateway.rename_state_file(dir_fd, "missing", "b")
        for bad in ("", "..", "x/y", "a\0b"):
            with pytest.raises(ValueError):
                gateway.rename_state_file(dir_fd, bad, "b")
            with pytest.raises(ValueError):
                gateway.rename_state_file(dir_fd, "b", bad)
    finally:
        os.close(dir_fd)
