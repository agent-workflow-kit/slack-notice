"""Schema harness shared by the tests.

`schema_errors(name, instance)` validates against `schemas/<name>.json` (JSON Schema draft
2020-12; cross-file `$ref`s resolve from the local files, never the network). `assert_valid`
is the helper for real tool output: it parses the text first, so a test passes the bytes the
tool printed (or wrote to log.jsonl) and not a hand-built object.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = ROOT / "schemas"


def schema_names() -> list[str]:
    """Every schema as a name relative to schemas/ without `.json` (`cli/send`, `defs`)."""
    return sorted(
        p.relative_to(SCHEMAS_DIR).with_suffix("").as_posix() for p in SCHEMAS_DIR.rglob("*.json")
    )


def schema_path(name: str) -> Path:
    path = (SCHEMAS_DIR / f"{name}.json").resolve()
    if not path.is_relative_to(SCHEMAS_DIR.resolve()):
        raise ValueError(f"schema name escapes schemas/: {name!r}")
    return path


def load_schema(name: str) -> dict[str, Any]:
    with schema_path(name).open(encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    resources = [
        (load_schema(n)["$id"], Resource.from_contents(load_schema(n))) for n in schema_names()
    ]
    return Registry().with_resources(resources)


def validator(name: str, definition: str | None = None) -> Draft202012Validator:
    """A validator for one schema, or for one entry of its `$defs` when `definition` is given.

    No format assertions: the schemas use patterns only (`format` is an annotation).
    """
    if definition is None:
        return Draft202012Validator(load_schema(name), registry=_registry())
    ref = {"$ref": f"{load_schema(name)['$id']}#/$defs/{definition}"}
    return Draft202012Validator(ref, registry=_registry())


def schema_errors(name: str, instance: Any, definition: str | None = None) -> list[ValidationError]:
    return list(validator(name, definition).iter_errors(instance))


def schema_error_pairs(
    name: str, instance: Any, definition: str | None = None
) -> set[tuple[tuple[str | int, ...], str]]:
    """Every (instance path, keyword) the schema reports, including inside oneOf/anyOf branches."""
    pairs: set[tuple[tuple[str | int, ...], str]] = set()

    def walk(errors: list[ValidationError]) -> None:
        for err in errors:
            pairs.add((tuple(err.absolute_path), str(err.validator)))
            walk(list(err.context or []))

    walk(schema_errors(name, instance, definition))
    return pairs


def assert_valid(name: str, output: str | bytes, definition: str | None = None) -> Any:
    """Parse real tool output as one JSON document and assert that it matches the schema.

    Returns the parsed document. Fails with every schema message when it does not match.
    """
    instance = json.loads(output)
    errors = schema_errors(name, instance, definition)
    assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors]
    return instance
