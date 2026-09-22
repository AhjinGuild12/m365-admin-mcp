"""Nested schema-driven projection (KTD17).

Replaces entra_mcp.fields.project (shallow) with an explicit nested allowlist.
``strip_keys`` is kept only as a defense-in-depth pass after projection.
Allowing a parent key never admits arbitrary children.
"""

from __future__ import annotations

from typing import Any

# A schema node is:
# - True: keep a non-container leaf; dict/list values are dropped (empty)
# - dict: object allowlist {field: nested_schema}
# - list of one schema: array of items projected with that schema
Schema = Any


def project_schema(obj: Any, schema: Schema) -> Any:
    """Project ``obj`` through ``schema``. Unknown and forbidden keys are absent."""
    if schema is True:
        if isinstance(obj, dict):
            return {}
        if isinstance(obj, list):
            return []
        return obj
    if isinstance(schema, list):
        item_schema: Schema = schema[0] if schema else True
        if not isinstance(obj, list):
            return []
        return [project_schema(item, item_schema) for item in obj]
    if isinstance(schema, dict):
        if not isinstance(obj, dict):
            return {}
        out: dict[str, Any] = {}
        for key, child_schema in schema.items():
            if key in obj:
                out[key] = project_schema(obj[key], child_schema)
        return out
    return None


def project(obj: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    """Flat object projection: each named field is a leaf (containers emptied)."""
    schema = {name: True for name in fields}
    projected = project_schema(obj, schema)
    return projected if isinstance(projected, dict) else {}


def project_list(items: Any, schema: Schema) -> list[Any]:
    if not items:
        return []
    if isinstance(schema, dict) or schema is True:
        return [project_schema(item, schema) for item in items]
    return project_schema(items, schema) if isinstance(schema, list) else []


def strip_keys(obj: Any, banned: frozenset[str]) -> Any:
    """Recursive denylist. Defense-in-depth after ``project_schema``."""
    if isinstance(obj, dict):
        return {k: strip_keys(v, banned) for k, v in obj.items() if k not in banned}
    if isinstance(obj, list):
        return [strip_keys(item, banned) for item in obj]
    return obj


def project_then_strip(obj: Any, schema: Schema, banned: frozenset[str] | None = None) -> Any:
    projected = project_schema(obj, schema)
    if banned:
        return strip_keys(projected, banned)
    return projected
