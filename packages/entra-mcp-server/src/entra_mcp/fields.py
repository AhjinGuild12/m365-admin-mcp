"""Project Graph objects onto declared field allowlists."""

from __future__ import annotations

from typing import Any


def project(obj: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    return {key: obj[key] for key in fields if key in obj}


def project_list(items: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    if not items:
        return []
    return [project(item, fields) for item in items]


def strip_keys(obj: Any, banned: frozenset[str]) -> Any:
    if isinstance(obj, dict):
        return {k: strip_keys(v, banned) for k, v in obj.items() if k not in banned}
    if isinstance(obj, list):
        return [strip_keys(item, banned) for item in obj]
    return obj
