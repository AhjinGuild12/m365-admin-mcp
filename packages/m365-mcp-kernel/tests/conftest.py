from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from m365_mcp_kernel.graph_client import GraphClient


@pytest.fixture
def graph_client_factory():
    def _make(**kwargs) -> GraphClient:
        token = kwargs.pop("token", "test-token")
        sleeps: list[float] = []

        def sleep(delay: float) -> None:
            sleeps.append(delay)

        if "token_provider" not in kwargs:
            kwargs["token_provider"] = lambda t=token: t
        client = GraphClient(sleep=sleep, **kwargs)
        client.sleeps = sleeps  # type: ignore[attr-defined]
        return client

    return _make
