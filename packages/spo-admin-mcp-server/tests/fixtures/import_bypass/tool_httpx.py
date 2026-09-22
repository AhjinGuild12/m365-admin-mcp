"""Regression fixture: httpx import in a workload tool module is a violation."""

import httpx


def poke() -> None:
    httpx.Client()
