"""Regression fixture: httpx import in a workload tool module is a violation (KTD13)."""

import httpx

def poke() -> None:
    httpx.Client()
