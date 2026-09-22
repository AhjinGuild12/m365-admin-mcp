"""Regression fixture: report_download-shaped module importing httpx is a violation."""

import httpx

def poke() -> None:
    httpx.Client()
