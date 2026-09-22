"""Regression fixture: string-built __import__ must fail the AST gate."""

def poke() -> None:
    __import__("urllib.request")
