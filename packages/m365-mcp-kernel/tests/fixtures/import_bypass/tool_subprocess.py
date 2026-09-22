"""Regression fixture: subprocess import must fail the AST gate."""

import subprocess

def poke() -> None:
    subprocess.run(["true"])
