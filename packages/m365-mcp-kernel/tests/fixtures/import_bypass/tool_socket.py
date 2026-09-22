"""Regression fixture: socket import in a tool module must fail the AST gate."""

import socket

def poke() -> None:
    socket.gethostname()
