from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.server_factory import ToolSpec, create_server, registered_tool_names

SRC = Path(__file__).resolve().parents[1] / "src"


def ping() -> dict:
    """Health ping."""
    return {"ok": True}


def test_create_server_registers_allowlist() -> None:
    mcp = create_server("m365-kernel-test", [ToolSpec("ping", ping, "Health ping")])
    assert registered_tool_names(mcp) == ("ping",)


def test_create_server_rejects_table_mismatch() -> None:
    with pytest.raises(SanitizedGraphError, match="tool_allowlist_mismatch"):
        create_server(
            "m365-kernel-test",
            [ToolSpec("ping", ping, "Health ping")],
            declared_names=("ping", "extra_tool"),
        )


def test_mcp_sdk_has_mcpserver_not_fastmcp() -> None:
    import importlib

    module = importlib.import_module("mcp.server.mcpserver")
    assert hasattr(module, "MCPServer")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("mcp.server.fastmcp")


ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"


@pytest.mark.skipif(not VENV_PYTHON.exists(), reason="U0 kernel venv not installed yet")
def test_stdio_initialize_handshake() -> None:
    script = r"""
from m365_mcp_kernel.server_factory import ToolSpec, create_server, run_stdio

def ping() -> dict:
    return {"ok": True}

mcp = create_server("m365-kernel-test", [ToolSpec("ping", ping, "Health ping")])
run_stdio(mcp)
"""
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }
    proc = subprocess.Popen(
        [str(VENV_PYTHON), "-I", "-B", "-c", script],
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "m365-u0", "version": "0.1"},
        },
    }
    try:
        stdout, stderr = proc.communicate(json.dumps(init) + "\n", timeout=12)
        line = (stdout or "").splitlines()[0] if stdout else ""
        msg = json.loads(line)
        assert msg.get("id") == 1
        result = msg.get("result") or {}
        info = result.get("serverInfo") or result.get("server_info") or {}
        assert info.get("name") == "m365-kernel-test"
        assert "secret" not in (stderr or "").lower()
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
