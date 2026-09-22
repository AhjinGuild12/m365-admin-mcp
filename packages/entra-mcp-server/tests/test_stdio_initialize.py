from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

SERVER_ROOT = Path(__file__).resolve().parents[1]
PYTHON = SERVER_ROOT / ".venv" / "bin" / "python"


@pytest.mark.skipif(not PYTHON.exists(), reason="U6/U2 venv not installed yet")
def test_mcp_initialize_over_stdio() -> None:
    env = {
        "ENTRA_TENANT_ID": "00000000-0000-0000-0000-000000000001",
        "ENTRA_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
        "ENTRA_CLIENT_SECRET": "fixture-secret-not-real",
        "ENTRA_SECRET_EXPIRES": "2099-01-01T00:00:00Z",
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }
    proc = subprocess.Popen(
        [str(PYTHON), "-I", "-B", "-m", "entra_mcp"],
        cwd=str(SERVER_ROOT),
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
            "clientInfo": {"name": "entra-u2-gate", "version": "0.1"},
        },
    }
    try:
        stdout, stderr = proc.communicate(json.dumps(init) + "\n", timeout=8)
        line = (stdout or "").splitlines()[0] if stdout else ""
        msg = json.loads(line)
        assert msg.get("id") == 1
        result = msg.get("result") or {}
        info = result.get("serverInfo") or result.get("server_info") or {}
        assert info.get("name") == "entra-ro"
        assert "fixture-secret-not-real" not in (stderr or "")
        assert "fixture-secret-not-real" not in line
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
