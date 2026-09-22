from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.conftest import gid

SERVER_ROOT = Path(__file__).resolve().parents[1]
PYTHON = SERVER_ROOT / ".venv" / "bin" / "python"
TENANT = gid("0")
SECRET = "fixture-secret-not-real"


@pytest.mark.skipif(not PYTHON.exists(), reason="package venv not installed yet")
def test_mcp_initialize_over_stdio() -> None:
    env = {
        "TEAMS_ADMIN_TENANT_ID": TENANT,
        "TEAMS_ADMIN_CLIENT_ID": TENANT,
        "TEAMS_ADMIN_CLIENT_SECRET": SECRET,
        "TEAMS_ADMIN_SECRET_EXPIRES": "2099-01-01T00:00:00Z",
        "TEAMS_ADMIN_CLIENT_CERTIFICATE_PATH": "",
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }
    proc = subprocess.Popen(
        [str(PYTHON), "-I", "-B", "-m", "teams_admin_mcp"],
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
            "clientInfo": {"name": "teams-phase-a", "version": "0.1"},
        },
    }
    try:
        stdout, stderr = proc.communicate(json.dumps(init) + "\n", timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    line = (stdout or "").splitlines()[0] if stdout else ""
    msg = json.loads(line)
    assert msg.get("id") == 1
    result = msg.get("result") or {}
    info = result.get("serverInfo") or result.get("server_info") or {}
    assert info.get("name") == "teams-admin-ro"
    combined = (stdout or "") + (stderr or "")
    assert SECRET not in combined
    assert TENANT not in combined
