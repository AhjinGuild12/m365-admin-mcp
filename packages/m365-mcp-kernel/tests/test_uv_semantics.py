"""Secret-free uv semantics fixture (KTD12).

Requires the kernel lock to exist. Run as part of U0 after `uv lock --no-build`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UV = Path("/opt/homebrew/Cellar/uv/0.11.28/bin/uv")
CACHE = Path.home() / ".config" / "m365-mcp-kernel" / "uv-cache"

pytestmark = pytest.mark.skipif(
    not (ROOT / "uv.lock").exists() or not UV.exists(),
    reason="kernel uv.lock or pinned uv missing",
)


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


def _editable_present(venv: Path, name: str) -> bool:
    site = next(venv.glob("lib/python*/site-packages"), None)
    if site is None:
        return False
    direct = list(site.glob(f"{name}*.dist-info")) + list(site.glob(f"__editable__.{name}*.pth"))
    pth = list(site.glob("*.pth"))
    text_hits = False
    for p in pth:
        try:
            body = p.read_text(encoding="utf-8")
        except OSError:
            continue
        if name.replace("-", "_") in body or name in body:
            text_hits = True
    return bool(direct) or text_hits


def test_dependency_only_then_audited_local_editables(tmp_path: Path) -> None:
    kernel = ROOT
    consumer = tmp_path / "dummy-mcp-server"
    consumer.mkdir()
    (consumer / "pyproject.toml").write_text(
        """
[build-system]
requires = ["hatchling==1.32.0"]
build-backend = "hatchling.build"

[project]
name = "dummy-mcp"
version = "0.0.0"
requires-python = ">=3.10"
dependencies = [
    "m365-mcp-kernel",
    "mcp>=2.1,<3",
    "azure-identity",
    "httpx",
]

[tool.hatch.build.targets.wheel]
packages = ["src/dummy_mcp"]

[tool.uv]
required-version = ">=0.11.28"
build-constraint-dependencies = [
    "hatchling==1.32.0",
    "packaging==26.3",
    "pathspec==1.1.1",
    "pluggy==1.6.0",
    "tomlkit==0.15.1",
    "trove-classifiers==2026.6.1.19",
]

[tool.uv.sources]
m365-mcp-kernel = { path = "%s", editable = true }
"""
        % kernel.as_posix()
    )
    src = consumer / "src" / "dummy_mcp"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("ok = True\n")

    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
        "LANG": "C",
        "UV_CACHE_DIR": str(CACHE),
        "HOME": str(tmp_path / "home"),
    }
    (tmp_path / "home").mkdir()

    locked = _run([str(UV), "lock", "--no-build"], cwd=consumer, env=env)
    assert locked.returncode == 0, locked.stderr + locked.stdout

    dep_only = _run(
        [
            str(UV),
            "sync",
            "--frozen",
            "--no-install-project",
            "--no-install-package",
            "m365-mcp-kernel",
            "--no-build",
        ],
        cwd=consumer,
        env=env,
    )
    assert dep_only.returncode == 0, dep_only.stderr + dep_only.stdout
    venv = consumer / ".venv"
    assert venv.is_dir()
    assert not _editable_present(venv, "m365-mcp-kernel")
    assert not _editable_present(venv, "dummy-mcp")
    assert not _editable_present(venv, "dummy_mcp")

    # uv 0.11.28: --no-build refuses local editables too. Audited local builds
    # are `uv sync --frozen` after a --no-build lock (third-party stay wheels).
    no_build_local = _run(
        [str(UV), "sync", "--frozen", "--no-build"],
        cwd=consumer,
        env=env,
    )
    assert no_build_local.returncode != 0
    assert "no-build" in (no_build_local.stderr + no_build_local.stdout).lower() or "no binary" in (
        no_build_local.stderr + no_build_local.stdout
    ).lower()

    both = _run([str(UV), "sync", "--frozen"], cwd=consumer, env=env)
    assert both.returncode == 0, both.stderr + both.stdout
    assert _editable_present(venv, "m365_mcp_kernel") or _editable_present(venv, "m365-mcp-kernel")
    assert _editable_present(venv, "dummy_mcp") or _editable_present(venv, "dummy-mcp")
    log = (both.stderr + both.stdout).lower()
    assert "building sdist" not in log
    shutil.rmtree(consumer / ".venv", ignore_errors=True)
