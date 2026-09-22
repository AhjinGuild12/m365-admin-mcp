from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
KERNEL = ROOT.parent / "m365-mcp-kernel" / "src"
for path in (KERNEL, SRC):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)
