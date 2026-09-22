"""stdio entry: python -I -B -m entra_mcp."""

import sys

from entra_mcp.server import mcp


def main() -> None:
    # Hosts speak MCP over a pipe; force line buffering so initialize is not stuck
    # in a block-buffered stdout (argv stays -I -B, no PYTHONUNBUFFERED).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
