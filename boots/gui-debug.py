#!/usr/bin/env python3
"""Verbose BRA Web GUI launcher."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    os.environ["BRA_VERBOSE"] = "1"
    os.environ["BRA_PROXY_DEBUG"] = "1"
    print("=== BRA VERBOSE DEBUG MODE ===")
    print("Terminal: color-coded trace on stderr")
    print("Log file: .bra/logs/verbose.log")
    print("Proxy:    .bra/logs/litellm.log (LiteLLM sidecar)")
    print("===============================")

    boots_dir = Path(__file__).resolve().parent
    gui_py = boots_dir / "gui.py"
    cmd = [sys.executable, str(gui_py), *(sys.argv[1:] if argv is None else argv)]
    try:
        return int(subprocess.run(cmd, env=dict(os.environ)).returncode)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
