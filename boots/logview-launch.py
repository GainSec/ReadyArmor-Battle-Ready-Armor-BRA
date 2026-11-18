#!/usr/bin/env python3
"""Launcher for boots/logview.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    boots_dir = Path(__file__).resolve().parent
    project_root = boots_dir.parent
    cmd = [sys.executable, str(boots_dir / "logview.py"), *(sys.argv[1:] if argv is None else argv)]
    try:
        return int(subprocess.run(cmd, cwd=str(project_root)).returncode)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

