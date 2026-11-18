#!/usr/bin/env python3
"""Capture layer1 Python script runtime contracts using safe probe invocations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _layer1_scripts(project_root: Path) -> Path:
    return project_root / "body" / "layer1" / "scripts"


def _layer1_root(project_root: Path) -> Path:
    return project_root / "body" / "layer1"


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def _run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: int, capture_limit: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": _truncate(proc.stdout or "", capture_limit),
            "stderr": _truncate(proc.stderr or "", capture_limit),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": _truncate(exc.stdout or "", capture_limit),
            "stderr": _truncate(exc.stderr or "", capture_limit),
            "timed_out": True,
        }


def capture_for_script(project_root: Path, name: str, timeout: int, capture_limit: int) -> dict[str, Any]:
    scripts_dir = _layer1_scripts(project_root)
    layer1_root = _layer1_root(project_root)
    entry = Path(name)
    if not entry.is_absolute():
        base = layer1_root if "/" in name else scripts_dir
        entry = base / name

    if entry.suffix == ".py":
        py = entry
    else:
        py = scripts_dir / f"{entry.stem}.py"
        if entry.parent != scripts_dir:
            py = entry.with_suffix(".py")

    shell = py.with_suffix(".sh")

    env = dict(os.environ)
    env.setdefault("BRA_LAYER1_PY_ENABLED", "1")
    env.setdefault("BRA_CALLER", "contract_capture")

    probes: dict[str, Any] = {
        "script": name,
        "shell_path": str(shell),
        "python_path": str(py),
        "shell_exists": shell.exists(),
        "python_exists": py.exists(),
    }

    if shell.exists():
        probes["shell_help"] = _run(
            ["bash", str(shell), "--help"],
            cwd=project_root / "body",
            env=env,
            timeout=timeout,
            capture_limit=capture_limit,
        )

    if py.exists():
        probes["python_help"] = _run([sys.executable, str(py), "--help"], cwd=project_root / "body", env=env, timeout=timeout, capture_limit=capture_limit)

    return probes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture layer1 script contract probes.")
    parser.add_argument("--project-root", type=Path, default=_project_root())
    parser.add_argument("--output", type=Path, default=Path("body/.bra/contracts/layer1-contracts.json"))
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--capture-limit", type=int, default=2000)
    parser.add_argument(
        "--scope",
        choices=["scripts", "all"],
        default="all",
        help="Capture only layer1/scripts or all layer1 Python files",
    )
    parser.add_argument("--scripts", nargs="*", help="Optional subset of script names (e.g. status.py precheck.py)")
    args = parser.parse_args(argv)

    project_root = args.project_root.resolve()
    scripts_dir = _layer1_scripts(project_root)
    layer1_root = _layer1_root(project_root)

    if args.scripts:
        names = sorted(set(args.scripts))
    else:
        if args.scope == "scripts":
            names = sorted(p.name for p in scripts_dir.glob("*.py"))
        else:
            names = sorted(str(p.relative_to(layer1_root)) for p in layer1_root.rglob("*.py"))

    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root),
        "scope": args.scope,
        "count": len(names),
        "scripts": [capture_for_script(project_root, name, args.timeout, args.capture_limit) for name in names],
    }

    output_path = (project_root / args.output).resolve() if not args.output.is_absolute() else args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    print(str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
