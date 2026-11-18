#!/usr/bin/env python3
"""BRA Web GUI launcher."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gui.py",
        description="BRA Web GUI launcher",
        add_help=False,
    )
    parser.add_argument("-p", "--port", default=os.environ.get("BRA_GUI_PORT", "9999"))
    parser.add_argument("-h", "--host", default=os.environ.get("BRA_GUI_HOST", "127.0.0.1"))
    parser.add_argument(
        "-d",
        "--bra-dir",
        default=None,
        help="BRA project directory (default: <project>/body)",
    )
    parser.add_argument("--no-auth", action="store_true")
    parser.add_argument("--ner", action="store_true", help="Enable NER model for anonymization")
    parser.add_argument("--help", action="store_true", help="Show this help")
    return parser.parse_args(argv)


def _show_help() -> None:
    default_port = os.environ.get("BRA_GUI_PORT", "9999")
    default_host = os.environ.get("BRA_GUI_HOST", "127.0.0.1")
    default_dir = os.environ.get("BRA_GUI_DIR", "body/")
    print("BRA Web GUI Launcher")
    print("")
    print("Usage: gui.py [OPTIONS]")
    print("")
    print("Options:")
    print(f"  -p, --port PORT    Server port (default: {default_port})")
    print(f"  -h, --host HOST    Bind host (default: {default_host})")
    print("  -d, --bra-dir DIR  BRA project directory (default: body/)")
    print("  --no-auth          Disable token authentication")
    print("  --ner              Enable NER model for anonymization (downloads ~1.6GB on first run)")
    print("  --help             Show this help")
    print("")
    print("Environment variables:")
    print(f"  BRA_GUI_PORT       Default port (current: {default_port})")
    print(f"  BRA_GUI_HOST       Default host (current: {default_host})")
    print(f"  BRA_GUI_DIR        Default BRA directory (current: {default_dir})")


def _ensure_venv(venv_dir: Path) -> Path:
    python_bin = venv_dir / "bin" / "python3"
    if not venv_dir.exists():
        print("[gui] Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    if not python_bin.exists():
        raise RuntimeError(f"Python executable missing from venv: {python_bin}")
    return python_bin


def _deps_installed(python_bin: Path) -> bool:
    probe = subprocess.run(
        [str(python_bin), "-c", "import fastapi, uvicorn, bra.core.bridge"],
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0


def _install_deps(python_bin: Path, project_root: Path, boots_dir: Path) -> None:
    print("[gui] Installing dependencies...")
    subprocess.run([str(python_bin), "-m", "pip", "install", "-q", "--upgrade", "pip"], check=True)
    subprocess.run([str(python_bin), "-m", "pip", "install", "-q", "-r", str(boots_dir / "requirements.txt")], check=True)
    subprocess.run([str(python_bin), "-m", "pip", "install", "-q", "-e", str(project_root / "head")], check=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.help:
        _show_help()
        return 0

    boots_dir = Path(__file__).resolve().parent
    project_root = boots_dir.parent
    bra_dir = Path(args.bra_dir) if args.bra_dir else Path(os.environ.get("BRA_GUI_DIR", str(project_root / "body")))
    if not bra_dir.is_absolute():
        bra_dir = (project_root / bra_dir).resolve()

    if not (bra_dir / ".bra").exists():
        print(f"[gui] Warning: .bra directory not found at {(bra_dir / '.bra')}")
        print("[gui] GUI will show limited information.")

    python_bin = _ensure_venv(boots_dir / ".venv")
    if not _deps_installed(python_bin):
        _install_deps(python_bin, project_root, boots_dir)

    env = dict(os.environ)
    venv_root = str(python_bin.parent.parent)
    env["VIRTUAL_ENV"] = venv_root
    path_parts = [str(python_bin.parent)]
    if env.get("PATH"):
        path_parts.append(env["PATH"])
    env["PATH"] = ":".join(path_parts)
    py_path_parts = [str(project_root), str(project_root / "head")]
    if env.get("PYTHONPATH"):
        py_path_parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = ":".join(py_path_parts)

    cmd = [
        str(python_bin),
        "-m",
        "boots.main",
        "--bra-dir",
        str(bra_dir),
        "--host",
        str(args.host),
        "--port",
        str(args.port),
    ]
    if args.no_auth:
        cmd.append("--no-auth")
    if args.ner:
        cmd.append("--ner")

    print("[gui] Starting BRA Web GUI...")
    try:
        proc = subprocess.run(cmd, cwd=str(project_root), env=env)
        return int(proc.returncode)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
