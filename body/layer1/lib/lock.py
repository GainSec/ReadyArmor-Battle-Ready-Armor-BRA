#!/usr/bin/env python3
"""PID lock-file helpers for single-instance script execution."""

from __future__ import annotations

import atexit
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_HELD_LOCKS: set[str] = set()


def _detect_body_root() -> Path:
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if parent.name == "body":
            return parent
    return cwd


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lock_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "lock.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [LOCK] [{os.getpid()}] {message}\n")
    except OSError:
        pass


def _lock_dir(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "locks"


def _get_lock_file(name: str, body_root: Path | None = None) -> Path:
    """Return lock file path for ``name``."""
    safe_name = name.replace("/", "_")
    return _lock_dir(body_root) / f"{safe_name}.lock"


def _is_pid_running(pid: int) -> bool:
    """Return ``True`` if PID exists and is signalable."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_locked(name: str, body_root: Path | None = None) -> bool:
    """Return ``True`` if lock exists and owner PID is still active."""
    lock_file = _get_lock_file(name, body_root)
    if not lock_file.is_file():
        return False

    try:
        first_line = lock_file.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
        lock_pid = int(first_line)
    except (IndexError, ValueError, OSError):
        try:
            lock_file.unlink()
        except OSError:
            pass
        return False

    if _is_pid_running(lock_pid):
        return True

    _lock_log(f"Cleaned stale lock for {name} (PID {lock_pid} no longer running)", body_root)
    try:
        lock_file.unlink()
    except OSError:
        pass
    return False


def get_lock_info(name: str, body_root: Path | None = None) -> str:
    """Return lock metadata text for ``name`` or empty string."""
    lock_file = _get_lock_file(name, body_root)
    try:
        return lock_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def acquire_lock(name: str, timeout: int = 0, body_root: Path | None = None) -> bool:
    """Acquire lock for ``name``. Returns ``True`` on success."""
    root = _detect_body_root() if body_root is None else body_root
    lock_file = _get_lock_file(name, root)
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    deadline = time.monotonic() + max(timeout, 0)
    while True:
        if is_locked(name, root):
            if timeout > 0 and time.monotonic() < deadline:
                time.sleep(1)
                continue
            lock_info = get_lock_info(name, root)
            print(f"Cannot acquire lock: {name}")
            if lock_info:
                print("Lock held by:")
                print(lock_info)
            _lock_log(f"Failed to acquire lock {name} - already held", root)
            return False

        payload = "\n".join(
            [
                str(os.getpid()),
                f"Script: {Path(sys.argv[0]).name or 'python'}",
                f"Started: {_utc_now()}",
                f"Hostname: {socket.gethostname()}",
                f"User: {os.environ.get('USER') or os.environ.get('USERNAME') or 'unknown'}",
            ]
        ) + "\n"

        try:
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            _HELD_LOCKS.add(name)
            _lock_log(f"Acquired lock: {name}", root)
            return True
        except FileExistsError:
            if timeout > 0 and time.monotonic() < deadline:
                time.sleep(1)
                continue
            _lock_log(f"Failed to acquire lock {name} - race condition", root)
            return False
        except OSError:
            _lock_log(f"Failed to acquire lock {name} - write error", root)
            return False


def release_lock(name: str, body_root: Path | None = None) -> bool:
    """Release lock if owned by current process."""
    root = _detect_body_root() if body_root is None else body_root
    lock_file = _get_lock_file(name, root)
    if not lock_file.is_file():
        _HELD_LOCKS.discard(name)
        return True

    owner_pid = None
    try:
        owner_pid = int(lock_file.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip())
    except (IndexError, ValueError, OSError):
        owner_pid = None

    if owner_pid not in {None, os.getpid()}:
        _lock_log(f"Cannot release lock {name} - not owned by this process (owned by {owner_pid})", root)
        return False

    try:
        lock_file.unlink()
    except OSError:
        return False

    _HELD_LOCKS.discard(name)
    _lock_log(f"Released lock: {name}", root)
    return True


def wait_for_lock(name: str, timeout: int = 30, body_root: Path | None = None) -> bool:
    """Wait until lock is free or timeout expires."""
    deadline = time.monotonic() + max(timeout, 0)
    while is_locked(name, body_root):
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)
    return True


def release_all_locks(body_root: Path | None = None) -> None:
    """Release all locks held by this process."""
    for name in list(_HELD_LOCKS):
        release_lock(name, body_root)


def _setup_lock_cleanup() -> None:
    """Register process-exit cleanup handler."""
    atexit.register(release_all_locks)


def list_locks(body_root: Path | None = None, *, quiet: bool = False) -> list[dict[str, str]]:
    """Return lock status entries for current lock directory."""
    root = _detect_body_root() if body_root is None else body_root
    lock_dir = _lock_dir(root)
    entries: list[dict[str, str]] = []

    if not quiet:
        print("Current locks:")
        print("==============")

    if not lock_dir.is_dir():
        if not quiet:
            print("No lock directory exists")
        return entries

    for lock_file in sorted(lock_dir.glob("*.lock")):
        name = lock_file.stem
        status = "LOCKED" if is_locked(name, root) else "FREE"
        info = get_lock_info(name, root)
        pid = ""
        first_line = info.splitlines()[0].strip() if info else ""
        if first_line.isdigit():
            pid = first_line
        entries.append({"name": name, "status": status, "pid": pid})

    if not quiet:
        if not entries:
            print("No locks found")
        else:
            for entry in entries:
                pid_suffix = f" (PID: {entry['pid']})" if entry["pid"] else ""
                print(f"  [{entry['status']}] {entry['name']}{pid_suffix}")

    return entries


def force_release_lock(name: str, body_root: Path | None = None) -> bool:
    """Force-remove lock file without ownership checks."""
    root = _detect_body_root() if body_root is None else body_root
    lock_file = _get_lock_file(name, root)
    if not lock_file.is_file():
        return False
    print(f"Force releasing lock: {name}")
    try:
        lock_file.unlink()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    _HELD_LOCKS.discard(name)
    _lock_log(f"FORCE released lock: {name}", root)
    return True


def _show_help() -> None:
    print(
        "lock.py\n\n"
        "Usage:\n"
        "  lock.py --acquire <name> [timeout]\n"
        "  lock.py --release <name>\n"
        "  lock.py --status <name>\n"
        "  lock.py --list\n"
    )


def main(argv: list[str] | None = None) -> int:
    _setup_lock_cleanup()
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--acquire" and len(args) >= 2:
        timeout = int(args[2]) if len(args) >= 3 and args[2].isdigit() else 0
        return 0 if acquire_lock(args[1], timeout=timeout) else 1

    if args[0] == "--release" and len(args) >= 2:
        return 0 if release_lock(args[1]) else 1

    if args[0] == "--status" and len(args) >= 2:
        print("LOCKED" if is_locked(args[1]) else "FREE")
        return 0

    if args[0] == "--list":
        list_locks()
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


_setup_lock_cleanup()

if __name__ == "__main__":
    raise SystemExit(main())
