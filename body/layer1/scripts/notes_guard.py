#!/usr/bin/env python3
"""notes_guard.py ─ layer3-engagement/NOTES/ Append-Only Enforcement

Purpose: Enforce append-only policy on layer3-engagement/NOTES/ directory
Invariant: No deletions, truncation, or modification of existing content

Usage:
  notes_guard.py check                    Validate layer3-engagement/NOTES/ structure
  notes_guard.py write <file>             Allow new file creation
  notes_guard.py append <file>            Allow appending to existing file
  notes_guard.py delete <file>            BLOCKED ─ always returns 1
  notes_guard.py modify <file>            BLOCKED ─ always returns 1
  notes_guard.py --help                   Show this help
  notes_guard.py --snapshot               Create baseline snapshot
  notes_guard.py --verify                 Verify against baseline

Exit Codes:
  0 ─ Allowed (operation is append-only safe)
  1 ─ Blocked (operation violates append-only policy)

Referenced By:
  ─ Prompt notes-guard doc path removed [legacy/deprecated]
  ─ CLAUDE.md (Evidence Chain of Custody)
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


_LIB_DIR = str((Path(__file__).resolve().parent.parent / "lib").resolve())
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

try:
    import killswitch as _killswitch  # type: ignore
except Exception:  # pragma: no cover
    _killswitch = None  # type: ignore


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_log(log_file: Path, level: str, message: str) -> None:
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_ts()}] [{level}] {message}\n")
    except Exception:
        # Governance guard must never crash due to logging.
        pass


def _con_info(msg: str) -> None:
    sys.stdout.write(f"[INFO] {msg}\n")


def _con_warn(msg: str) -> None:
    sys.stdout.write(f"[WARN] {msg}\n")


def _con_error(msg: str) -> None:
    sys.stderr.write(f"[ERROR] {msg}\n")


def _con_blocked(msg: str) -> None:
    sys.stderr.write(f"[BLOCKED] {msg}\n")


def _con_allowed(msg: str) -> None:
    sys.stdout.write(f"[ALLOWED] {msg}\n")


def _resolve_target(body_root: Path, target: str) -> Path:
    path = Path(target)
    if not path.is_absolute():
        path = body_root / path
    return path.resolve()


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        return path.read_bytes().count(b"\n")
    except Exception:
        return 0


def _sha256(path: Path) -> str:
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def _create_snapshot(notes_dir: Path, snapshot_file: Path, log_file: Path) -> int:
    _con_info("Creating layer3-engagement/NOTES/ snapshot")
    _append_log(log_file, "INFO", "Creating layer3-engagement/NOTES/ snapshot")
    if not notes_dir.is_dir():
        _con_error("layer3-engagement/NOTES/ directory does not exist")
        _append_log(log_file, "ERROR", "layer3-engagement/NOTES/ directory does not exist")
        return 1

    files: list[dict[str, int | str]] = []
    for file_path in sorted(p for p in notes_dir.rglob("*") if p.is_file()):
        rel = file_path.relative_to(notes_dir).as_posix()
        files.append(
            {
                "path": rel,
                "lines": _count_lines(file_path),
                "hash": _sha256(file_path),
                "size": file_path.stat().st_size,
            }
        )

    snapshot_file.parent.mkdir(parents=True, exist_ok=True)
    snapshot_file.write_text(
        json.dumps({"timestamp": _utc_ts(), "files": files}, separators=(",", ":")),
        encoding="utf-8",
    )
    _con_info(f"Snapshot saved to {snapshot_file}")
    _append_log(log_file, "INFO", f"Snapshot saved to {snapshot_file}")
    return 0


def _verify_snapshot(notes_dir: Path, snapshot_file: Path, log_file: Path) -> int:
    _con_info("Verifying layer3-engagement/NOTES/ against baseline")
    _append_log(log_file, "INFO", "Verifying layer3-engagement/NOTES/ against baseline")

    if not snapshot_file.is_file():
        _con_error("No baseline snapshot found. Run --snapshot first.")
        _append_log(log_file, "ERROR", "No baseline snapshot found. Run --snapshot first.")
        return 1

    try:
        snapshot = json.loads(snapshot_file.read_text(encoding="utf-8"))
    except Exception:
        _con_error("Baseline snapshot is unreadable")
        _append_log(log_file, "ERROR", "Baseline snapshot is unreadable")
        return 1

    baseline: dict[str, dict[str, int | str]] = {
        str(item.get("path", "")): item for item in snapshot.get("files", []) if isinstance(item, dict)
    }
    violations = 0

    for file_path in sorted(p for p in notes_dir.rglob("*") if p.is_file()):
        rel = file_path.relative_to(notes_dir).as_posix()
        current_lines = _count_lines(file_path)
        current_hash = _sha256(file_path)
        entry = baseline.get(rel)
        if entry is None:
            _con_info(f"NEW: {rel} (not in baseline)")
            _append_log(log_file, "INFO", f"NEW: {rel} (not in baseline)")
            continue
        base_lines = int(entry.get("lines", 0))
        base_hash = str(entry.get("hash", ""))
        if current_lines < base_lines:
            violations += 1
            _con_error(f"VIOLATION: {rel} reduced from {base_lines} to {current_lines} lines")
            _append_log(log_file, "ERROR", f"VIOLATION: {rel} reduced from {base_lines} to {current_lines} lines")
        elif current_lines == base_lines and base_hash and current_hash != base_hash:
            violations += 1
            _con_error(f"VIOLATION: {rel} content modified without line change")
            _con_error(f"  Baseline hash: {base_hash}")
            _con_error(f"  Current hash:  {current_hash}")
            _append_log(log_file, "ERROR", f"VIOLATION: {rel} content modified without line change")
        elif current_lines > base_lines:
            _con_info(f"OK: {rel} appended ({base_lines} \u2192 {current_lines} lines)")
            _append_log(log_file, "INFO", f"OK: {rel} appended ({base_lines} -> {current_lines} lines)")

    _con_info("Checking for deleted files...")
    _append_log(log_file, "INFO", "Checking for deleted files...")
    for rel in baseline:
        if not (notes_dir / rel).is_file():
            violations += 1
            _con_error(f"VIOLATION: {rel} was DELETED (existed in baseline)")
            _append_log(log_file, "ERROR", f"VIOLATION: {rel} was DELETED (existed in baseline)")

    if violations:
        _con_error(f"Found {violations} append-only violations")
        _append_log(log_file, "ERROR", f"Found {violations} append-only violations")
        return 1
    _con_info("layer3-engagement/NOTES/ integrity verified - no violations")
    _append_log(log_file, "INFO", "layer3-engagement/NOTES/ integrity verified - no violations")
    return 0


def _check_operation(operation: str, target: str | None, notes_dir: Path, body_root: Path, log_file: Path) -> int:
    op = operation.lower()
    if op == "check":
        _con_info("Validating layer3-engagement/NOTES/ structure")
        _append_log(log_file, "INFO", "Validating layer3-engagement/NOTES/ structure")
        if not notes_dir.is_dir():
            _con_warn("layer3-engagement/NOTES/ directory does not exist")
            _append_log(log_file, "WARN", "layer3-engagement/NOTES/ directory does not exist")
            sys.stdout.write("Creating layer3-engagement/NOTES/ directory...\n")
            notes_dir.mkdir(parents=True, exist_ok=True)
            _con_info("layer3-engagement/NOTES/ created")
            _append_log(log_file, "INFO", "layer3-engagement/NOTES/ created")
        else:
            notes_dir.mkdir(parents=True, exist_ok=True)
            file_count = sum(1 for p in notes_dir.rglob("*") if p.is_file())
            _con_info(f"layer3-engagement/NOTES/ contains {file_count} files")
            _append_log(log_file, "INFO", f"layer3-engagement/NOTES/ contains {file_count} files")
            for expected in ("FINDINGS.md", "SESSION.md"):
                if (notes_dir / expected).is_file():
                    _con_info(f"Found: {expected}")
                    _append_log(log_file, "INFO", f"Found: {expected}")
                else:
                    _con_warn(f"Optional file missing: {expected}")
                    _append_log(log_file, "WARN", f"Optional file missing: {expected}")
        _con_info("layer3-engagement/NOTES/ structure valid")
        _append_log(log_file, "INFO", "layer3-engagement/NOTES/ structure valid")
        return 0

    if op in {"delete", "remove", "rm"}:
        _con_blocked("DELETE operation is NEVER allowed in layer3-engagement/NOTES/")
        _con_blocked(f"Target: {target or ''}")
        _append_log(log_file, "BLOCKED", f"DELETE operation is NEVER allowed in layer3-engagement/NOTES/")
        _append_log(log_file, "VIOLATION", f"Attempted deletion: {target or ''}")
        return 1

    if op in {"modify", "edit", "overwrite", "truncate"}:
        _con_blocked("MODIFY operation is NOT allowed in layer3-engagement/NOTES/")
        _con_blocked(f"Target: {target or ''}")
        _con_blocked("Use 'append' to add content without modifying existing")
        _append_log(log_file, "BLOCKED", f"MODIFY operation is NOT allowed in layer3-engagement/NOTES/")
        _append_log(log_file, "VIOLATION", f"Attempted modification: {target or ''}")
        return 1

    if op in {"rename", "move", "mv"}:
        _con_blocked("RENAME operation is NOT allowed in layer3-engagement/NOTES/")
        _con_blocked(f"Target: {target or ''}")
        _append_log(log_file, "BLOCKED", f"RENAME operation is NOT allowed in layer3-engagement/NOTES/")
        _append_log(log_file, "VIOLATION", f"Attempted rename: {target or ''}")
        return 1

    if op not in {"write", "create", "append"}:
        _con_warn(f"Unknown operation: {operation}")
        _con_warn("Defaulting to BLOCK for safety")
        _append_log(log_file, "WARN", f"Unknown operation: {operation}")
        return 1

    if not target:
        _con_error(f"No target file specified")
        _append_log(log_file, "ERROR", f"No target file specified for {operation}")
        return 1

    target_path = _resolve_target(body_root, target)
    if not _is_within(target_path, notes_dir):
        _con_blocked(f"Path outside layer3-engagement/NOTES/: {target_path}")
        _append_log(log_file, "BLOCKED", f"Path outside layer3-engagement/NOTES/: {target_path}")
        return 1

    if op in {"write", "create"} and target_path.exists():
        _con_blocked(f"File already exists: {target_path} (use 'append' instead)")
        _append_log(log_file, "BLOCKED", f"File already exists (use append): {target_path}")
        return 1

    if op == "append" and not target_path.is_file():
        _con_warn(f"File does not exist, treating as 'write': {target_path}")
        _append_log(log_file, "WARN", f"File does not exist, treating as 'write': {target_path}")

    _con_allowed(f"{operation.capitalize()} operation allowed: {target_path}")
    _append_log(log_file, "ALLOWED", f"{operation.upper()} allowed: {target_path}")

    # Auto-invoke self-improvement for findings/leads appends
    if op == "append":
        si_script = Path(__file__).resolve().parent / "self-improvement.py"
        if si_script.is_file() and target:
            si_args: list[str] | None = None
            if "FINDINGS.md" in str(target_path):
                si_args = ["--finding", "--auto"]
            elif "LEADS.md" in str(target_path):
                si_args = ["--lead", "--auto"]
            if si_args:
                try:
                    subprocess.run(
                        [sys.executable, str(si_script)] + si_args,
                        capture_output=True, timeout=30,
                    )
                except (subprocess.TimeoutExpired, OSError):
                    pass

    return 0


def _print_help() -> None:
    sys.stdout.write(
        "notes_guard.py ─ layer3-engagement/NOTES/ Append-Only Enforcement\n"
        "\n"
        "USAGE:\n"
        "    notes_guard.py check                    Validate layer3-engagement/NOTES/ structure\n"
        "    notes_guard.py write <file>             Check if new file creation is allowed\n"
        "    notes_guard.py append <file>            Check if appending to file is allowed\n"
        "    notes_guard.py delete <file>            Check if deletion is allowed (always NO)\n"
        "    notes_guard.py modify <file>            Check if modification is allowed (always NO)\n"
        "    notes_guard.py --help                   Show this help\n"
        "    notes_guard.py --snapshot               Create baseline snapshot of layer3-engagement/NOTES/\n"
        "    notes_guard.py --verify                 Verify layer3-engagement/NOTES/ against baseline\n"
        "\n"
        "DESCRIPTION:\n"
        "    Enforces append-only semantics on the layer3-engagement/NOTES/ directory per governance model.\n"
        "    This protects evidence integrity by preventing accidental or malicious\n"
        "    deletion or modification of existing content.\n"
        "\n"
        "ALLOWED OPERATIONS:\n"
        "    ● Creating new files in layer3-engagement/NOTES/\n"
        "    ● Appending content to existing files\n"
        "    ● Creating new subdirectories\n"
        "\n"
        "BLOCKED OPERATIONS:\n"
        "    ✗ Deleting any file or directory\n"
        "    ✗ Truncating files (reducing line count)\n"
        "    ✗ Modifying existing content (only append allowed)\n"
        "    ✗ Renaming files (considered delete + create)\n"
        "\n"
        "EXIT CODES:\n"
        "    0 ─ Operation allowed\n"
        "    1 ─ Operation blocked\n"
        "\n"
        "EXAMPLES:\n"
        "    # Create baseline snapshot\n"
        "    ./notes_guard.py --snapshot\n"
        "\n"
        "    # Check structure\n"
        "    ./notes_guard.py check\n"
        "\n"
        "    # Verify new file creation\n"
        "    ./notes_guard.py write layer3-engagement/NOTES/new_finding.md\n"
        "    # Exit: 0 (Allowed)\n"
        "\n"
        "    # Attempt deletion\n"
        "    ./notes_guard.py delete layer3-engagement/NOTES/FINDINGS.md\n"
        "    # Exit: 1 (Blocked)\n"
        "\n"
        "REFERENCED BY:\n"
        "    # ─ Prompt notes-guard doc path removed [legacy/deprecated]\n"
        "    ─ CLAUDE.md (Evidence Chain of Custody)\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    body_root = _detect_body_root(Path(__file__).resolve())
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    log_file = body_root / ".bra" / "logs" / "notes_guard.log"
    snapshot_file = body_root / ".bra" / "snapshots" / "notes_baseline.json"

    if _killswitch is not None:
        try:
            _killswitch.check_killswitch(body_root)
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else 99

    if not args or args[0] in {"--help", "-h"}:
        _print_help()
        return 0
    if args[0] == "--snapshot":
        return _create_snapshot(notes_dir, snapshot_file, log_file)
    if args[0] == "--verify":
        return _verify_snapshot(notes_dir, snapshot_file, log_file)

    operation = args[0]
    target = args[1] if len(args) > 1 else None
    _append_log(log_file, "INFO", f"Operation: {operation}, Target: {target or ''}")
    return _check_operation(operation, target, notes_dir, body_root, log_file)


if __name__ == "__main__":
    raise SystemExit(main())
