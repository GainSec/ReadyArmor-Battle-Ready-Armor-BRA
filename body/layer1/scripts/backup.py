#!/usr/bin/env python3
"""Native backup manager for BRA state."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BACKUP_TARGETS = (
    ".bra",
    "layer3-engagement/NOTES",
    "layer3-engagement/OVERRIDES.md",
)
ROTATION_THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _backup_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _format_size(size_bytes: int) -> str:
    """Format byte count for human readability."""
    if size_bytes >= 1073741824:
        return f"{size_bytes / 1073741824:.2f} GiB"
    elif size_bytes >= 1048576:
        return f"{size_bytes / 1048576:.2f} MiB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KiB"
    return f"{size_bytes} bytes"


def _resolve_within(base: Path, raw: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve(strict=False)
    base_resolved = base.resolve(strict=False)
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"Path escapes backup directory: {raw}") from exc
    return resolved


def _resolve_backup_reference(backups_dir: Path, raw_backup: str) -> Path:
    raw_path = Path(raw_backup)
    if raw_path.is_absolute():
        return raw_path.resolve(strict=False)
    if raw_path.parts[:1] == ("BACKUPS",):
        raw_path = Path(*raw_path.parts[1:])
    return _resolve_within(backups_dir, str(raw_path))


def _manifest_entries(backup_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for file_path in sorted(backup_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.name == "manifest.json":
            continue
        rel = file_path.relative_to(backup_dir).as_posix()
        entries.append({"path": rel, "sha256": _sha256(file_path), "size": file_path.stat().st_size})
    return entries


def _log(body_root: Path, level: str, message: str) -> None:
    """Append to .bra/logs/backup.log."""
    log_file = body_root / ".bra" / "logs" / "backup.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        pass


def _write_manifest(backup_dir: Path, body_root: Path) -> None:
    entries = _manifest_entries(backup_dir)
    total_size = sum(e["size"] for e in entries)
    payload = {
        "version": "1.0",
        "created": _utc_now(),
        "timestamp": backup_dir.name,
        "source": str(body_root),
        "file_count": len(entries),
        "total_size": total_size,
        "targets": list(BACKUP_TARGETS),
        "artifacts": entries,
    }
    (backup_dir / "manifest.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _copy_target(body_root: Path, backup_dir: Path, rel_target: str) -> None:
    source = body_root / rel_target
    destination = backup_dir / rel_target
    if not source.exists():
        return
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _create_backup(body_root: Path, backups_dir: Path, *, name: str | None, dry_run: bool) -> int:
    stamp = name or _backup_stamp()
    backup_dir = backups_dir / stamp
    index = 1
    while backup_dir.exists():
        backup_dir = backups_dir / f"{stamp}_{index}"
        index += 1

    if dry_run:
        print(f"[DRY-RUN] Would create backup: {backup_dir}")
        for target in BACKUP_TARGETS:
            print(f"[DRY-RUN] Would copy: {target}")
        return 0

    backup_dir.mkdir(parents=True, exist_ok=False)
    print(f"[BACKUP] Creating backup: {stamp}")
    print(f"[BACKUP] Destination: {backup_dir}")
    print()
    copied = 0
    for target in BACKUP_TARGETS:
        source = body_root / target
        if not source.exists():
            print(f"[WARN] Target not found, skipping: {target}")
            continue
        print(f"[BACKUP] Backing up: {target}")
        _copy_target(body_root, backup_dir, target)
        copied += 1
    _write_manifest(backup_dir, body_root)

    total_files = sum(1 for path in backup_dir.rglob("*") if path.is_file())
    total_size = sum(path.stat().st_size for path in backup_dir.rglob("*") if path.is_file())
    manifest_path = backup_dir / "manifest.json"

    print()
    print("[BACKUP] ==========================================")
    print("[BACKUP]   BACKUP COMPLETE")
    print("[BACKUP] ==========================================")
    print(f"[BACKUP] Location:  {backup_dir}")
    print(f"[BACKUP] Files:     {total_files}")
    print(f"[BACKUP] Size:      {_format_size(total_size)}")
    print(f"[BACKUP] Manifest:  {manifest_path}")
    _log(body_root, "BACKUP", f"Created backup: {backup_dir.name} ({total_size} bytes, {copied} targets)")
    return 0


def _list_backups(backups_dir: Path) -> int:
    if not backups_dir.exists():
        print("No backups directory found.")
        return 0
    entries = [path for path in sorted(backups_dir.iterdir()) if path.is_dir()]
    if not entries:
        print("No backups available.")
        return 0

    print(f"[INFO] Available backups in {backups_dir}:")
    print()
    for backup in entries:
        size = sum(path.stat().st_size for path in backup.rglob("*") if path.is_file())
        has_manifest = "yes" if (backup / "manifest.json").is_file() else "no"
        print(f"  {backup.name:<20}  {_format_size(size):>12}  manifest: {has_manifest}")
    print()
    print(f"[INFO] Total: {len(entries)} backup(s)")
    return 0


def _verify_backup(backups_dir: Path, raw_backup: str) -> int:
    try:
        backup = _resolve_backup_reference(backups_dir, raw_backup)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    manifest_path = backup / "manifest.json"
    if not backup.is_dir():
        print(f"[ERROR] Backup not found: {backup}", file=sys.stderr)
        return 1
    if not manifest_path.is_file():
        print(f"[ERROR] Missing manifest: {manifest_path}", file=sys.stderr)
        return 1

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid manifest JSON: {manifest_path}", file=sys.stderr)
        return 2

    verified = 0
    failed = 0
    missing = 0
    # Support both old ("entries") and new ("artifacts") manifest key
    entries_list = payload.get("artifacts", payload.get("entries", []))
    for entry in entries_list:
        rel = str(entry.get("path", ""))
        expected = str(entry.get("sha256", ""))
        file_path = backup / rel
        if not file_path.is_file():
            print(f"[ERROR] MISSING: {rel}")
            missing += 1
            continue
        actual = _sha256(file_path)
        if actual != expected:
            print(f"[ERROR] MISMATCH: {rel}")
            print(f"  Expected: {expected}")
            print(f"  Actual:   {actual}")
            failed += 1
        else:
            verified += 1

    print()
    print("[INFO] Verification results:")
    print(f"[INFO]   Verified: {verified}")
    print(f"[INFO]   Failed:   {failed}")
    print(f"[INFO]   Missing:  {missing}")

    if failed > 0 or missing > 0:
        print("[ERROR] Verification FAILED")
        return 2

    print("[INFO] Verification PASSED")
    return 0


def _restore_backup(body_root: Path, backups_dir: Path, raw_backup: str, *, dry_run: bool) -> int:
    try:
        backup = _resolve_backup_reference(backups_dir, raw_backup)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if not backup.is_dir():
        print(f"[ERROR] Backup not found: {backup}", file=sys.stderr)
        return 1

    # Verify backup integrity before restoring
    print("[RESTORE] Verifying backup integrity before restore...")
    rc = _verify_backup(backups_dir, raw_backup)
    if rc != 0:
        print("[ERROR] Backup verification failed, aborting restore", file=sys.stderr)
        return 2

    print()
    print("[RESTORE] ==========================================")
    print("[RESTORE]   RESTORING FROM BACKUP")
    print("[RESTORE] ==========================================")
    print(f"[RESTORE] Source: {backup}")
    print(f"[RESTORE] Target: {body_root}")
    print()

    # Create pre-restore backup of current state
    if not dry_run:
        pre_restore_name = f"pre_restore_{_backup_stamp()}"
        pre_restore_dir = backups_dir / pre_restore_name
        print(f"[WARN] Creating pre-restore backup: {pre_restore_dir}")
        _log(body_root, "RESTORE", f"Creating pre-restore backup: {pre_restore_name}")
        pre_restore_dir.mkdir(parents=True, exist_ok=True)
        for target in BACKUP_TARGETS:
            source = body_root / target
            if source.exists():
                _copy_target(body_root, pre_restore_dir, target)
        _write_manifest(pre_restore_dir, body_root)

        for target in BACKUP_TARGETS:
            source_path = backup / target
            destination_path = body_root / target
            if not source_path.exists():
                continue
            if destination_path.is_dir():
                shutil.rmtree(destination_path)
            elif destination_path.exists():
                destination_path.unlink()

    restored = 0
    for item in sorted(backup.rglob("*")):
        if item.name == "manifest.json":
            continue
        if not item.is_file():
            continue
        rel = item.relative_to(backup)
        destination = (body_root / rel).resolve(strict=False)
        try:
            destination.relative_to(body_root.resolve(strict=False))
        except ValueError:
            print(f"[WARN] Skipping unsafe path in backup: {rel}")
            continue

        if dry_run:
            print(f"[DRY-RUN] Would restore: {rel}")
            restored += 1
            continue

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)
        restored += 1

    print()
    print("[RESTORE] ==========================================")
    print("[RESTORE]   RESTORE COMPLETE")
    print("[RESTORE] ==========================================")
    print(f"Restored {restored} file(s) from {backup}")
    _log(body_root, "RESTORE", f"Restored {restored} file(s) from {backup.name}")
    if not dry_run:
        print(f"[RESTORE] Pre-restore backup: {pre_restore_dir}")
    return 0


def _prune_backups(backups_dir: Path, keep: int, *, dry_run: bool) -> int:
    print(f"[INFO] Pruning old backups (keeping last {keep})")
    backups = [path for path in sorted(backups_dir.iterdir()) if path.is_dir()] if backups_dir.exists() else []
    if len(backups) <= keep:
        print(f"[INFO] Only {len(backups)} backup(s) found, nothing to prune")
        return 0

    to_remove = backups[: len(backups) - keep]
    for backup in to_remove:
        if dry_run:
            print(f"[DRY-RUN] Would remove: {backup}")
            continue
        print(f"[WARN] Removing old backup: {backup.name}")
        shutil.rmtree(backup)

    if not dry_run:
        print(f"[INFO] Removed {len(to_remove)} old backup(s)")

    return 0


def _rotation_warning(backups_dir: Path) -> None:
    if not backups_dir.exists():
        return
    total_size = sum(path.stat().st_size for path in backups_dir.rglob("*") if path.is_file())
    if total_size > ROTATION_THRESHOLD_BYTES:
        print(
            f"[WARN] BACKUPS exceeds 10 GiB ({total_size} bytes). Consider running --prune.",
            file=sys.stderr,
        )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    epilog = """\
backup.py -- B.R.A. State Backup Manager

USAGE:
    backup.py                           Create timestamped backup
    backup.py --restore <backup>        Restore from backup directory
    backup.py --verify <backup>         Verify backup integrity
    backup.py --list                    List available backups
    backup.py --prune                   Remove old backups (keep last 5)
    backup.py --help                    Show this help

DESCRIPTION:
    Creates timestamped backups of B.R.A. state directories with
    manifest generation and integrity verification.

BACKUP TARGETS:
    - .bra/                     Agent configuration and state
    - layer3-engagement/NOTES/  Evidence and findings
    - layer3-engagement/OVERRIDES.md  Override audit trail

BACKUP STRUCTURE:
    BACKUPS/
    \u2514\u2500\u2500 YYYYMMDD_HHMMSS/
        \u251c\u2500\u2500 manifest.json                 SHA256 hashes of all files
        \u251c\u2500\u2500 .bra/                         Copy of .bra/
        \u251c\u2500\u2500 layer3-engagement/NOTES/      Copy of evidence
        \u2514\u2500\u2500 layer3-engagement/OVERRIDES.md

EXIT CODES:
    0 - Success
    1 - Error (missing directory, copy failed)
    2 - Verification failed (hash mismatch)

ROTATION:
    Warns when BACKUPS/ exceeds 10 GiB total size.
    Use --prune to remove old backups (keeps last 5).

EXAMPLES:
    # Create new backup
    ./backup.py
    # Creates: BACKUPS/20240115_143022/

    # List available backups
    ./backup.py --list

    # Verify backup integrity
    ./backup.py --verify BACKUPS/20240115_143022

    # Restore from backup
    ./backup.py --restore BACKUPS/20240115_143022

REFERENCED BY:
    - layer2-templates/backups.md
"""
    parser = argparse.ArgumentParser(
        description="Create, verify, list, prune, and restore BRA backups.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--list", "-l", action="store_true", help="List available backups.")
    action.add_argument("--verify", "-v", metavar="BACKUP", help="Verify backup integrity using manifest.json.")
    action.add_argument("--restore", "-r", metavar="BACKUP", help="Restore files from a backup directory.")
    action.add_argument("--prune", action="store_true", help="Prune old backups, keeping newest entries.")
    parser.add_argument("--keep", type=int, default=5, help="Backups to keep when using --prune (default: 5).")
    parser.add_argument("--name", help="Optional backup directory name for creation mode.")
    parser.add_argument("--dry-run", action="store_true", help="Preview operations without writing/deleting files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()
    backups_dir = body_root / "BACKUPS"
    backups_dir.mkdir(parents=True, exist_ok=True)

    _rotation_warning(backups_dir)

    _log(body_root, "INFO", f"backup.py invoked: {sys.argv[1:]}")

    if args.list:
        return _list_backups(backups_dir)
    if args.verify:
        return _verify_backup(backups_dir, args.verify)
    if args.restore:
        return _restore_backup(body_root, backups_dir, args.restore, dry_run=args.dry_run)
    if args.prune:
        if args.keep < 1:
            print("[ERROR] --keep must be >= 1", file=sys.stderr)
            return 1
        return _prune_backups(backups_dir, args.keep, dry_run=args.dry_run)

    return _create_backup(body_root, backups_dir, name=args.name, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
