#!/usr/bin/env python3
"""Native backup restore utility with archive safety checks."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import os
from pathlib import Path
import tarfile
import sys


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _append_log(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] [{level}] {message}\n")


def _list_archives(backups_dir: Path) -> list[Path]:
    if not backups_dir.is_dir():
        return []
    return sorted((p for p in backups_dir.glob("*.tar.gz") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)


def _resolve_archive(backups_dir: Path, archive: str | None, latest: bool) -> Path | None:
    if latest:
        archives = _list_archives(backups_dir)
        return archives[0] if archives else None

    if not archive:
        return None

    path = Path(archive).expanduser()
    if path.is_absolute():
        return path
    candidate = backups_dir / path
    if candidate.exists():
        return candidate
    return path


def _preview_archive(archive_path: Path) -> int:
    if not archive_path.is_file():
        print(f"Archive not found: {archive_path}", file=sys.stderr)
        return 2

    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            members = tar.getmembers()

            print()
            print("═══ ARCHIVE PREVIEW ═══")
            print()
            print(f"Archive: {archive_path.name}")
            size_kb = archive_path.stat().st_size // 1024
            print(f"Size: {size_kb}KB")
            print()

            # Check for manifest
            manifest_names = [m.name for m in members if "MANIFEST" in m.name]
            if manifest_names:
                try:
                    f = tar.extractfile(manifest_names[0])
                    if f:
                        print("Manifest:")
                        print(f.read().decode("utf-8", errors="replace"))
                        print()
                except (KeyError, OSError):
                    pass

            print("Contents:")
            print()

            total = len(members)
            for member in members[:50]:
                print(f"  {member.name}")

            if total > 50:
                print()
                print(f"... and {total - 50} more entries")

            print()
            print(f"Total entries: {total}")
            print()
    except tarfile.TarError as exc:
        print(f"Invalid archive: {exc}", file=sys.stderr)
        return 1

    return 0


def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    root = destination.resolve()
    for member in tar.getmembers():
        member_path = destination / member.name
        resolved = member_path.resolve()
        if not str(resolved).startswith(str(root) + os.sep) and resolved != root:
            raise ValueError(f"Unsafe path in archive: {member.name}")
    tar.extractall(path=destination)


def _validate_gzip(archive_path: Path) -> bool:
    """Validate gzip integrity by reading through the entire archive."""
    import gzip
    try:
        with gzip.open(archive_path, "rb") as f:
            while f.read(65536):
                pass
        return True
    except (gzip.BadGzipFile, OSError):
        return False


def _restore_archive(body_root: Path, archive_path: Path, force: bool, log_file: Path) -> int:
    if not archive_path.is_file():
        print(f"Archive not found: {archive_path}", file=sys.stderr)
        return 2

    # Validate gzip integrity
    if not _validate_gzip(archive_path):
        print(f"Archive integrity check FAILED: {archive_path}", file=sys.stderr)
        return 1

    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            members = tar.getmembers()
            # Show manifest if present
            manifest_names = [m.name for m in members if "MANIFEST" in m.name]
            if manifest_names:
                try:
                    manifest_member = tar.getmember(manifest_names[0])
                    f = tar.extractfile(manifest_member)
                    if f:
                        print("Archive manifest:")
                        print(f.read().decode("utf-8", errors="replace"))
                        print()
                except (KeyError, OSError):
                    pass
    except tarfile.TarError as exc:
        print(f"Archive read failed: {exc}", file=sys.stderr)
        return 1

    size_kb = archive_path.stat().st_size // 1024
    entry_count = len(members)

    if not force:
        print()
        print("\u2554" + "\u2550" * 64 + "\u2557")
        print("\u2551" + "                    RESTORE CONFIRMATION".ljust(64) + "\u2551")
        print("\u255a" + "\u2550" * 64 + "\u255d")
        print()
        print(f"Archive: {archive_path.name}")
        print(f"Size: {size_kb}KB")
        print()
        print(f"This will restore {entry_count} files/directories.")
        print()
        print("WARNING: Existing files will be overwritten!")
        print()

        if not sys.stdin.isatty():
            print("Refusing interactive restore in non-interactive mode. Use --force.", file=sys.stderr)
            return 1
        try:
            answer = input("Type 'RESTORE' to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nRestore cancelled.")
            return 1
        if answer != "RESTORE":
            print("Restore cancelled.")
            return 1

    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            _safe_extract(tar, body_root)
    except (tarfile.TarError, ValueError) as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 1

    _append_log(log_file, "INFO", f"Restored archive {archive_path}")

    print()
    print("═══ RESTORING ═══")
    print()
    print(f"Archive: {archive_path.name}")
    print()
    print("Restore complete!")
    print()
    print("Restored:")
    print(f"  Files/directories: {entry_count}")
    print()

    # Show key items restored
    try:
        with tarfile.open(archive_path, mode="r:gz") as tar2:
            key_items = [m.name for m in tar2.getmembers()
                         if m.name.startswith(".bra/") or m.name.startswith("layer3-engagement/")]
            if key_items:
                print("Key items restored:")
                for item in key_items[:10]:
                    print(f"  {item}")
                print()
    except tarfile.TarError:
        pass

    print("Next steps:")
    print("  1. Run ./layer1/scripts/status.py to verify state")
    print("  2. Run ./layer1/scripts/precheck.py to validate environment")
    print("  3. Run ./layer1/scripts/audit.py to verify artifacts")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    epilog = """\
restore.py -- Restore from Backup Archive

USAGE:
    restore.py                          List available backups
    restore.py <archive>                Restore from specific archive
    restore.py --latest                 Restore from most recent backup
    restore.py --preview <archive>      Preview contents without extracting
    restore.py --force                  Skip confirmation prompt
    restore.py --help                   Show this help

DESCRIPTION:
    Restores project state from a backup archive created by packup.py
    or reset.py. Lists available backups if no archive specified.

SUPPORTED ARCHIVES:
    - packup_*.tar.gz     Created by packup.py for transfer/resumption
    - reset_backup_*.tar.gz  Created by reset.py before project reset

RESTORE BEHAVIOR:
    - Extracts archive contents to project root
    - Overwrites existing files with archived versions
    - Does NOT delete files that aren't in the archive
    - Preserves file permissions from archive

SAFETY:
    - Validates archive integrity before extraction
    - Prompts for confirmation (use --force to skip)
    - Shows preview of what will be restored

EXAMPLES:
    # List all available backups
    ./layer1/scripts/restore.py

    # Preview an archive's contents
    ./layer1/scripts/restore.py --preview BACKUPS/packup_20260124.tar.gz

    # Restore from specific archive
    ./layer1/scripts/restore.py BACKUPS/reset_backup_20260124_120000.tar.gz

    # Restore from most recent backup
    ./layer1/scripts/restore.py --latest

    # Restore without confirmation (for automation)
    ./layer1/scripts/restore.py --latest --force
"""
    parser = argparse.ArgumentParser(
        description="Restore body workspace from BACKUPS archive.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("archive", nargs="?", help="Archive path to restore")
    parser.add_argument("--latest", action="store_true", help="Restore from the newest BACKUPS/*.tar.gz")
    parser.add_argument("--preview", metavar="ARCHIVE", help="Preview archive contents without extraction")
    parser.add_argument("--force", action="store_true", help="Skip restore confirmation prompt")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))
    backups_dir = body_root / "BACKUPS"
    log_file = body_root / ".bra" / "logs" / "restore.log"

    if args.preview:
        preview_path = _resolve_archive(backups_dir, args.preview, latest=False)
        if preview_path is None:
            print("No archive provided for --preview", file=sys.stderr)
            return 1
        return _preview_archive(preview_path)

    if args.archive is None and not args.latest:
        archives = _list_archives(backups_dir)
        # Also check project root for packup archives
        project_root = body_root.parent
        packups = sorted(project_root.glob("packup_*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        all_archives = list(archives) + [p for p in packups if p not in archives]

        print()
        print("═══ AVAILABLE BACKUPS ═══")
        print()

        if not backups_dir.is_dir() and not packups:
            print("No BACKUPS directory found.")
            print()
            print("Backups are created by:")
            print("  - packup.py  -> packup_*.tar.gz")
            print("  - reset.py   -> reset_backup_*.tar.gz (in BACKUPS/)")
            print()
            return 1

        if not all_archives:
            print("No backup archives found.")
            print()
            return 1

        print(f"Found {len(all_archives)} backup(s):")
        print()

        for idx, archive in enumerate(all_archives, 1):
            size_kb = archive.stat().st_size // 1024
            stamp = datetime.fromtimestamp(archive.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            # Detect type from filename
            if "reset_" in archive.name:
                atype = "reset"
            elif "packup_" in archive.name:
                atype = "packup"
            else:
                atype = "other"
            print(f"  {idx:2d}. {archive.name:<45s} {size_kb:>6d}KB  {stamp}  [{atype}]")

        print()
        print("To restore: ./layer1/scripts/restore.py <archive-path>")
        print("To preview: ./layer1/scripts/restore.py --preview <archive-path>")
        print()
        return 0

    archive_path = _resolve_archive(backups_dir, args.archive, latest=args.latest)
    if archive_path is None or (archive_path is not None and not archive_path.is_file()):
        if args.latest:
            print("No backup archives available.", file=sys.stderr)
        else:
            project_root = body_root.parent
            print(f"Archive not found: {args.archive}", file=sys.stderr)
            print()
            print("Searched in:")
            print(f"  - {args.archive}")
            print(f"  - {backups_dir / args.archive}")
            print(f"  - {project_root / args.archive}")
            print()
            print("Run './layer1/scripts/restore.py' to list available backups.")
        return 2

    return _restore_archive(body_root, archive_path, force=args.force, log_file=log_file)


if __name__ == "__main__":
    raise SystemExit(main())
