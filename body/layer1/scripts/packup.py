#!/usr/bin/env python3
"""Native engagement archive creator."""

from __future__ import annotations

import argparse
import shutil
import tarfile
from datetime import datetime
from pathlib import Path

DENIED_SUFFIXES = {
    ".apk",
    ".aab",
    ".ipa",
    ".img",
    ".bin",
    ".rom",
    ".iso",
    ".qcow2",
    ".vmdk",
    ".vdi",
    ".elf",
    ".exe",
    ".dll",
    ".dylib",
    ".so",
    ".pcap",
    ".pcapng",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".jar",
    ".war",
    ".ear",
}


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


_HELP_TEXT = """\
packup.py — Engagement State Archiver

USAGE:
    packup.py                       Create archive with auto-generated name
    packup.py --output FILE.tar.gz  Specify output filename
    packup.py --dry-run             Show what would be included
    packup.py --minimal             Only essential state (no logs)
    packup.py --full                Include everything (logs, temp files)
    packup.py --list                List contents of existing archive
    packup.py --help                Show this help

DESCRIPTION:
    Packages project artifacts, findings, leads, and state into a portable
    tar.gz archive. The archive preserves the engagement state so testing
    can resume from the same point in an uncluttered project.

ARCHIVE CONTENTS:
    Default mode includes:
    - .bra/artifacts/      Phase artifacts and manifest
    - .bra/pipeline_state.json
    - .bra/hunt_state.json
    - .bra/improvement_state.json
    - .bra/approvals/      Active tokens
    - .bra/logs/           Audit logs (watch, track, audit)
    - layer3-engagement/                Instantiated engagement documents
    - layer3-engagement/NOTES/           Findings, leads, requirements
    - layer1/lib/            Custom libraries
    - Custom PoC directories (poc/, exploit/, payload/)

    Minimal mode (--minimal):
    - Excludes all logs
    - Excludes temporary work directories

    Full mode (--full):
    - Includes all .bra/ contents
    - Includes temporary files

EXCLUDES:
    - layer2-templates/  (use base repo for templates)
    - node_modules/, vendor/ (package dependencies)
    - .git/                  (version control)
    - Large binaries (apk, ipa, img, bin, pcap, etc.)
    - Existing packup archives

OUTPUT:
    Default: packup_YYYYMMDD_HHMMSS.tar.gz in project root
    Custom:  --output path/to/archive.tar.gz

EXAMPLES:
    # Create default archive
    python3 layer1/scripts/packup.py

    # Preview what will be included
    python3 layer1/scripts/packup.py --dry-run

    # Create minimal archive for transfer
    python3 layer1/scripts/packup.py --minimal --output engagement_state.tar.gz

    # Include everything
    python3 layer1/scripts/packup.py --full
"""


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="packup.py",
        description="Create a portable archive of engagement state.",
        epilog=_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", help="Output archive path (.tar.gz).")
    parser.add_argument("--dry-run", action="store_true", help="List files that would be archived.")
    parser.add_argument("--minimal", action="store_true", help="Exclude logs and temporary data.")
    parser.add_argument("--full", action="store_true", help="Include additional runtime folders when present.")
    parser.add_argument("--list", action="store_true", help="List contents of an existing archive from --output.")
    return parser.parse_args(argv)


def _include_roots(body_root: Path, *, minimal: bool, full: bool) -> list[Path]:
    paths: list[Path] = []
    for rel in (
        ".bra/pipeline_state.json",
        ".bra/hunt_state.json",
        ".bra/improvement_state.json",
        ".bra/artifacts",
        ".bra/approvals",
        "layer3-engagement/NOTES",
        "layer3-engagement/SCOPE.md",
        "layer3-engagement/ROE.md",
        "layer3-engagement/PLAN.md",
        "layer3-engagement/REPORT.md",
        "layer3-engagement/REVIEW.md",
        "layer3-engagement/RETRO.md",
        "layer3-engagement/README-PROJECTOVERVIEW.md",
        "layer3-engagement/TOOLSUITES.md",
        "layer3-engagement/SKILLSUITES.md",
        "layer3-engagement/BACKUPS.md",
        "layer3-engagement/VENDOR-SUBMISSION.md",
        "layer3-engagement/CNA-SUBMISSION.md",
        "layer3-engagement/DISCLOSURE-PACKAGE.md",
        "layer3-engagement/LESSONS-LEARNED.md",
        "layer3-engagement/STATS.md",
        "layer3-engagement/IMPROVEMENTS.md",
        "layer3-engagement/OVERRIDES.md",
        "layer3-engagement/SCRIPTS-AUDIT-REPORT.md",
        "layer3-engagement/README.md",
        "layer3-engagement/disclosure",
        "layer3-engagement/pitches",
        "layer1/lib",
        "poc",
        "exploit",
        "exploits",
        "payload",
        "payloads",
        "tools",
    ):
        candidate = body_root / rel
        if candidate.exists():
            paths.append(candidate)

    if full:
        # Full mode: include entire logs directory
        logs = body_root / ".bra" / "logs"
        if logs.exists():
            paths.append(logs)
    elif not minimal:
        # Default mode: include only audit-related logs
        for log_name in ("watch.log", "track.log", "audit.log", "ci.log", "danger_check.log"):
            log_path = body_root / ".bra" / "logs" / log_name
            if log_path.is_file():
                paths.append(log_path)
    # Minimal mode: no logs at all

    if full:
        for rel in (".bra/specs", "layer3-engagement/ingest"):
            candidate = body_root / rel
            if candidate.exists():
                paths.append(candidate)
    return paths


def _is_excluded(path: Path, *, body_root: Path) -> bool:
    rel = path.relative_to(body_root)
    rel_str = str(rel)
    name = path.name

    if ".git" in rel.parts or "node_modules" in rel.parts or "vendor" in rel.parts or "layer2-templates" in rel.parts:
        return True
    if "__pycache__" in rel.parts:
        return True
    if name.endswith(".pyc") or name in {".DS_Store", "Thumbs.db"}:
        return True
    if name.startswith("packup_") and name.endswith(".tar.gz"):
        return True
    if path.is_file() and path.suffix.lower() in DENIED_SUFFIXES:
        return True
    if rel_str.startswith("BACKUPS/"):
        return True
    return False


def _walk_files(base: Path) -> list[Path]:
    if base.is_file():
        return [base]
    if not base.exists():
        return []
    return sorted(path for path in base.rglob("*") if path.is_file())


def _collect_files(body_root: Path, *, minimal: bool, full: bool) -> list[Path]:
    files: list[Path] = []
    for root in _include_roots(body_root, minimal=minimal, full=full):
        files.extend(_walk_files(root))

    seen: set[Path] = set()
    unique: list[Path] = []
    for file_path in files:
        if file_path in seen:
            continue
        seen.add(file_path)
        if _is_excluded(file_path, body_root=body_root):
            continue
        unique.append(file_path)
    return sorted(unique)


def _archive_output(body_root: Path, output_arg: str | None) -> Path:
    if output_arg:
        output = Path(output_arg)
        if not output.is_absolute():
            output = body_root / output
        return output
    return body_root / f"packup_{_timestamp()}.tar.gz"


def _create_archive(output: Path, body_root: Path, files: list[Path]) -> None:
    import tempfile as _tf
    output.parent.mkdir(parents=True, exist_ok=True)

    # Generate manifest
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = f"# Packup Manifest\n# Generated: {now}\n# Files: {len(files)}\n\n"
    for f in files:
        manifest += f"- {f.relative_to(body_root)}\n"

    with tarfile.open(output, mode="w:gz") as tf:
        for file_path in files:
            tf.add(file_path, arcname=str(file_path.relative_to(body_root)), recursive=False)

        # Add manifest
        with _tf.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as tmp:
            tmp.write(manifest)
            tmp_path = Path(tmp.name)
        tf.add(tmp_path, arcname=".packup/MANIFEST.md")
        tmp_path.unlink(missing_ok=True)

        # Add packed-at timestamp
        with _tf.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(now + "\n")
            tmp_path = Path(tmp.name)
        tf.add(tmp_path, arcname=".packup/PACKED_AT")
        tmp_path.unlink(missing_ok=True)


def _list_archive(path: Path) -> int:
    if not path.exists():
        print(f"[ERROR] archive not found: {path}")
        return 1
    with tarfile.open(path, mode="r:gz") as tf:
        for member in tf.getmembers():
            print(member.name)
    return 0


def _get_claude_temp_dir(body_root: Path) -> Path:
    """Get the Claude Code temp directory for this project."""
    encoded = str(body_root).replace("/", "-")
    return Path("/private/tmp/claude") / encoded


def _check_claude_temp(body_root: Path) -> None:
    """Check for Claude Code temp files that may contain engagement data."""
    claude_temp = _get_claude_temp_dir(body_root)
    if not claude_temp.is_dir():
        return

    temp_files = list(claude_temp.rglob("*"))
    temp_file_count = sum(1 for f in temp_files if f.is_file())
    if temp_file_count == 0:
        return

    print()
    print("═══════════════════════════════════════════════════════════════")
    print("  CLAUDE CODE TEMP FILES DETECTED")
    print("═══════════════════════════════════════════════════════════════")
    print()
    print(f"Found {temp_file_count} file(s) in Claude Code temp directory:")
    print(f"  {claude_temp}")
    print()
    print("These may contain engagement data from background tasks.")
    print()
    print("Options:")
    print("  1. Include in archive (copy to .bra/artifacts/claude-temp/)")
    print("  2. Delete (clean up)")
    print("  3. Skip (leave as-is, may leak data)")
    print()

    try:
        choice = input("Choice [1/2/3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "3"

    if choice == "1":
        dest_dir = body_root / ".bra" / "artifacts" / "claude-temp"
        dest_dir.mkdir(parents=True, exist_ok=True)
        for item in claude_temp.iterdir():
            target = dest_dir / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            elif item.is_file():
                shutil.copy2(item, target)
        print("[CAPTURED] Copied to .bra/artifacts/claude-temp/")
    elif choice == "2":
        shutil.rmtree(claude_temp, ignore_errors=True)
        print(f"[CLEANED] Deleted {claude_temp}")
    elif choice == "3":
        print("[SKIPPED] Files remain in temp directory")
    else:
        print("[SKIPPED] Invalid choice, files remain")
    print()


def main(argv: list[str] | None = None) -> int:
    import sys

    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _detect_body_root(Path(__file__).resolve())
    output = _archive_output(body_root, args.output)

    if args.list:
        return _list_archive(output)

    # Check for Claude Code temp files before archiving
    if not args.dry_run:
        _check_claude_temp(body_root)

    files = _collect_files(body_root, minimal=args.minimal, full=args.full)

    if args.dry_run:
        print()
        print("═══ PACKUP DRY RUN ═══")
        print()
        for file_path in files:
            print(f"- {file_path.relative_to(body_root)}")
        print(f"Total files: {len(files)}")
        return 0

    try:
        _create_archive(output, body_root, files)
    except OSError as exc:
        print(f"packup.py failed: {exc}")
        return 1

    size_kb = output.stat().st_size // 1024
    print()
    print("[INFO] Archive created successfully!")
    print()
    print("Archive Details:")
    print(f"  File: {output}")
    print(f"  Size: {size_kb}KB")
    print(f"  Items: {len(files)}")
    print()
    print("To extract:")
    print(f"  tar -xzf {output}")
    print()
    print("To list contents:")
    print(f"  tar -tzf {output}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
