#!/usr/bin/env python3
"""Native project reset utility for BRA engagement runtime.

Archives all engagement artifacts and resets project to default
pre-engagement state for a fresh start.

DANGER: This is a destructive operation. Use with caution.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ============== KILL SWITCH ==============

def _check_killswitch(body_root: Path) -> bool:
    """Return True if kill switch is STOP (halt all operations)."""
    claude_md = body_root / "CLAUDE.md"
    if claude_md.is_file():
        text = _read_text(claude_md)
        match = re.search(
            r"##\s*Kill\s*Switch\s*\n+```\s*\n\s*(STOP|CLEAR)\s*\n```",
            text, re.IGNORECASE,
        )
        if match and match.group(1).upper() == "STOP":
            return True
    stop_file = body_root / ".bra" / "STOP"
    if stop_file.is_file():
        return True
    if os.environ.get("BRA_STOP") == "1":
        return True
    return False


# ============== DESTRUCTIVE APPROVAL ==============

def _has_destructive_approval(body_root: Path) -> bool:
    """Check DESTRUCTIVE-APPROVAL token via env, file, or ROE.md."""
    if os.environ.get("DESTRUCTIVE_APPROVAL") == "1":
        return True
    approval_file = body_root / ".bra" / "approvals" / "DESTRUCTIVE-APPROVAL"
    if approval_file.is_file():
        return True
    roe_file = body_root / "layer3-engagement" / "ROE.md"
    if roe_file.is_file():
        text = _read_text(roe_file)
        if re.search(r"DESTRUCTIVE-APPROVAL:\s*GRANTED", text, re.IGNORECASE):
            return True
    return False


# ============== ARCHIVE ==============

_CORE_SCRIPTS = {
    "agentic-handler", "approval-gate", "approve-target",
    "audit", "backup", "battlestations", "bra",
    "danger_check", "dedupe-integrated", "deploy", "disclose",
    "dry-run", "generate-docs", "growth", "hunt",
    "ingest", "integrate-ingest", "leads", "lessons-learned", "notes_guard",
    "offensive_gate", "packup", "precheck", "prep-deploy",
    "ref_harvest", "remote-ingest", "report-ready", "reset", "restore",
    "run-tests", "scope-intake", "self-improvement", "stats",
    "status", "validate-mappings",
}

_LAYER3_ROOT_DOCS = [
    "SCOPE.md", "ROE.md", "PLAN.md", "REPORT.md", "REVIEW.md", "RETRO.md",
    "README-PROJECTOVERVIEW.md", "TOOLSUITES.md", "SKILLSUITES.md",
    "BACKUPS.md", "CNA-SUBMISSION.md", "DISCLOSURE-PACKAGE.md",
    "VENDOR-SUBMISSION.md", "LESSONS-LEARNED.md", "STATS.md",
    "IMPROVEMENTS.md", "README.md", "SCRIPTS-AUDIT-REPORT.md",
    "OVERRIDES.md",
]


def _build_reset_list(body_root: Path) -> list[Path]:
    """Build list of items to archive and reset."""
    items: list[Path] = []

    bra = body_root / ".bra"
    if bra.exists():
        items.append(bra)

    notes = body_root / "layer3-engagement" / "NOTES"
    if notes.exists():
        items.append(notes)

    layer3 = body_root / "layer3-engagement"
    for doc in _LAYER3_ROOT_DOCS:
        path = layer3 / doc
        if path.is_file():
            items.append(path)

    for subdir in ("disclosure", "pitches", "ingest"):
        path = layer3 / subdir
        if path.is_dir():
            items.append(path)

    for custom in ("poc", "exploit", "exploits", "payload", "payloads", "tools", "output", "OUTPUT"):
        path = body_root / custom
        if path.exists():
            items.append(path)

    # Custom scripts (not core)
    scripts_dir = body_root / "layer1" / "scripts"
    if scripts_dir.is_dir():
        for script in sorted(scripts_dir.glob("*.sh")):
            if script.stem not in _CORE_SCRIPTS:
                items.append(script)

    return items


def _calculate_impact(body_root: Path, items: list[Path]) -> tuple[int, int, int]:
    """Return (total_kb, file_count, dir_count)."""
    total_size = 0
    file_count = 0
    dir_count = 0
    for item in items:
        if not item.exists():
            continue
        if item.is_dir():
            dir_count += 1
            for f in item.rglob("*"):
                if f.is_file():
                    file_count += 1
                    try:
                        total_size += f.stat().st_size
                    except OSError:
                        pass
        else:
            file_count += 1
            try:
                total_size += item.stat().st_size
            except OSError:
                pass
    return (total_size // 1024, file_count, dir_count)


def _create_archive(body_root: Path, items: list[Path]) -> Path | None:
    if not items:
        return None

    backup_dir = body_root / "BACKUPS"
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / f"reset_backup_{_timestamp()}.tar.gz"

    # Create manifest
    manifest_content = (
        f"# Reset Backup Manifest\n"
        f"# Generated: {_utc_now()}\n"
        f"# Project: {body_root}\n\n"
        f"## Archived Items:\n"
    )
    for item in items:
        try:
            manifest_content += f"- {item.relative_to(body_root)}\n"
        except ValueError:
            manifest_content += f"- {item}\n"
    manifest_content += f"\n## Reset performed by: reset.py\n"

    with tarfile.open(archive, mode="w:gz") as tf:
        for path in items:
            if path.exists():
                try:
                    arcname = str(path.relative_to(body_root))
                except ValueError:
                    arcname = path.name
                tf.add(path, arcname=arcname, recursive=True)

        # Add manifest
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as tmp:
            tmp.write(manifest_content)
            tmp_path = Path(tmp.name)
        tf.add(tmp_path, arcname=".reset_manifest/MANIFEST.md")
        tmp_path.unlink(missing_ok=True)

        # Add timestamp
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(_utc_now() + "\n")
            tmp_path = Path(tmp.name)
        tf.add(tmp_path, arcname=".reset_manifest/RESET_AT")
        tmp_path.unlink(missing_ok=True)

    return archive


# ============== RESET OPERATIONS ==============

_NOTES_STUBS: dict[str, str] = {
    "FINDINGS.md": "# Findings\n\n> Document findings here during engagement.\n\n---\n\n",
    "LEADS.md": "# Leads\n\n> Track investigation leads here.\n\n---\n\n",
    "INTEL.md": "# Intelligence Notes\n\n> Document intelligence findings here.\n\n---\n\n",
    "EXECUTIVE_SUMMARY.md": "# Executive Summary\n\n> High-level summary for stakeholders.\n\n---\n\n",
    "SESSION.md": "# Session Log\n\n> Session notes will be recorded here.\n\n---\n\n",
}


def _reset_notes(body_root: Path) -> None:
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    if not notes_dir.exists():
        return

    for name, stub in _NOTES_STUBS.items():
        path = notes_dir / name
        if path.is_file():
            path.write_text(stub, encoding="utf-8")

    # Clear refmap but keep structure
    refmap = notes_dir / "reqs" / "_refmap.csv"
    if refmap.is_file():
        refmap.write_text("ref_id,source,description\n", encoding="utf-8")

    # Remove non-baseline files in reqs/
    reqs_dir = notes_dir / "reqs"
    if reqs_dir.is_dir():
        for item in reqs_dir.iterdir():
            if item.is_file() and item.name not in (".gitkeep", "_refmap.csv"):
                item.unlink(missing_ok=True)
            elif item.is_dir() and item.name != "reqfiles":
                shutil.rmtree(item, ignore_errors=True)

    # Clean reqfiles (keep .gitkeep)
    reqfiles = reqs_dir / "reqfiles" if reqs_dir.is_dir() else None
    if reqfiles and reqfiles.is_dir():
        for item in reqfiles.iterdir():
            if item.is_file() and item.name != ".gitkeep":
                item.unlink(missing_ok=True)

    # Remove IntelWriter dedup state
    seen = notes_dir / ".seen_entries.txt"
    seen.unlink(missing_ok=True)


_LAYER3_SKELETONS: dict[str, str] = {
    "SCOPE.md": "# Scope (Instance)\n\n> Populate from scope-intake.md template.\n",
    "ROE.md": "# ROE (Instance)\n\n> Populate from scope-intake.md template.\n",
    "PLAN.md": "# Plan (Instance)\n\n> Populate during planning phase.\n",
    "REPORT.md": "# Report (Instance)\n\n> Generate using /report-ready command.\n",
    "REVIEW.md": "# Review (Instance)\n\n> Populate during review phase.\n",
    "RETRO.md": "# Retrospective (Instance)\n\n> Generate using retro.sh script.\n",
    "README-PROJECTOVERVIEW.md": "# Project Overview (Instance)\n\n> Populate during scope intake.\n",
    "TOOLSUITES.md": "# Tool Suites (Instance)\n\n> Document tools used in engagement.\n",
    "SKILLSUITES.md": "# Skill Suites (Instance)\n\n> Document skills applied in engagement.\n",
    "BACKUPS.md": "# Backups (Instance)\n\n> Document backup procedures.\n",
    "CNA-SUBMISSION.md": "# CNA Submission (Instance)\n\n> Populate for CVE submission.\n",
    "DISCLOSURE-PACKAGE.md": "# Disclosure Package (Instance)\n\n> Populate for vendor disclosure.\n",
    "VENDOR-SUBMISSION.md": "# Vendor Submission (Instance)\n\n> Populate for vendor notification.\n",
}

_OVERRIDES_SKELETON = """\
# Override Recommendations

> Cross-engagement advisory overrides. Promoted from engagement pitch docs.
> These are recommendations only — never auto-materialized into `.bra/overrides.json`.

---

## Recommended Overrides

<!-- FORMAT:
### [TYPE] match_key=match_value
- **Rationale:** Why this override is recommended
- **Engagements:** Number of engagements where this was used
- **Action:** grant_session | allow | FULL | LIMITED
-->

---

## Engagement Decisions

<!-- Populated during engagement by engage.py -->
<!-- Each decision is appended as it occurs -->
"""


def _reset_layer3_engagement(body_root: Path) -> None:
    layer3 = body_root / "layer3-engagement"
    if not layer3.is_dir():
        return

    # Reset instance docs to skeletons
    for name, content in _LAYER3_SKELETONS.items():
        path = layer3 / name
        if path.is_file():
            path.write_text(content, encoding="utf-8")

    # Reset OVERRIDES.md from template or skeleton
    overrides_template = body_root / "layer2-templates" / "overrides.md"
    overrides_target = layer3 / "OVERRIDES.md"
    if overrides_template.is_file():
        shutil.copy2(overrides_template, overrides_target)
    elif overrides_target.is_file():
        overrides_target.write_text(_OVERRIDES_SKELETON, encoding="utf-8")

    # Clear disclosure, pitches, ingest directory contents
    for subdir in ("disclosure", "pitches"):
        path = layer3 / subdir
        if path.is_dir():
            for item in path.iterdir():
                if item.is_file():
                    item.unlink(missing_ok=True)
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)

    if (layer3 / "ingest").is_dir():
        for item in (layer3 / "ingest").iterdir():
            if item.is_file():
                item.unlink(missing_ok=True)
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)

    # Remove script-generated files
    for name in ("STATS.md", "IMPROVEMENTS.md", "LESSONS-LEARNED.md", "README.md", "SCRIPTS-AUDIT-REPORT.md"):
        path = layer3 / name
        if path.is_file():
            path.unlink(missing_ok=True)


def _reset_bra(body_root: Path) -> None:
    bra = body_root / ".bra"
    if bra.is_dir():
        shutil.rmtree(bra)

    # Remove orphaned .bra inside layer3-engagement
    orphan = body_root / "layer3-engagement" / ".bra"
    if orphan.is_dir():
        shutil.rmtree(orphan)

    # Remove rogue findings directory
    rogue = body_root / "layer3-engagement" / "findings"
    if rogue.is_dir():
        shutil.rmtree(rogue)

    # Recreate baseline BRA runtime structure expected by precheck/audit.
    for rel in (
        "artifacts",
        "artifacts/raw",
        "artifacts/intel_work",
        "artifacts/static_work",
        "artifacts/dynamic_work",
        "artifacts/report_work",
        "logs",
        "approvals",
        "one-time-approvals",
        "phase_state",
        "specs",
        "snapshots",
        "tmp",
        "config",
        "improvements",
        "locks",
        "dry-run",
        "ui",
    ):
        (bra / rel).mkdir(parents=True, exist_ok=True)


def _reset_custom_dirs(body_root: Path) -> None:
    for name in ("poc", "exploit", "exploits", "payload", "payloads", "tools", "output", "OUTPUT"):
        path = body_root / name
        if path.is_dir():
            shutil.rmtree(path)


def _reset_custom_scripts(body_root: Path) -> None:
    scripts_dir = body_root / "layer1" / "scripts"
    if not scripts_dir.is_dir():
        return
    for script in scripts_dir.glob("*.sh"):
        if script.stem not in _CORE_SCRIPTS:
            script.unlink(missing_ok=True)


def _reset_claude_temp(body_root: Path) -> str | None:
    """Remove Claude Code temp files for this project."""
    encoded = str(body_root).replace("/", "-")
    claude_temp = Path("/private/tmp/claude") / encoded
    if claude_temp.is_dir():
        count = sum(1 for f in claude_temp.rglob("*") if f.is_file())
        shutil.rmtree(claude_temp, ignore_errors=True)
        return f"Cleaned Claude Code temp: {claude_temp} ({count} files)"
    return None


# ============== DRY RUN ==============

def _dry_run(body_root: Path, items: list[Path]) -> int:
    print("\n═══ RESET DRY RUN ═══")
    print(f"Project: {body_root}\n")
    print("Items to be ARCHIVED and REMOVED:")

    for item in items:
        if not item.exists():
            continue
        try:
            rel = item.relative_to(body_root)
        except ValueError:
            rel = item
        if item.is_dir():
            count = sum(1 for f in item.rglob("*") if f.is_file())
            print(f"  [DEL DIR]  {rel} ({count} files)")
        else:
            size = item.stat().st_size
            print(f"  [DEL FILE] {rel} ({size} bytes)")

    print("\nItems that will be PRESERVED:")
    print("  [KEEP] layer1/rules/          (governance rules)")
    print("  [KEEP] layer2-templates/      (templates)")
    print("  [KEEP] layer3-engagement/ingest/")
    print("  [KEEP] layer1/scripts/*.py    (core scripts)")
    print("  [KEEP] layer1/lib/            (script libraries)")
    print("  [KEEP] bra-gui/               (GUI components)")
    print("  [KEEP] plans/                 (planning documents)")
    print("  [KEEP] tests/                 (test files)")
    print("  [KEEP] .claude/               (Claude Code config)")
    print("  [KEEP] BACKUPS/               (backup archives)")
    print("  [KEEP] CLAUDE.md, README.md   (root documentation)")

    print("\nPost-reset structure:")
    print("  layer3-engagement/NOTES/FINDINGS.md  -> Empty stub")
    print("  layer3-engagement/NOTES/LEADS.md     -> Empty stub")
    print("  layer3-engagement/NOTES/INTEL.md     -> Empty stub")
    print("  layer3-engagement/NOTES/SESSION.md   -> Empty stub")
    print("  layer3-engagement/*.md               -> Skeleton templates")
    print("  .bra/                                -> Removed entirely")

    total_kb, file_count, dir_count = _calculate_impact(body_root, items)
    print(f"\nImpact Summary:")
    print(f"  Directories: {dir_count}")
    print(f"  Files: {file_count}")
    print(f"  Total size: ~{total_kb}KB")
    print(f"  Backup would be: BACKUPS/reset_backup_{_timestamp()}.tar.gz\n")
    return 2


# ============== MAIN ==============

def _parse_args(argv: list[str]) -> argparse.Namespace:
    epilog = """\
reset.py — Project State Reset

USAGE:
    reset.py                        Interactive reset with confirmation
    reset.py --dry-run              Show what would be reset (no changes)
    reset.py --force                Skip confirmation prompt
    reset.py --keep-archive         Keep backup archive after reset (default)
    reset.py --no-keep-archive      Delete backup archive after successful reset
    reset.py --archive-only         Create archive but don't reset
    reset.py --help                 Show this help

DESCRIPTION:
    Archives all engagement artifacts and resets the project to its default
    pre-engagement state. This allows starting fresh while preserving a
    complete backup of all work done.

    DANGER: This is a destructive operation that will remove:
    - All pipeline state and artifacts
    - All logs and approvals
    - All findings and leads content
    - All instantiated engagement documents
    - Custom PoC/exploit directories

BACKUP:
    Before any deletion, creates a comprehensive backup archive at:
    BACKUPS/reset_backup_YYYYMMDD_HHMMSS.tar.gz

    The backup includes EVERYTHING that will be removed, so the
    engagement can be fully restored if needed.

WHAT GETS RESET:
    .bra/                              Completely removed
    layer3-engagement/NOTES/*.md       Content cleared, files kept as stubs
    layer3-engagement/*.md             Reset to skeleton templates
    poc/, exploit/, tools/  Completely removed
    Custom scripts          Removed (layer1/lib/ preserved)

WHAT STAYS:
    CLAUDE.md, tokens.md, scope.md, roe.md (root templates)
    layer2-templates/   Template files
    layer1/scripts/*.py     Core scripts
    BACKUPS/                Backup archives

EXAMPLES:
    # Preview what will be reset
    ./layer1/scripts/reset.py --dry-run

    # Reset with confirmation
    ./layer1/scripts/reset.py

    # Reset without prompts (CI/automation)
    ./layer1/scripts/reset.py --force

    # Just create backup, don't reset
    ./layer1/scripts/reset.py --archive-only
"""
    parser = argparse.ArgumentParser(
        prog="reset.py",
        description="Archive runtime artifacts and reset engagement state.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="Print what would be reset, no changes.")
    parser.add_argument("--force", action="store_true", help="Perform reset without interactive prompt.")
    parser.add_argument("--archive-only", action="store_true", help="Create backup archive only.")
    parser.add_argument(
        "--keep-archive",
        action="store_true",
        default=True,
        help="Keep generated backup archive (default behavior).",
    )
    parser.add_argument("--no-keep-archive", action="store_true", help="Delete backup archive after reset.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _detect_body_root(Path(__file__).resolve())
    items = _build_reset_list(body_root)

    # Kill switch check
    if _check_killswitch(body_root):
        print("STOP: Kill switch is active. All operations halted.", file=sys.stderr)
        return 99

    # Dry run (no approval needed)
    if args.dry_run:
        return _dry_run(body_root, items)

    # Archive only (no approval needed)
    if args.archive_only:
        print()
        print("═══ ARCHIVE ONLY ═══")
        print()
        archive = _create_archive(body_root, items)
        if archive is not None:
            print(f"[INFO] archive created: {archive}")
        else:
            print("[INFO] no reset candidates found; nothing archived")
        return 0

    # DESTRUCTIVE-APPROVAL token required for actual reset
    if not _has_destructive_approval(body_root):
        print(
            "DESTRUCTIVE-APPROVAL TOKEN REQUIRED\n\n"
            "Reset is a destructive operation that requires explicit approval.\n\n"
            "To approve, provide token via ONE of:\n"
            "  1. Environment: DESTRUCTIVE_APPROVAL=1 python3 reset.py --force\n"
            "  2. File: touch .bra/approvals/DESTRUCTIVE-APPROVAL\n"
            "  3. ROE.md: Add 'DESTRUCTIVE-APPROVAL: GRANTED'\n\n"
            "For preview only (no approval needed):\n"
            "  python3 reset.py --dry-run",
            file=sys.stderr,
        )
        return 1

    # Interactive confirmation unless --force
    if not args.force:
        print()
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║                    WARNING: DESTRUCTIVE ACTION                ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print()
        print("This will:")
        print("  1. Archive ALL engagement data to BACKUPS/")
        print("  2. REMOVE .bra/ (state, artifacts, logs)")
        print("  3. CLEAR layer3-engagement/NOTES/ content")
        print("  4. RESET layer3-engagement/*.md to skeletons")
        print("  5. REMOVE custom directories (poc/, exploit/, etc.)")

        _, file_count, _ = _calculate_impact(body_root, items)
        print(f"\n  {file_count} files will be affected\n")

        try:
            confirmation = input("Type 'RESET' to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nReset cancelled")
            return 1

        if confirmation != "RESET":
            print("Reset cancelled")
            return 1

    # PROJECT RESET banner
    print()
    print("═══ PROJECT RESET ═══")
    print()
    print(f"Project: {body_root}")
    print(f"Timestamp: {_utc_now()}")
    print()

    # Step 1: Create backup
    print("Step 1: Creating backup archive")
    archive = _create_archive(body_root, items)
    if archive is not None:
        size_kb = archive.stat().st_size // 1024
        print(f"[INFO] Backup created: {archive} ({size_kb}KB)")

    print()
    print("Step 2: Performing reset")

    # Perform reset
    try:
        _reset_bra(body_root)
        _reset_notes(body_root)
        _reset_layer3_engagement(body_root)
        _reset_custom_dirs(body_root)
        _reset_custom_scripts(body_root)
        temp_msg = _reset_claude_temp(body_root)
        if temp_msg:
            print(f"[INFO] {temp_msg}")
    except OSError as exc:
        print(f"reset.py failed: {exc}", file=sys.stderr)
        return 1

    print()
    print("Reset complete!")
    print()
    if archive is not None:
        archive_rel = f"BACKUPS/{archive.name}"
        if args.no_keep_archive:
            archive.unlink(missing_ok=True)
            print("[INFO] archive created then removed (--no-keep-archive)")
        else:
            print(f"Backup archive: {archive_rel}")
            print()
            print("To restore from backup:")
            print(f"  tar -xzf {archive_rel}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
