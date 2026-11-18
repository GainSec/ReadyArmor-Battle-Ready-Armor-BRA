#!/usr/bin/env python3
"""Native deployment package builder for BRA framework files."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
import tarfile
import tempfile
import sys


LAYER1_FILES = (
    "CLAUDE.md",
    "layer1/rules/scope.md",
    "layer1/rules/roe.md",
    "layer1/rules/tokens.md",
    "layer2-templates/skillset.md",
    "layer2-templates/toolset.md",
)

INCLUDE_DIRS = (
    "layer1",
    "layer2-templates",
    "scripts",
    ".claude",
)

ROOT_OPTIONALS = ("README.md", "README.bra.md")

EXCLUDE_PATTERNS = (
    "*.log",
    "*.tmp",
    "*.pyc",
    ".DS_Store",
    "**/__pycache__/**",
    ".git/**",
    ".bra/**",
    "BACKUPS/**",
    "layer3-engagement/NOTES/**",
    "layer3-engagement/pitches/**",
    "layer3-engagement/disclosure/**",
    "layer3-engagement/*.md",
)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


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


def _normalize(rel: Path) -> str:
    return rel.as_posix().lstrip("./")


def _is_excluded(rel: Path) -> bool:
    rel_str = _normalize(rel)
    if rel_str in {".git", ".bra", "BACKUPS"}:
        return True
    for pattern in EXCLUDE_PATTERNS:
        if fnmatch(rel_str, pattern) or fnmatch(f"{rel_str}/", pattern):
            return True
    return False


def _iter_includes(body_root: Path) -> list[Path]:
    includes: list[Path] = []
    for rel in LAYER1_FILES:
        path = body_root / rel
        if path.is_file():
            includes.append(path)

    for rel in INCLUDE_DIRS:
        path = body_root / rel
        if path.is_dir():
            includes.append(path)

    for rel in ROOT_OPTIONALS:
        path = body_root / rel
        if path.is_file():
            includes.append(path)

    return includes


def _collect_files(body_root: Path, includes: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in includes:
        if path.is_file():
            rel = path.relative_to(body_root)
            if not _is_excluded(rel):
                files.append(path)
            continue

        for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
            rel = file_path.relative_to(body_root)
            if _is_excluded(rel):
                continue
            files.append(file_path)

    deduped = sorted(set(files), key=lambda p: p.as_posix())
    return deduped


def _safe_output_path(body_root: Path, output: str | None) -> Path:
    if output:
        chosen = Path(output).expanduser()
        return chosen if chosen.is_absolute() else body_root / chosen
    return body_root / f"B.R.A.-deploy-{_timestamp()}.tar.gz"


def _create_archive(body_root: Path, output_path: Path, files: list[Path]) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(prefix="prep-deploy-", suffix=".tar.gz", dir=output_path.parent, delete=False) as temp:
        temp_path = Path(temp.name)

    try:
        with tarfile.open(temp_path, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            for file_path in files:
                rel = file_path.relative_to(body_root)
                tar.add(file_path, arcname=_normalize(rel), recursive=False)

            # Add deploy manifest
            manifest = f"# Deploy Manifest\n# Generated: {_utc_now()}\n# Files: {len(files)}\n"
            for file_path in files:
                manifest += f"- {_normalize(file_path.relative_to(body_root))}\n"
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as mf:
                mf.write(manifest)
                mf_path = Path(mf.name)
            tar.add(mf_path, arcname=".deploy-manifest.txt", recursive=False)
            mf_path.unlink(missing_ok=True)

        temp_path.replace(output_path)
    finally:
        if temp_path.exists() and temp_path != output_path:
            temp_path.unlink(missing_ok=True)

    size_kb = output_path.stat().st_size // 1024
    print()
    print("════════════════════════════════════════════════════════════════")
    print("  DEPLOYMENT ARCHIVE CREATED")
    print("════════════════════════════════════════════════════════════════")
    print()
    print(f"  Archive: {output_path}")
    print(f"  Size:    {size_kb}KB")
    print(f"  Files:   {len(files)}")
    print()
    print("  To deploy to a new instance:")
    print()
    print("    1. Copy archive to target machine")
    print("    2. mkdir B.R.A. && cd B.R.A.")
    print(f"    3. tar -xzf {output_path}")
    print("    4. python3 layer1/scripts/precheck.py")
    print()
    print("════════════════════════════════════════════════════════════════")
    print()
    return 0


def _verify_archive(archive_path: Path, body_root: Path, log_file: Path) -> int:
    """Verify archive integrity and list contents."""
    if not archive_path.is_file():
        print(f"Archive not found: {archive_path}", file=sys.stderr)
        return 1
    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            members = tar.getmembers()
            file_count = sum(1 for m in members if m.isfile())
            total_size = sum(m.size for m in members if m.isfile())
            print(f"Archive: {archive_path}")
            print(f"Files: {file_count}")
            print(f"Total size: {total_size // 1024}KB")
            print(f"Integrity: OK")
            _append_log(log_file, "INFO", f"verify OK: {archive_path} files={file_count}")
    except tarfile.TarError as exc:
        print(f"Archive FAILED integrity check: {exc}", file=sys.stderr)
        _append_log(log_file, "ERROR", f"verify FAILED: {archive_path}: {exc}")
        return 1
    return 0


def _list_includes(body_root: Path, includes: list[Path], files: list[Path]) -> int:
    print()
    print("=== Deployment Package Contents ===")
    print()

    print("Layer 1 (Root Guides):")
    for rel in LAYER1_FILES:
        path = body_root / rel
        if path.is_file():
            print(f"  [x] {rel} ({path.stat().st_size} bytes)")
        else:
            print(f"  [ ] {rel} (not found)")
    print()

    print("Layer 2 (Templates):")
    layer2_dir = body_root / "layer2-templates"
    if layer2_dir.is_dir():
        template_files = sorted(layer2_dir.rglob("*.md"))
        print(f"  [x] layer2-templates/ ({len(template_files)} files)")
        for path in template_files:
            print(f"      - {path.relative_to(body_root)}")
    else:
        print("  [ ] layer2-templates/ (not found)")
    print()

    print("Framework Components:")
    for rel in INCLUDE_DIRS:
        path = body_root / rel
        if path.is_dir():
            count = sum(1 for p in files if p.is_relative_to(path))
            print(f"  [x] {rel}/ ({count} files)")
        else:
            print(f"  [ ] {rel}/ (not found)")
    print()

    print("Excluded (engagement-specific):")
    print("  - .bra/ (runtime state)")
    print("  - layer3-engagement/NOTES/ (evidence)")
    print("  - BACKUPS/ (archives)")
    print("  - layer3-engagement/*.md (Layer 3 instances)")
    print()
    print("Archive file count:", len(files))
    return 0


_HELP_TEXT = """\
prep-deploy.py — Package Layer 1 & 2 for Deployment

USAGE:
    prep-deploy.py                      Create deployment archive
    prep-deploy.py --list               List files that would be included
    prep-deploy.py --output <path>      Specify output path for archive
    prep-deploy.py --help               Show this help

DESCRIPTION:
    Packages B.R.A. framework files (Layer 1 and Layer 2) into a
    portable tar.gz archive that can be deployed to another instance.

INCLUDED FILES:

    Layer 1 (Root Guides):
        CLAUDE.md, scope.md, roe.md, tokens.md, skillset.md, toolset.md

    Layer 2 (Templates):
        layer2-templates/   (all template files)

    Framework Components:
        layer1/                 (all scripts, hooks, and libraries)
        .claude/                (skills and hooks)
        (reference docs now in layer2-templates/reference/)

EXCLUDED FILES:
    - .bra/                            (runtime state)
    - layer3-engagement/NOTES/         (engagement evidence)
    - BACKUPS/                         (engagement backups)
    - layer3-engagement/*.md           (Layer 3 instances)
    - layer3-engagement/pitches/             (engagement pitches)
    - *.log, *.tmp              (temporary files)

OUTPUT:
    Default: B.R.A.-deploy-YYYYMMDD_HHMMSS.tar.gz

EXAMPLES:
    # Create deployment archive
    python3 layer1/scripts/prep-deploy.py

    # Preview what would be included
    python3 layer1/scripts/prep-deploy.py --list

    # Specify custom output path
    python3 layer1/scripts/prep-deploy.py --output ~/B.R.A.-v2.tar.gz

DEPLOYMENT:
    To deploy to a new instance:

    1. Copy archive to target machine
    2. mkdir B.R.A. && cd B.R.A.
    3. tar -xzf B.R.A.-deploy-*.tar.gz
    4. python3 layer1/scripts/precheck.py

EXIT CODES:
    0 - Success
    1 - Error
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a deployment archive with Layer 1/2 framework files.",
        epilog=_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--list", action="store_true", help="List files that would be included and exit")
    parser.add_argument("--verify", action="store_true", help="Verify existing archive integrity")
    parser.add_argument("--output", metavar="PATH", help="Output archive path (default: body root timestamped tar.gz)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))
    log_file = body_root / ".bra" / "logs" / "prep-deploy.log"

    includes = _iter_includes(body_root)
    files = _collect_files(body_root, includes)

    _append_log(log_file, "INFO", f"prep-deploy start includes={len(includes)} files={len(files)}")

    if args.verify:
        output_path = _safe_output_path(body_root, args.output)
        return _verify_archive(output_path, body_root, log_file)

    if not files:
        print("No eligible files found for packaging.", file=sys.stderr)
        _append_log(log_file, "ERROR", "No eligible files found")
        return 1

    # Validate Layer 1 governance files are present
    for rel in LAYER1_FILES:
        path = body_root / rel
        if not path.is_file():
            print(f"[WARN] Missing governance file: {rel}")

    if args.list:
        return _list_includes(body_root, includes, files)

    output_path = _safe_output_path(body_root, args.output)
    rc = _create_archive(body_root, output_path, files)
    _append_log(log_file, "INFO", f"archive created: {output_path}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
