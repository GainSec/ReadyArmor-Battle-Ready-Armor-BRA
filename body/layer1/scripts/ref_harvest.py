#!/usr/bin/env python3
"""Native artifact harvester with manifest generation and verification."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", delete=False) as tmp:
        json.dump(payload, tmp, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(path)


def _collect_source_files(source: Path) -> list[tuple[Path, Path]]:
    if source.is_file():
        return [(source, Path(source.name))]
    if source.is_dir():
        files: list[tuple[Path, Path]] = []
        base_name = source.name
        for file_path in sorted(p for p in source.rglob("*") if p.is_file()):
            rel = Path(base_name) / file_path.relative_to(source)
            files.append((file_path, rel))
        return files
    return []


def _build_manifest(dest_dir: Path, source_ref: str, files: list[tuple[Path, Path]]) -> dict:
    artifacts = []
    for file_path, rel in files:
        artifacts.append(
            {
                "path": rel.as_posix(),
                "sha256": _sha256(file_path),
                "size": file_path.stat().st_size,
                "acquired": _utc_now(),
                "source": source_ref,
            }
        )

    return {
        "version": "1.0",
        "created": _utc_now(),
        "source": source_ref,
        "artifacts": artifacts,
    }


def _manifest_for_directory(directory: Path) -> dict:
    files: list[tuple[Path, Path]] = []
    for file_path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "manifest.json"):
        files.append((file_path, file_path.relative_to(directory)))
    return _build_manifest(directory, str(directory.resolve()), files)


def _harvest(source: Path, destination: Path, log_file: Path) -> int:
    if not source.exists():
        print(f"Source not found: {source}", file=sys.stderr)
        return 1

    destination.mkdir(parents=True, exist_ok=True)
    collected = _collect_source_files(source)
    if not collected:
        print(f"No files found to harvest: {source}", file=sys.stderr)
        return 1

    if source.is_file():
        print(f"Harvesting file: {source}")
    else:
        print(f"Harvesting directory: {source}")

    copied: list[tuple[Path, Path]] = []
    for src, rel in collected:
        dest_file = destination / rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest_file)
        copied.append((dest_file, rel))
        print(f"Collected: {rel}")

    manifest = _build_manifest(destination, str(source.resolve()), copied)
    manifest_path = destination / "manifest.json"
    _safe_write_json(manifest_path, manifest)
    _append_log(log_file, "INFO", f"Harvested source={source} files={len(copied)} destination={destination}")

    print(f"Harvested {len(copied)} file(s) into: {destination}")
    print(f"Manifest: {manifest_path}")
    return 0


def _generate_manifest(directory: Path, log_file: Path) -> int:
    if not directory.is_dir():
        print(f"Directory not found: {directory}", file=sys.stderr)
        return 1
    manifest = _manifest_for_directory(directory)
    manifest_path = directory / "manifest.json"
    _safe_write_json(manifest_path, manifest)
    _append_log(log_file, "INFO", f"Generated manifest for {directory}")
    print(f"Manifest generated: {manifest_path}")
    return 0


def _verify_manifest(manifest_path: Path, log_file: Path) -> int:
    if not manifest_path.is_file():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        print(f"Invalid manifest JSON: {exc}", file=sys.stderr)
        return 1

    artifacts = data.get("artifacts", [])
    base_dir = manifest_path.parent
    mismatches = 0
    missing = 0

    for entry in artifacts:
        rel_path = Path(str(entry.get("path", "")))
        expected = str(entry.get("sha256", ""))
        file_path = base_dir / rel_path
        if not file_path.is_file():
            missing += 1
            print(f"MISSING: {rel_path}")
            continue
        actual = _sha256(file_path)
        if actual != expected:
            mismatches += 1
            print(f"MISMATCH: {rel_path}")
            print(f"Expected: {expected}")
            print(f"Actual:   {actual}")

    total = len(artifacts)
    print(f"Verified {total} entries: {total - missing - mismatches} ok, {missing} missing, {mismatches} mismatched")
    _append_log(log_file, "INFO", f"verify manifest={manifest_path} total={total} missing={missing} mismatch={mismatches}")

    if missing or mismatches:
        return 2
    return 0


_HELP_TEXT = """\
ref_harvest.py — Reference Artifact Harvester

USAGE:
    ref_harvest.py <source> [destination]    Harvest file/directory to artifacts
    ref_harvest.py --manifest <directory>    Generate manifest.json for directory
    ref_harvest.py --verify <manifest.json>  Verify artifacts against manifest
    ref_harvest.py --help                    Show this help

DESCRIPTION:
    Collects evidence artifacts with cryptographic hashing for chain of custody.
    Each harvested artifact is:
    - Copied to destination preserving directory structure
    - Hashed with SHA256
    - Recorded in manifest.json with metadata

MANIFEST FORMAT:
    {
      "version": "1.0",
      "created": "<ISO-8601 timestamp>",
      "source": "<original source path>",
      "artifacts": [
        {
          "path": "relative/path/to/file",
          "sha256": "hash...",
          "size": 12345,
          "acquired": "<ISO-8601 timestamp>",
          "source": "original/path"
        }
      ]
    }

EXIT CODES:
    0 - Success
    1 - Error (source not found, copy failed)
    2 - Verification failed (hash mismatch)

EXAMPLES:
    # Harvest a single file
    python3 ref_harvest.py /path/to/evidence.bin
    # Creates: .bra/artifacts/evidence.bin + manifest.json

    # Harvest directory to custom location
    python3 ref_harvest.py /path/to/target output/evidence
    # Creates: output/evidence/... + output/evidence/manifest.json

    # Generate manifest for existing directory
    python3 ref_harvest.py --manifest .bra/artifacts
    # Creates: .bra/artifacts/manifest.json

    # Verify manifest integrity
    python3 ref_harvest.py --verify .bra/artifacts/manifest.json
    # Exit: 0 (all hashes match) or 2 (mismatch found)

REFERENCED BY:
    - layer2-templates/evidence-manifest.md
    - layer2-templates/methodologies/firmware-extraction.md
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Harvest artifacts with SHA256 manifest support.",
        epilog=_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("source", nargs="?", help="Source file or directory to harvest")
    parser.add_argument("destination", nargs="?", help="Destination directory (default: .bra/artifacts)")
    parser.add_argument("--manifest", metavar="DIR", help="Generate manifest.json for an existing directory")
    parser.add_argument("--verify", metavar="MANIFEST", help="Verify files against a manifest.json")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))
    default_dest = body_root / ".bra" / "artifacts"
    log_file = body_root / ".bra" / "logs" / "ref_harvest.log"

    if args.manifest and args.verify:
        print("Use either --manifest or --verify, not both.", file=sys.stderr)
        return 1

    if args.manifest:
        manifest_dir = Path(args.manifest).expanduser()
        if not manifest_dir.is_absolute():
            manifest_dir = body_root / manifest_dir
        return _generate_manifest(manifest_dir.resolve(), log_file)

    if args.verify:
        manifest = Path(args.verify).expanduser()
        if not manifest.is_absolute():
            manifest = body_root / manifest
        return _verify_manifest(manifest.resolve(), log_file)

    if not args.source:
        parser.print_help(sys.stderr)
        return 1

    source = Path(args.source).expanduser()
    if not source.is_absolute():
        source = body_root / source

    if args.destination:
        destination = Path(args.destination).expanduser()
        if not destination.is_absolute():
            destination = body_root / destination
    else:
        destination = default_dest

    return _harvest(source.resolve(), destination.resolve(), log_file)


if __name__ == "__main__":
    raise SystemExit(main())
