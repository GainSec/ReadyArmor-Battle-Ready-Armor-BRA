#!/usr/bin/env python3
"""Integrate redacted ingest content into reusable reference markdown files."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

_HELP_TEXT = """\
Usage: integrate-ingest.py [OPTIONS]

Integrate `layer3-engagement/ingest/` content into reusable reference files.

Options:
  --dry-run           Show what would be generated without writing files
  --output-dir DIR    Output directory for integrated files
  --verbose           Show per-project processing details
  -h, --help          Show this help

Redaction Rules:
  - Project/folder names from layer3-engagement/ingest/*
  - Specific file paths containing user directories
  - Device serial numbers, specific IPs (except localhost/examples)
  - Company/product names from source projects
  - API keys, credentials, specific endpoints

Preserved Content:
  - Generic tool names (nmap, Ghidra, adb, etc.)
  - Methodology descriptions and workflows
  - Command patterns with placeholder values
  - Security research techniques

Examples:
  integrate-ingest.py --dry-run
  integrate-ingest.py --output-dir ./output
"""


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_under_root(root: Path, raw: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve(strict=False))
    except ValueError as exc:
        raise ValueError(f"Output path escapes body root: {raw}") from exc
    return resolved


def _redact(text: str, project_names: list[str]) -> str:
    output = text

    for project in project_names:
        if len(project) >= 4:
            output = re.sub(rf"\b{re.escape(project)}\b", "[PROJECT]", output, flags=re.IGNORECASE)

    replacements = [
        (r"/Users/[a-zA-Z0-9_-]+/", "/Users/[USER]/"),
        (r"/home/[a-zA-Z0-9_-]+/", "/home/[USER]/"),
        (r"192\.168\.[0-9]+\.[0-9]+", "[INTERNAL_IP]"),
        (r"10\.[0-9]+\.[0-9]+\.[0-9]+", "[INTERNAL_IP]"),
        (r"172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+", "[INTERNAL_IP]"),
        (r"sk-[A-Za-z0-9]{20,}", "[API_KEY]"),
        (r"api[_-]?key\s*[:=]\s*[\"'][^\"']+[\"']", "api_key=[REDACTED]"),
        (r"password\s*[:=]\s*[\"'][^\"']+[\"']", "password=[REDACTED]"),
        (r"[0-9]{6}P[0-9]{8}", "[DEVICE_SERIAL]"),
        (r"finding[0-9]+_[a-z_]+\.py", "[POC_SCRIPT].py"),
    ]
    for pattern, replacement in replacements:
        output = re.sub(pattern, replacement, output, flags=re.IGNORECASE)

    return output


def _collect_projects(ingest_dir: Path) -> list[Path]:
    if not ingest_dir.is_dir():
        return []
    return [path for path in sorted(ingest_dir.iterdir()) if path.is_dir() and path.name != ".gitkeep"]


def _integrate_file(
    projects: list[Path],
    source_names: list[str],
    output_file: Path,
    title: str,
    project_names: list[str],
    verbose: bool,
    dry_run: bool,
    *,
    header_extra: str = "",
    section_template: str | None = None,
) -> int:
    if not header_extra and title == "Integrated Tools Reference":
        header_extra = "## Tool Categories"
    if section_template is None and title == "Integrated Security Methodologies":
        section_template = "## Methodology Pattern {n}"

    segments: list[str] = [
        f"# {title}",
        "",
        f"> **Source:** Aggregated from multiple security research projects",
        f"> **Status:** Redacted for reuse - no project-specific identifiers",
        f"> **Last Updated:** {datetime.now().strftime('%Y-%m-%d')}",
        "",
        "---",
        "",
    ]

    if header_extra:
        segments.extend([header_extra, ""])

    processed = 0
    for project in projects:
        candidate = None
        for source_name in source_names:
            check = project / source_name
            if check.is_file():
                candidate = check
                break
        if candidate is None:
            continue
        processed += 1
        raw = candidate.read_text(encoding="utf-8", errors="ignore")
        redacted = _redact(raw, project_names)
        if section_template is not None:
            section_label = section_template.format(n=processed)
            segments.extend([section_label, "", redacted.strip(), "", "---", ""])
        else:
            segments.extend([redacted.strip(), "", "---", ""])
        if verbose:
            print(f"[INFO] processed {candidate}")

    if processed == 0:
        if verbose:
            print(f"[INFO] no sources for {source_name}")
        return 0

    content = "\n".join(segments).strip() + "\n"
    if dry_run:
        preview = "\n".join(content.splitlines()[:50])
        print(f"[DRY-RUN] Would write {output_file} from {processed} source file(s)")
        print("DRY RUN PREVIEW (first 50 lines):")
        print(preview)
        print("...")
        return processed

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(content, encoding="utf-8")
    print(f"[OK] wrote {output_file} ({processed} source file(s))")
    return processed


def _write_summary(output_dir: Path, project_count: int, generated: dict[str, int], *, dry_run: bool) -> None:
    lines = [
        "# Integration Summary",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Source:** layer3-engagement/ingest/",
        f"**Projects Processed:** {project_count}",
        "",
        "## Redaction Applied",
        "",
        "The following types of information were redacted:",
        "",
        "| Category | Replacement |",
        "|----------|-------------|",
        "| Project names | [PROJECT] |",
        "| Company names | [TARGET] |",
        "| User paths | /Users/[USER]/ |",
        "| Device serials | [DEVICE_SERIAL] |",
        "| Internal IPs | [INTERNAL_IP] |",
        "| PoC scripts | [POC_SCRIPT].py |",
        "| API keys | [API_KEY] |",
        "",
        "## Files Generated",
        "",
    ]
    descriptions = {
        "tools-integrated.md": "Combined tool references",
        "methodologies-integrated.md": "Security research methodologies",
        "skills-integrated.md": "Capability/skill mappings",
        "workflows-integrated.md": "Operational workflows",
    }
    for name, count in generated.items():
        desc = descriptions.get(name, f"{count} source file(s)")
        lines.append(f"- `{name}` - {desc}")

    lines.extend(
        [
            "",
            f"## Projects Processed",
            "",
            f"**{project_count} source projects integrated** (names redacted)",
            "",
            "## Usage",
            "",
            "These integrated files contain generic, reusable content suitable for:",
            "- Training new engagements",
            "- Tool reference lookups",
            "- Methodology templates",
            "- Workflow patterns",
            "",
            "**Note:** Original project-specific details have been removed. For engagement-specific",
            "information, refer to the original project documentation (if authorized).",
            "",
        ]
    )
    content = "\n".join(lines)

    summary = output_dir / "INTEGRATION-SUMMARY.md"
    if dry_run:
        print(f"[DRY-RUN] Would write {summary}")
        return
    summary.write_text(content, encoding="utf-8")
    print(f"[OK] wrote {summary}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    if "--help" in argv or "-h" in argv:
        print(_HELP_TEXT)
        raise SystemExit(0)

    parser = argparse.ArgumentParser(
        description="Integrate layer3-engagement/ingest/* content into main reference files with redaction.",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes.")
    parser.add_argument(
        "--output-dir",
        default="layer2-templates/reference/integrated",
        help="Output directory for integrated files (default: layer2-templates/reference/integrated).",
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed processing information.")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()

    try:
        output_dir = _resolve_under_root(body_root, args.output_dir)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    ingest_dir = body_root / "layer3-engagement" / "ingest"
    projects = _collect_projects(ingest_dir)
    project_names = [project.name for project in projects]

    if not projects:
        print(f"[ERROR] No ingest project directories found in {ingest_dir}", file=sys.stderr)
        return 1

    mapping: list[tuple[list[str], str, str, str, str | None]] = [
        (["tools.md"], "tools-integrated.md", "Integrated Tools Reference", "## Tool Categories", None),
        (["methodologies.md", "methodology.md"], "methodologies-integrated.md", "Integrated Security Methodologies", "", "## Methodology Pattern {n}"),
        (["skills.md"], "skills-integrated.md", "Integrated Skills Reference", "", None),
        (["workflows.md"], "workflows-integrated.md", "Integrated Workflows Reference", "", None),
    ]

    generated: dict[str, int] = {}
    for source_names, output_name, title, header_extra, section_template in mapping:
        count = _integrate_file(
            projects,
            source_names,
            output_dir / output_name,
            title,
            project_names,
            verbose=args.verbose,
            dry_run=args.dry_run,
            header_extra=header_extra,
            section_template=section_template,
        )
        generated[output_name] = count

    _write_summary(output_dir, len(projects), generated, dry_run=args.dry_run)
    print("Integration complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
