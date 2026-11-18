#!/usr/bin/env python3
"""Native validator for skill/tool cross-references."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
import re
import sys


BACKTICK_RE = re.compile(r"`([a-zA-Z0-9_-]+)`")
TABLE_ROW_RE = re.compile(r"^\|\s*`?([a-zA-Z0-9_-]+)`?\s*\|")


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _log_line(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] [{level}] {message}\n")


def _table_first_col_names(content: str) -> set[str]:
    names: set[str] = set()
    for raw in content.splitlines():
        if not raw.startswith("|"):
            continue
        if "---" in raw:
            continue
        if raw.lower().startswith("| skill") or raw.lower().startswith("| tool") or raw.lower().startswith("| workflow"):
            continue
        match = TABLE_ROW_RE.match(raw)
        if match:
            names.add(match.group(1))
    return names


def _extract_section(content: str, header_prefix: str) -> str:
    lines = content.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip().lower().startswith(header_prefix.lower()):
            start = idx + 1
            break
    if start is None:
        return ""

    end = len(lines)
    for idx in range(start, len(lines)):
        if lines[idx].startswith("## "):
            end = idx
            break
    return "\n".join(lines[start:end])


def _extract_backticked(content: str) -> set[str]:
    return set(BACKTICK_RE.findall(content))


def _find_duplicates(content: str, kind: str) -> list[str]:
    """Find duplicate definitions in table first columns."""
    seen: dict[str, int] = {}
    for raw in content.splitlines():
        if not raw.startswith("|"):
            continue
        if "---" in raw:
            continue
        match = TABLE_ROW_RE.match(raw)
        if match:
            name = match.group(1)
            seen[name] = seen.get(name, 0) + 1
    return sorted(name for name, count in seen.items() if count > 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate skillset/toolset mapping consistency.", add_help=False)
    parser.add_argument("--verbose", action="store_true", help="Print detailed reference mismatches")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if orphaned references are found")
    parser.add_argument("--help", "-h", action="store_true", help="Show this help")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.help:
        print(
            "validate-mappings.py -- Validate Tool/Skill Mapping Consistency\n\n"
            "USAGE:\n"
            "    validate-mappings.py                Run full validation\n"
            "    validate-mappings.py --verbose      Show detailed findings\n"
            "    validate-mappings.py --strict       Exit 1 if any orphans found\n"
            "    validate-mappings.py --help         Show this help\n\n"
            "DESCRIPTION:\n"
            "    Validates that tools referenced in skillset.md exist in toolset.md\n"
            "    and vice versa. Helps maintain consistency between the two catalogs.\n\n"
            "CHECKS PERFORMED:\n"
            "    1. Tools in skillset.md tables exist in toolset.md\n"
            "    2. Skills in toolset.md references exist in skillset.md\n"
            "    3. Reports any orphaned cross-references\n\n"
            "OUTPUT:\n"
            "    - Summary printed to stdout\n"
            "    - Detailed log: .bra/logs/mappings-validation.log\n\n"
            "EXIT CODES:\n"
            "    0 - All mappings valid (or non-strict mode)\n"
            "    1 - Orphaned references found (strict mode only)\n"
            "    2 - Required files not found\n\n"
            "EXAMPLES:\n"
            "    # Basic validation\n"
            "    ./layer1/scripts/validate-mappings.py\n\n"
            "    # Detailed output\n"
            "    ./layer1/scripts/validate-mappings.py --verbose\n\n"
            "    # CI/CD mode - fail on orphans\n"
            "    ./layer1/scripts/validate-mappings.py --strict"
        )
        return 0

    body_root = _find_body_root(Path(__file__))
    skillset_path = body_root / "layer2-templates" / "skillset.md"
    toolset_path = body_root / "layer2-templates" / "toolset.md"
    report_path = body_root / ".bra" / "logs" / "mappings-validation.log"

    print("")
    print("\u2554" + "\u2550" * 79 + "\u2557")
    print("\u2551" + "MAPPING VALIDATION".center(79) + "\u2551")
    print("\u255a" + "\u2550" * 79 + "\u255d")
    print("")

    if not skillset_path.is_file() or not toolset_path.is_file():
        missing = [str(path) for path in (skillset_path, toolset_path) if not path.is_file()]
        for item in missing:
            print(f"[ERROR] Missing required file: {item}", file=sys.stderr)
            _log_line(report_path, "ERROR", f"missing file {item}")
        return 2

    print(f"Skillset: {skillset_path}")
    print(f"Toolset: {toolset_path}")

    skillset_text = skillset_path.read_text(encoding="utf-8", errors="replace")
    toolset_text = toolset_path.read_text(encoding="utf-8", errors="replace")

    skill_definitions = _table_first_col_names(skillset_text)
    tool_definitions = _table_first_col_names(toolset_text)

    tool_refs = _extract_backticked(_extract_section(skillset_text, "## tools"))
    if not tool_refs:
        tool_refs = _extract_backticked(skillset_text) - skill_definitions

    skill_refs = _extract_backticked(_extract_section(toolset_text, "## skill"))
    if not skill_refs:
        skill_refs = _extract_backticked(toolset_text) - tool_definitions

    # Common words to skip (not real tool/skill names)
    skip_words = {
        "Tool", "Purpose", "Platform", "License", "Task", "Primary", "Secondary",
        "Description", "Scope", "Token", "Required", "Yes", "No", "None", "N", "A",
        "GPL", "MIT", "BSD", "AGPL", "Apache", "Commercial", "Community",
    }
    tool_refs -= skip_words
    skill_refs -= skip_words

    orphan_tools = sorted(tool_refs - tool_definitions)
    orphan_skills = sorted(skill_refs - skill_definitions)

    # Catalog consistency: count definitions and check duplicates
    workflow_count = len(re.findall(r"^\|.*`.*`.*\|.*\|.*layer", skillset_text, flags=re.MULTILINE | re.IGNORECASE))

    print("")
    print("\u2550\u2550\u2550 Catalog Consistency \u2550\u2550\u2550")
    print("")
    print(f"  [PASS] Skills defined: {len(skill_definitions)}")
    print(f"  [PASS] Tools defined: {len(tool_definitions)}")
    print(f"  [PASS] Workflows defined: {workflow_count}")

    # Duplicate detection
    dup_skills = _find_duplicates(skillset_text, "skill")
    dup_tools = _find_duplicates(toolset_text, "tool")
    if dup_skills:
        print(f"  WARNING: Duplicate skill definitions: {', '.join(dup_skills)}")
        _log_line(report_path, "WARN", f"Duplicate skills: {', '.join(dup_skills)}")
    if dup_tools:
        print(f"  WARNING: Duplicate tool definitions: {', '.join(dup_tools)}")
        _log_line(report_path, "WARN", f"Duplicate tools: {', '.join(dup_tools)}")

    # Tool Reference Validation
    print("")
    print("\u2550\u2550\u2550 Tool Reference Validation \u2550\u2550\u2550")
    print("")

    if not tool_refs:
        print("  [PASS] No explicit tool references in skillset.md (skill-to-tool mapping defined in engagement SKILLSUITES.md)")
    elif not orphan_tools:
        print(f"  [PASS] All tool references valid ({len(tool_refs)} checked)")
    else:
        print(f"  [WARN] {len(orphan_tools)} orphaned tool references found")

    # Skill Reference Validation
    print("")
    print("\u2550\u2550\u2550 Skill Reference Validation \u2550\u2550\u2550")
    print("")

    if not skill_refs:
        print("  [PASS] No explicit skill references in toolset.md (tool-to-skill mapping defined in engagement TOOLSUITES.md)")
    elif not orphan_skills:
        print(f"  [PASS] All skill references valid ({len(skill_refs)} checked)")
    else:
        print(f"  [WARN] {len(orphan_skills)} orphaned skill references found")

    _log_line(report_path, "INFO", f"tools={len(tool_definitions)} skills={len(skill_definitions)}")
    _log_line(report_path, "INFO", f"orphan_tools={len(orphan_tools)} orphan_skills={len(orphan_skills)}")

    if args.verbose:
        if orphan_tools:
            print("\nOrphan tool references:")
            for item in orphan_tools:
                print(f"  - {item}")
                _log_line(report_path, "WARN", f"orphan tool ref {item}")
        if orphan_skills:
            print("\nOrphan skill references:")
            for item in orphan_skills:
                print(f"  - {item}")
                _log_line(report_path, "WARN", f"orphan skill ref {item}")

    # Summary banner
    total_orphans = len(orphan_tools) + len(orphan_skills)
    print("")
    print("\u2550" * 79)
    print("MAPPING VALIDATION SUMMARY".center(79))
    print("\u2550" * 79)
    print("")

    if total_orphans == 0:
        print("  STATUS: ALL MAPPINGS VALID")
        print("")
        print("  Tool and skill cross-references are consistent.")
    else:
        print(f"  STATUS: {total_orphans} ORPHANED REFERENCES")
        print("")
        print(f"  Orphaned tools: {len(orphan_tools)}")
        print(f"  Orphaned skills: {len(orphan_skills)}")
        print("")
        print("  Consider updating skillset.md or toolset.md to resolve.")

    print("")
    print(f"  Report: {report_path}")
    print("")

    if args.strict and (orphan_tools or orphan_skills):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
