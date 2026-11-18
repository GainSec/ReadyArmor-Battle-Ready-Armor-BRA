#!/usr/bin/env python3
"""Extract unique candidates from integrated references and emit pitch files."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

# ~200 word false-positive filter for tool names
FALSE_POSITIVE_WORDS = frozenset("""
    arm64 armeabi x86 mips json logging argparse exec true false null none yes no ok
    test example default usage note see the and for with from used using key value type
    name file path url http https com org net src lib bin var tmp etc usr opt dev target
    app project system device version abort access action address admin agentic allow
    analyze android api application architectures attack authentication authorization
    available backup base boot bootstrap build byte call capabilities capture category
    chain channel check class cleanup client code collection command communication
    components config configuration connect connection content context control convert
    copy core create cross cryptography data debug debugging delete dependency deploy
    deserialization details development directory disable display domain download driver
    dump dynamic enable encode encryption endpoint engine entry environment error eval
    event execute execution exit export extract factory feature field filter find firmware
    flag flow format framework function gateway generate generic global grant group
    handler hardware hash header health help history hook host id import include index
    info information init initialization initialize inject injection input install
    installation instance integration interface internal invoke java kill layer length
    library limit line link linux list listen load loader local location lock log login
    lookup loop macro main manage management manager manifest manual map mapping match
    max memory merge message metadata method methods min mode model module monitor mount
    multi network node object offset operation option options output override package
    param parameter parameters parse parser partition patch pattern payload pending
    permission permissions phase platform plugin pointer policy poll port post prefix
    prepare preview primary print priority private privilege process processing
    production profile program properties property protocol provider proxy public
    publish pull push query queue range raw read reader receive record recovery reference
    refresh register registry release reload remote remove render replace report request
    requirements reset resource response restart restore result resume retrieve return
    revert role root rotate router rule run runtime sample sandbox scan schedule schema
    scope script scripts search section secure security segment send sequence server
    service services session setting settings setup shell shutdown signal size snapshot
    socket software solution source sources spec specification stack stage standalone
    standard start state static statistics status step stop storage stream string struct
    structure submit subscribe success suffix summary support supported suspend switch
    sync table tag target task template terminal terminate testing thread threshold
    timeout timestamp token tool topic trace track transfer transform transit translate
    transport trigger trust tunnel type types uid unit unix unload unpack update upgrade
    upload uri user util utilities utility uuid valid validate validation validator value
    values variable variant vector vendor verbose verify version versions view virtual
    volume wait watch watchdog whitelist windows worker workflow wrapper write writer zone
    purpose overview skill capability evidence technology impact mitigation component
    objective process
""".split())

# Category patterns for tool classification
TOOL_CATEGORIES = [
    ("Android/Mobile", re.compile(r"^(adb|fastboot|apktool|jadx|frida|objection|magisk|logcat|dex|smali)")),
    ("Binary Analysis", re.compile(r"^(ghidra|radare2|r2|binwalk|objdump|readelf|nm|strings|file|ida|hopper|cutter)")),
    ("Network", re.compile(r"^(nmap|masscan|wireshark|tcpdump|netcat|nc|curl|wget|httpx|nuclei|burp)")),
    ("Bluetooth/Radio", re.compile(r"^(bluetoothctl|hcitool|gatttool|btmon|sdptool|rfcomm|gnuradio|hackrf|rtl)")),
    ("Fuzzing", re.compile(r"^(afl|honggfuzz|libfuzzer|boofuzz|radamsa)")),
    ("SELinux", re.compile(r"^(seinfo|sesearch|secilc|checkpolicy)")),
    ("Debugging", re.compile(r"^(gdb|lldb|strace|ltrace|valgrind)")),
]

SKILL_CATEGORIES = [
    ("Reverse Engineering", re.compile(r"(reverse|decompil|disassem)")),
    ("Exploitation", re.compile(r"(exploit|injection|bypass)")),
    ("Analysis", re.compile(r"(analysis|review|audit)")),
    ("Intelligence", re.compile(r"(intel|enum|discovery)")),
    ("Reporting", re.compile(r"(report|document|evidence)")),
    ("Network", re.compile(r"(network|traffic|packet)")),
    ("Mobile", re.compile(r"(mobile|android|ios)")),
]


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


def _normalize(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value


def _is_false_positive(name: str) -> bool:
    return name in FALSE_POSITIVE_WORDS or len(name) < 2


def _categorize_tool(name: str) -> str:
    for cat_name, pattern in TOOL_CATEGORIES:
        if pattern.match(name):
            return cat_name
    return "General"


def _categorize_skill(name: str) -> str:
    for cat_name, pattern in SKILL_CATEGORIES:
        if pattern.search(name):
            return cat_name
    return "General"


# ── Extraction functions ──────────────────────────────────────────────────

def _extract_tools(source: Path) -> set[str]:
    """Extract tool candidates using multiple patterns."""
    if not source.is_file():
        return set()
    text = source.read_text(encoding="utf-8", errors="ignore")
    names: set[str] = set()

    # Pattern 1: Table format - | `toolname` |
    for m in re.finditer(r"^\| `([a-zA-Z0-9_-]+)`", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    # Pattern 2: Bold format - **toolname** - description
    for m in re.finditer(r"^- \*\*([a-zA-Z0-9_-]+)\*\*", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    # Pattern 3: Inline backticks (tool-like patterns)
    for m in re.finditer(r"`([a-z][a-z0-9_-]*)`", text):
        names.add(_normalize(m.group(1)))

    # Pattern 4: ### Toolname section headers
    for m in re.finditer(r"^### ([A-Za-z0-9_-]+)$", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    names.discard("")
    return {n for n in names if not _is_false_positive(n)}


def _extract_skills(source: Path) -> set[str]:
    if not source.is_file():
        return set()
    text = source.read_text(encoding="utf-8", errors="ignore")
    names: set[str] = set()

    # Pattern 1: Table format
    for m in re.finditer(r"^\| `([a-zA-Z0-9_-]+)`", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    # Pattern 2: Table first column text
    for m in re.finditer(r"^\| ([A-Z][a-zA-Z ]+)\|", text, re.MULTILINE):
        val = m.group(1).strip()
        if val not in ("Skill", "Tool", "Capability", "Category"):
            names.add(_normalize(val))

    # Pattern 3: ### Numbered or plain headers
    for m in re.finditer(r"^### (?:\d+\. )?([A-Z][a-zA-Z ]+)$", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    names.discard("")
    return {n for n in names if not _is_false_positive(n) and len(n) >= 3}


def _extract_methodologies(source: Path) -> set[str]:
    if not source.is_file():
        return set()
    text = source.read_text(encoding="utf-8", errors="ignore")
    names: set[str] = set()

    # # Title headers
    for m in re.finditer(r"^# ([A-Z][A-Za-z /()-]+)$", text, re.MULTILINE):
        val = m.group(1).strip()
        if not re.search(r"Integrated|Reference|Skills|Tools|Workflows", val):
            names.add(_normalize(val))

    # ## Methodology headers
    for m in re.finditer(r"^## ([A-Z][A-Za-z ()-]+Methodology)", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    # ## Research/Analysis/etc headers
    for m in re.finditer(r"^## ((?:Research|Analysis|Extraction|Testing|Attack|Security|Vulnerability|Exploitation) [A-Za-z]+)", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    names.discard("")
    return {n for n in names if len(n) >= 5 and not n.startswith("methodology-pattern")}


def _extract_workflows(source: Path) -> set[str]:
    if not source.is_file():
        return set()
    text = source.read_text(encoding="utf-8", errors="ignore")
    names: set[str] = set()

    for m in re.finditer(r"^# ([A-Z][A-Za-z /()-]+)$", text, re.MULTILINE):
        val = m.group(1).strip()
        if not re.search(r"Integrated|Reference|Skills|Tools|Methodologies", val):
            names.add(_normalize(val))

    for m in re.finditer(r"^## (?:Phase|Workflow|Step|Process) \d+:? (.+)", text, re.MULTILINE):
        names.add(_normalize(m.group(1)))

    names.discard("")
    return {n for n in names if len(n) >= 4 and not re.match(r"^(workflow|phase|step|process|overview|reference|summary|purpose|primary-workflows)$", n)}


def _extract_names_generic(path: Path) -> set[str]:
    """Generic extraction for backwards compatibility."""
    if not path.is_file():
        return set()
    text = path.read_text(encoding="utf-8", errors="ignore")
    names: set[str] = set()
    for token in re.findall(r"`([A-Za-z0-9][A-Za-z0-9_-]{1,})`", text):
        names.add(_normalize(token))
    for heading in re.findall(r"^###\s+(.+)$", text, flags=re.MULTILINE):
        cleaned = heading.split("(", 1)[0].strip("` ")
        candidate = _normalize(cleaned)
        if candidate:
            names.add(candidate)
    names.discard("")
    return {n for n in names if not _is_false_positive(n)}


def _from_file_stems(directory: Path) -> set[str]:
    if not directory.is_dir():
        return set()
    return {_normalize(path.stem) for path in directory.glob("*.md") if path.is_file()}


# ── Pitch generation ─────────────────────────────────────────────────────

def _write_tool_pitch(output_path: Path, items: list[str]) -> None:
    count = len(items)
    rows = [
        f"# Pitch: Add {count} Tools to Master TOC",
        "",
        f"**Date:** {date.today().isoformat()}",
        "**Category:** Tools",
        "**Source:** layer2-templates/reference/integrated/tools-integrated.md",
        "**Status:** Proposed",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"This pitch proposes adding {count} tools extracted from integrated project documentation",
        "to the master tool catalog at `layer2-templates/toolset.md`.",
        "",
        "---",
        "",
        "## Proposed Additions",
        "",
        "| Tool | Category | Notes |",
        "|------|----------|-------|",
    ]
    for item in items:
        cat = _categorize_tool(item)
        rows.append(f"| `{item}` | {cat} | Extracted from integrated docs |")
    rows.extend([
        "",
        "---",
        "",
        "## Justification",
        "",
        "These tools were extracted from aggregated project documentation and deduplicated",
        "against the existing `layer2-templates/toolset.md` master catalog. They represent",
        "commonly used security research tools not yet formally cataloged.",
        "",
        "## Integration Path",
        "",
        "1. Review proposed tools for relevance",
        "2. Verify no duplicates or near-duplicates (e.g., `adb` vs `android-debug-bridge`)",
        "3. Add approved tools to appropriate category in `layer2-templates/toolset.md`",
        "4. Update skill mappings in `layer2-templates/skillset.md` if applicable",
        "",
        "---",
        "",
        "## Verification",
        "",
        "- [ ] No duplicates with existing toolset.md",
        "- [ ] No identifiable project/company names",
        "- [ ] All tools are legitimate security research tools",
        "- [ ] Categories are appropriate",
        "",
    ])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(rows), encoding="utf-8")


def _write_skill_pitch(output_path: Path, items: list[str]) -> None:
    count = len(items)
    rows = [
        f"# Pitch: Add {count} Skills to Master TOC",
        "",
        f"**Date:** {date.today().isoformat()}",
        "**Category:** Skills",
        "**Source:** layer2-templates/reference/integrated/skills-integrated.md",
        "**Status:** Proposed",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"This pitch proposes adding {count} skills extracted from integrated project documentation",
        "to the master skill catalog at `layer2-templates/skillset.md`.",
        "",
        "---",
        "",
        "## Proposed Additions",
        "",
        "| Skill | Category | Description |",
        "|-------|----------|-------------|",
    ]
    for item in items:
        cat = _categorize_skill(item)
        rows.append(f"| `{item}` | {cat} | Extracted from integrated docs |")
    rows.extend([
        "",
        "---",
        "",
        "## Justification",
        "",
        "These skills were extracted from aggregated project documentation and deduplicated",
        "against the existing `layer2-templates/skillset.md` master catalog.",
        "",
        "## Integration Path",
        "",
        "1. Review proposed skills for relevance",
        "2. Merge similar skills (e.g., `static-analysis` and `code-review`)",
        "3. Add approved skills to appropriate category in `layer2-templates/skillset.md`",
        "4. Document tool requirements for each skill",
        "",
        "---",
        "",
        "## Verification",
        "",
        "- [ ] No duplicates with existing skillset.md",
        "- [ ] No identifiable project/company names",
        "- [ ] Skills are actionable techniques",
        "- [ ] Categories are appropriate",
        "",
    ])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(rows), encoding="utf-8")


def _write_methodology_pitch(output_path: Path, items: list[str]) -> None:
    count = len(items)
    rows = [
        f"# Pitch: Add {count} Methodology Templates",
        "",
        f"**Date:** {date.today().isoformat()}",
        "**Category:** Methodologies",
        "**Source:** layer2-templates/reference/integrated/methodologies-integrated.md",
        "**Status:** Proposed",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"This pitch proposes adding {count} methodology patterns extracted from integrated",
        "project documentation to `layer2-templates/methodologies/`.",
        "",
        "---",
        "",
        "## Proposed Additions",
        "",
        "| Methodology | Existing Similar | Notes |",
        "|-------------|------------------|-------|",
    ]
    for item in items:
        rows.append(f"| `{item}` | TBD | Review source for details |")
    rows.extend([
        "",
        "---",
        "",
        "## Justification",
        "",
        "These methodology patterns were extracted from aggregated project documentation.",
        "Each represents a repeatable security research approach.",
        "",
        "## Integration Path",
        "",
        "1. Review each methodology for completeness",
        "2. Check for overlap with existing templates",
        "3. Create new template files in `layer2-templates/methodologies/`",
        "4. Update METHODOLOGY-ROADMAP.md",
        "",
        "---",
        "",
        "## Verification",
        "",
        "- [ ] No duplicates with existing methodologies/",
        "- [ ] No identifiable project/company names",
        "- [ ] Methodologies are complete and actionable",
        "",
    ])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(rows), encoding="utf-8")


def _write_workflow_pitch(output_path: Path, items: list[str]) -> None:
    count = len(items)
    rows = [
        f"# Pitch: Add {count} Workflow Templates",
        "",
        f"**Date:** {date.today().isoformat()}",
        "**Category:** Workflows",
        "**Source:** layer2-templates/reference/integrated/workflows-integrated.md",
        "**Status:** Proposed",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"This pitch proposes adding {count} workflow patterns extracted from integrated",
        "project documentation to `layer2-templates/workflows/`.",
        "",
        "---",
        "",
        "## Proposed Additions",
        "",
        "| Workflow | Existing Similar | Notes |",
        "|----------|------------------|-------|",
    ]
    for item in items:
        rows.append(f"| `{item}` | TBD | Review source for details |")
    rows.extend([
        "",
        "---",
        "",
        "## Justification",
        "",
        "These workflow patterns were extracted from aggregated project documentation.",
        "Each represents a repeatable operational sequence.",
        "",
        "## Integration Path",
        "",
        "1. Review each workflow for completeness",
        "2. Check for overlap with existing templates",
        "3. Create new template files in `layer2-templates/workflows/`",
        "4. Link to related methodologies and tools",
        "",
        "---",
        "",
        "## Verification",
        "",
        "- [ ] No duplicates with existing workflows/",
        "- [ ] No identifiable project/company names",
        "- [ ] Workflows are complete and actionable",
        "",
    ])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(rows), encoding="utf-8")


HELP_EPILOG = """\
EXAMPLES:
    # Preview all extractions
    ./layer1/scripts/dedupe-integrated.py --dry-run --all

    # Process only tools and create pitch
    ./layer1/scripts/dedupe-integrated.py --tools

    # Process everything with verbose output
    ./layer1/scripts/dedupe-integrated.py --all --verbose

FILES:
    Source files (read-only):
        layer2-templates/reference/integrated/tools-integrated.md
        layer2-templates/reference/integrated/skills-integrated.md
        layer2-templates/reference/integrated/methodologies-integrated.md
        layer2-templates/reference/integrated/workflows-integrated.md

    Master TOCs (for comparison):
        layer2-templates/toolset.md
        layer2-templates/skillset.md
        layer2-templates/methodologies/*.md
        layer2-templates/workflows/*.md

    Output:
        layer3-engagement/pitches/YYYY-MM-DD-tool-additions.md
        layer3-engagement/pitches/YYYY-MM-DD-skill-additions.md
        layer3-engagement/pitches/YYYY-MM-DD-methodology-additions.md
        layer3-engagement/pitches/YYYY-MM-DD-workflow-additions.md
"""


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="dedupe-integrated.py - Extract and deduplicate items from integrated reference files",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be added without creating pitch files.")
    parser.add_argument("--tools", action="store_true", help="Process only tools.")
    parser.add_argument("--skills", action="store_true", help="Process only skills.")
    parser.add_argument("--methods", "--methodologies", action="store_true", help="Process only methodologies.")
    parser.add_argument("--workflows", action="store_true", help="Process only workflows.")
    parser.add_argument("--all", action="store_true", help="Process all categories (default).")
    parser.add_argument(
        "--output",
        default="layer3-engagement/pitches",
        help="Output directory for pitches (default: layer3-engagement/pitches/).",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed extraction info.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()

    try:
        output_dir = _resolve_under_root(body_root, args.output)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] B.R.A. Deduplication Script", file=sys.stderr)
    print(f"[INFO] Working directory: {body_root}", file=sys.stderr)

    selected = {
        "tools": args.tools,
        "skills": args.skills,
        "methods": args.methods,
        "workflows": args.workflows,
    }
    if args.all or not any(selected.values()):
        selected = {key: True for key in selected}

    if args.dry_run:
        print("[WARN] DRY-RUN mode - no files will be created", file=sys.stderr)

    integrated_dir = body_root / "layer2-templates" / "reference" / "integrated"
    master_dir = body_root / "layer2-templates"

    # Verify source directory exists
    if not integrated_dir.is_dir():
        print(f"[ERROR] Integrated directory not found: {integrated_dir}", file=sys.stderr)
        return 1

    # Per-category extractors
    extractors = {
        "tools": lambda src: _extract_tools(src),
        "skills": lambda src: _extract_skills(src),
        "methods": lambda src: _extract_methodologies(src),
        "workflows": lambda src: _extract_workflows(src),
    }

    # Human-readable labels for processing headers
    bucket_labels = {
        "tools": "Tools",
        "skills": "Skills",
        "methods": "Methodologies",
        "workflows": "Workflows",
    }

    # Master TOC descriptions for log messages
    master_sources = {
        "tools": master_dir / "toolset.md",
        "skills": master_dir / "skillset.md",
        "methods": master_dir / "methodologies",
        "workflows": master_dir / "workflows",
    }

    definitions = {
        "tools": {
            "source": integrated_dir / "tools-integrated.md",
            "existing": _extract_names_generic(master_dir / "toolset.md"),
            "title": "Tool Additions",
            "filename": f"{date.today().isoformat()}-tool-additions.md",
        },
        "skills": {
            "source": integrated_dir / "skills-integrated.md",
            "existing": _extract_names_generic(master_dir / "skillset.md"),
            "title": "Skill Additions",
            "filename": f"{date.today().isoformat()}-skill-additions.md",
        },
        "methods": {
            "source": integrated_dir / "methodologies-integrated.md",
            "existing": _from_file_stems(master_dir / "methodologies"),
            "title": "Methodology Templates",
            "filename": f"{date.today().isoformat()}-methodology-additions.md",
        },
        "workflows": {
            "source": integrated_dir / "workflows-integrated.md",
            "existing": _from_file_stems(master_dir / "workflows"),
            "title": "Workflow Templates",
            "filename": f"{date.today().isoformat()}-workflow-additions.md",
        },
    }

    generated = 0
    total_missing = 0

    for bucket, enabled in selected.items():
        if not enabled:
            continue

        label = bucket_labels[bucket]
        print(f"[INFO] === Processing {label} ===", file=sys.stderr)

        source = definitions[bucket]["source"]
        if not source.is_file():
            print(f"[ERROR] Source file not found: {source}", file=sys.stderr)
            continue

        print(f"[INFO] Extracting {label.lower()} from: {source}", file=sys.stderr)
        extractor = extractors[bucket]
        extracted = extractor(source)

        if args.verbose:
            print(f"[DEBUG] Extracted {len(extracted)} raw {label.lower()} candidates", file=sys.stderr)

        # Load existing items
        master_src = master_sources[bucket]
        if master_src.exists():
            print(f"[INFO] Loading existing {label.lower()} from: {master_src}", file=sys.stderr)
        else:
            print(f"[WARN] Master {label.lower()} not found: {master_src}", file=sys.stderr)

        existing = definitions[bucket]["existing"]

        if args.verbose:
            print(f"[DEBUG] Found {len(existing)} existing {label.lower()} in master TOC", file=sys.stderr)

        missing = sorted(name for name in extracted if name and name not in existing)
        total_missing += len(missing)

        print(f"[INFO] Extracted: {len(extracted)} | Existing: {len(existing)} | New: {len(missing)}", file=sys.stderr)

        if not missing:
            print(f"[WARN] No new {label.lower()} to add", file=sys.stderr)
            continue

        if args.dry_run:
            print(f"[INFO] [DRY-RUN] Would create pitch with {len(missing)} new {label.lower()}:", file=sys.stderr)
            for item in missing[:20]:
                print(item)
            if len(missing) > 20:
                print(f"... and {len(missing) - 20} more")
            continue

        pitch_path = output_dir / definitions[bucket]["filename"]
        if bucket == "tools":
            _write_tool_pitch(pitch_path, missing)
        elif bucket == "skills":
            _write_skill_pitch(pitch_path, missing)
        elif bucket == "methods":
            _write_methodology_pitch(pitch_path, missing)
        elif bucket == "workflows":
            _write_workflow_pitch(pitch_path, missing)
        print(f"[OK] Created {label.lower()} pitch: {pitch_path}", file=sys.stderr)
        generated += 1

    print(f"[INFO] === Summary ===", file=sys.stderr)
    if total_missing == 0:
        return 0
    if args.dry_run:
        print(f"[DRY-RUN] total candidates: {total_missing}")
    else:
        print(f"[INFO] Pitch files created in: {output_dir}", file=sys.stderr)
        print(f"Generated {generated} pitch file(s), candidates={total_missing}")
    print(f"[OK] Done!", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
