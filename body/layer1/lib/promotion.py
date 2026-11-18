#!/usr/bin/env python3
"""Promote approved pitch checklist items into Layer 2 templates."""

from __future__ import annotations

from contextlib import contextmanager
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROMOTION_TOKEN_CREATED = False


def _detect_body_root() -> Path:
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if parent.name == "body":
            return parent
    return cwd


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _paths(body_root: Path | None = None) -> dict[str, Path]:
    root = _detect_body_root() if body_root is None else body_root
    return {
        "root": root,
        "token": root / ".bra" / "approvals" / "LAYER2-WRITE-APPROVAL",
        "pitches": root / "layer3-engagement" / "pitches",
        "skillset": root / "layer2-templates" / "skillset.md",
        "toolset": root / "layer2-templates" / "toolset.md",
        "methodologies": root / "layer2-templates" / "methodologies",
        "workflows": root / "layer2-templates" / "workflows",
        "attack_chains": root / "layer2-templates" / "attack-chains",
        "promotion_log": root / ".bra" / "logs" / "promotion.log",
        "overrides": root / "layer2-templates" / "overrides.md",
    }


def _create_layer2_token(body_root: Path | None = None) -> Path:
    """Create temporary write-approval token for Layer 2 template writes."""
    global _PROMOTION_TOKEN_CREATED
    paths = _paths(body_root)
    token_file = paths["token"]
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(
        "\n".join(
            [
                f"# Created by promotion.py at {_utc_now()}",
                "layer2-templates/skillset.md",
                "layer2-templates/toolset.md",
                "layer2-templates/methodologies/*",
                "layer2-templates/workflows/*",
                "layer2-templates/attack-chains/*",
                "layer2-templates/overrides.md",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _PROMOTION_TOKEN_CREATED = True
    return token_file


def _remove_layer2_token(body_root: Path | None = None) -> bool:
    """Remove token file if created by this process."""
    global _PROMOTION_TOKEN_CREATED
    token_file = _paths(body_root)["token"]
    if not _PROMOTION_TOKEN_CREATED or not token_file.is_file():
        return False
    try:
        token_file.unlink()
    except OSError:
        return False
    _PROMOTION_TOKEN_CREATED = False
    return True


@contextmanager
def _layer2_write_scope(body_root: Path | None = None):
    """Match shell behavior by creating a temporary Layer 2 write token."""
    token_file = _paths(body_root)["token"]
    created_here = not token_file.is_file()
    if created_here:
        _create_layer2_token(body_root)
    try:
        yield
    finally:
        if created_here:
            _remove_layer2_token(body_root)


def log_promotion(level: str, message: str, body_root: Path | None = None) -> None:
    """Append entry to promotion activity log."""
    log_file = _paths(body_root)["promotion_log"]
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] [{level}] {message}\n")


def get_pitch_files(body_root: Path | None = None) -> list[Path]:
    """Return pitch markdown files sorted newest-first by name."""
    pitches = _paths(body_root)["pitches"]
    if not pitches.is_dir():
        return []
    return sorted((path for path in pitches.rglob("*.md") if path.is_file()), reverse=True)


def pitch_has_pending(pitch_file: str | Path) -> bool:
    """Return whether pitch contains approved but unimplemented items."""
    try:
        text = Path(pitch_file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(re.search(r"^- \[x\]", text, re.MULTILINE) and not re.search(r"^- \[x\] IMPLEMENTED", text, re.MULTILINE))


def get_approved_items(pitch_file: str | Path) -> list[str]:
    """Return approved checklist lines excluding already implemented items."""
    try:
        lines = Path(pitch_file).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    return [line for line in lines if line.startswith("- [x]") and "IMPLEMENTED" not in line]


def get_item_section(pitch_file: str | Path, line_num: int) -> str:
    """Return nearest numbered section title above line number."""
    try:
        lines = Path(pitch_file).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""

    section = ""
    for idx, line in enumerate(lines, start=1):
        if idx > line_num:
            break
        match = re.match(r"^##\s+[0-9]+\.\s+(.*)$", line)
        if match:
            section = match.group(1).strip()
    return section


def get_section_target(pitch_file: str | Path, section_name: str) -> str:
    """Return `> Target:` value within section."""
    try:
        text = Path(pitch_file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

    section_match = re.search(rf"^##\s+[0-9]+\.\s+{re.escape(section_name)}([\s\S]*?)(?=^##\s+[0-9]+\.\s|\Z)", text, re.MULTILINE)
    if not section_match:
        return ""

    target_match = re.search(r"^>\s*Target:\s*`?(.+?)`?$", section_match.group(1), re.MULTILINE)
    return target_match.group(1).strip() if target_match else ""


def parse_proposal_line(line: str) -> tuple[str, str]:
    """Parse approved checklist line into title/description tuple."""
    match = re.match(r"^- \[x\] \*\*(.+?)\*\*:?\s*(.*)$", line)
    if not match:
        return line.strip(), ""
    return match.group(1).strip(), match.group(2).strip()


def mark_as_implemented(pitch_file: str | Path, line_num: int) -> bool:
    """Mark selected checklist line as implemented."""
    path = Path(pitch_file)
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False

    if line_num < 1 or line_num > len(lines):
        return False

    line = lines[line_num - 1]
    if not line.startswith("- [x]") or "IMPLEMENTED" in line:
        return False

    stamp = datetime.now().strftime("%Y-%m-%d")
    lines[line_num - 1] = line.replace("- [x]", f"- [x] IMPLEMENTED {stamp} -", 1)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return True


def _ensure_heading_table(path: Path, heading: str, table_header: list[str]) -> None:
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    text = path.read_text(encoding="utf-8", errors="ignore")
    if heading in text:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n\n---\n\n")
        handle.write(f"## {heading}\n\n")
        for row in table_header:
            handle.write(row + "\n")


def add_skill(skill_name: str, skill_description: str, body_root: Path | None = None) -> int:
    """Add skill row to layer2 skillset table."""
    path = _paths(body_root)["skillset"]
    if path.is_file() and re.search(rf"\|\s*`?{re.escape(skill_name)}`?\s*\|", path.read_text(encoding="utf-8", errors="ignore"), re.IGNORECASE):
        print(f"  SKIP Skill '{skill_name}' already exists")
        log_promotion("SKIP", f"Skill {skill_name} already exists", body_root)
        return 2

    _ensure_heading_table(
        path,
        "Engagement-Derived Skills",
        ["| Skill | Description | Source |", "|-------|-------------|--------|"],
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"| `{skill_name}` | {skill_description or 'Derived from engagement'} | Pitch promotion |\n")

    print(f"  ADDED Skill '{skill_name}'")
    log_promotion("PROMOTED", f"Skill {skill_name} added to skillset.md", body_root)
    return 0


def add_tool(tool_name: str, tool_purpose: str, body_root: Path | None = None) -> int:
    """Add tool row to layer2 toolset table."""
    path = _paths(body_root)["toolset"]
    if path.is_file() and re.search(rf"\|\s*`?{re.escape(tool_name)}`?\s*\|", path.read_text(encoding="utf-8", errors="ignore"), re.IGNORECASE):
        print(f"  SKIP Tool '{tool_name}' already exists")
        log_promotion("SKIP", f"Tool {tool_name} already exists", body_root)
        return 2

    _ensure_heading_table(
        path,
        "Engagement-Derived Tools",
        ["| Tool | Purpose | Platform | License |", "|------|---------|----------|---------|"],
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"| `{tool_name}` | {tool_purpose or 'Derived from engagement'} | Cross-platform | - |\n")

    print(f"  ADDED Tool '{tool_name}'")
    log_promotion("PROMOTED", f"Tool {tool_name} added to toolset.md", body_root)
    return 0


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", re.sub(r"\s+", "-", name.lower())).strip("-") or "item"


def add_methodology(method_name: str, method_description: str, body_root: Path | None = None) -> int:
    """Create methodology draft markdown file."""
    paths = _paths(body_root)
    filename = _slugify(method_name)
    path = paths["methodologies"] / f"{filename}.md"
    if path.is_file():
        print(f"  SKIP Methodology '{filename}.md' already exists")
        log_promotion("SKIP", f"Methodology {filename}.md already exists", body_root)
        return 2

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                f"# {method_name}",
                "",
                f"> **Created:** {datetime.now().strftime('%Y-%m-%d')}",
                "> **Source:** Engagement pitch promotion",
                "> **Status:** Draft",
                "",
                "---",
                "",
                "## Overview",
                "",
                method_description or "Derived from engagement findings.",
                "",
                "---",
                "",
                "## Phases",
                "",
                "### 1. Intelligence",
                "- [ ] TODO: Define intel steps",
                "",
                "### 2. Analysis",
                "- [ ] TODO: Define analysis steps",
                "",
                "### 3. Testing",
                "- [ ] TODO: Define testing steps",
                "",
                "---",
                "",
                "## Tools Required",
                "",
                "- TODO: List required tools",
                "",
                "---",
                "",
                "## References",
                "",
                "- Derived from engagement findings",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  CREATED Methodology '{filename}.md'")
    log_promotion("PROMOTED", f"Methodology {filename}.md created", body_root)
    return 0


def add_attack_chain(chain_name: str, chain_description: str, body_root: Path | None = None) -> int:
    """Create attack-chain markdown skeleton."""
    paths = _paths(body_root)
    filename = _slugify(chain_name)
    path = paths["attack_chains"] / f"{filename}.md"
    if path.is_file():
        print(f"  SKIP Attack chain '{filename}.md' already exists")
        log_promotion("SKIP", f"Attack chain {filename}.md already exists", body_root)
        return 2

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                f"# Attack Chain: {chain_name}",
                "",
                f"> **Created:** {datetime.now().strftime('%Y-%m-%d')}",
                "> **Source:** Engagement pitch promotion",
                "",
                "---",
                "",
                "## Description",
                "",
                chain_description or "Derived from engagement findings.",
                "",
                "---",
                "",
                "## Chain Steps",
                "",
                "1. **Initial Access**",
                "   - TODO: Document initial access method",
                "",
                "2. **Execution**",
                "   - TODO: Document execution steps",
                "",
                "3. **Impact**",
                "   - TODO: Document impact/outcome",
                "",
                "---",
                "",
                "## Prerequisites",
                "",
                "- TODO: List prerequisites",
                "",
                "## Mitigations",
                "",
                "- TODO: List mitigations",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  CREATED Attack chain '{filename}.md'")
    log_promotion("PROMOTED", f"Attack chain {filename}.md created", body_root)
    return 0


def add_override(override_name: str, override_description: str, source_ref: str = "unknown-pitch", body_root: Path | None = None) -> int:
    """Add override recommendation to layer2 overrides catalog."""
    path = _paths(body_root)["overrides"]
    if path.is_file() and f"### {override_name}" in path.read_text(encoding="utf-8", errors="ignore"):
        print(f"  SKIP Override '{override_name}' already exists")
        log_promotion("SKIP", f"Override {override_name} already exists", body_root)
        return 2

    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                [
                    "# Override Recommendations",
                    "",
                    "> Cross-engagement advisory overrides. Promoted from engagement pitch docs.",
                    "> These are recommendations only — never auto-materialized into `.bra/overrides.json`.",
                    "",
                    "---",
                    "",
                    "## Recommended Overrides",
                    "",
                    "<!-- FORMAT:",
                    "### [TYPE] match_key=match_value",
                    "- **Rationale:** Why this override is recommended",
                    "- **Engagements:** Number of engagements where this was used",
                    "- **Action:** grant_session | allow | FULL | LIMITED",
                    "-->",
                    "",
                    "---",
                    "",
                    "## Engagement Decisions",
                    "",
                    "<!-- Populated during engagement by engage.py -->",
                    "<!-- Each decision is appended as it occurs -->",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n".join(
                [
                    "",
                    f"### {override_name}",
                    f"- **Rationale:** {override_description or 'Derived from engagement findings.'}",
                    "- **Engagements:** 1",
                    "- **Action:** allow",
                    "- **Source Layer:** layer3-engagement/pitches",
                    f"- **Source Pitch:** {source_ref}",
                    f"- **Promoted:** {datetime.now().strftime('%Y-%m-%d')}",
                ]
            )
            + "\n"
        )

    print(f"  ADDED Override recommendation '{override_name}'")
    log_promotion("PROMOTED", f"Override {override_name} added to overrides.md", body_root)
    return 0


def _route_section(section_name: str) -> str:
    lowered = section_name.lower()
    if "skill" in lowered:
        return "skill"
    if "tool" in lowered:
        return "tool"
    if "methodology" in lowered:
        return "methodology"
    if "attack chain" in lowered or "technique pattern" in lowered:
        return "attack_chain"
    if "override" in lowered:
        return "override"
    if "attack surface" in lowered:
        return "manual"
    return "unknown"


def promote_from_pitch(pitch_file: str | Path, dry_run: bool = False, body_root: Path | None = None) -> dict[str, int]:
    """Promote approved checklist items from a single pitch file."""
    with _layer2_write_scope(body_root):
        path = Path(pitch_file)
        if not path.is_file():
            print(f"ERROR Pitch file not found: {path}")
            raise FileNotFoundError(f"Pitch file not found: {path}")

        print(f"\nProcessing: {path.name}")

        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        result = {"promoted": 0, "skipped": 0, "failed": 0}
        current_section = ""

        for idx, line in enumerate(lines, start=1):
            section_match = re.match(r"^##\s+[0-9]+\.\s+(.+)$", line)
            if section_match:
                current_section = section_match.group(1).strip()
                continue

            if not line.startswith("- [x]") or "IMPLEMENTED" in line:
                continue

            title, description = parse_proposal_line(line)
            print(f"  Found: [{current_section}] {title}")

            if dry_run:
                print("    DRY-RUN Would promote to appropriate target")
                result["promoted"] += 1
                continue

            route = _route_section(current_section)
            status = 1
            if route == "skill":
                status = add_skill(title, description, body_root)
            elif route == "tool":
                status = add_tool(title, description, body_root)
            elif route == "methodology":
                status = add_methodology(title, description, body_root)
            elif route == "attack_chain":
                status = add_attack_chain(title, description, body_root)
            elif route == "override":
                status = add_override(title, description, path.name, body_root)
            elif route == "manual":
                print("  MANUAL Attack surface items require manual placement")
                log_promotion("MANUAL", f"Attack surface: {title} - requires manual decision", body_root)
                result["skipped"] += 1
                continue
            else:
                print(f"  UNKNOWN Section '{current_section}' - skipping")
                log_promotion("UNKNOWN", f"Unknown section '{current_section}' for item '{title}'", body_root)
                result["skipped"] += 1
                continue

            if status in {0, 2}:
                if mark_as_implemented(path, idx):
                    pass
                if status == 0:
                    result["promoted"] += 1
                else:
                    result["skipped"] += 1
            else:
                result["failed"] += 1

        print(f"  Summary: {result['promoted']} promoted, {result['skipped']} skipped, {result['failed']} failed")
        return result


def get_pending_promotions(body_root: Path | None = None) -> dict[str, Any]:
    """Return pending approved-item counts per pitch and total."""
    print("=== Pending Promotions ===")
    print("")
    summary: dict[str, Any] = {"total": 0, "files": {}}
    files_with_pending = 0
    for pitch in get_pitch_files(body_root):
        approved = len(get_approved_items(pitch))
        if approved <= 0:
            continue
        summary["files"][str(pitch)] = approved
        summary["total"] += approved
        files_with_pending += 1
        print(f"  {pitch.name}: {approved} pending")
    print("")
    print(f"Total: {summary['total']} pending items in {files_with_pending} files")
    return summary


def promote_all(dry_run: bool = False, body_root: Path | None = None) -> dict[str, Any]:
    """Promote approved items from all pitch files."""
    with _layer2_write_scope(body_root):
        bar = "\u2550" * 64
        print(bar)
        print("  PITCH PROPOSAL PROMOTION")
        if dry_run:
            print("  MODE: DRY-RUN (no changes will be made)")
        print(bar)

        aggregate = {"promoted": 0, "skipped": 0, "failed": 0, "files": 0}
        for pitch in get_pitch_files(body_root):
            if not pitch_has_pending(pitch):
                continue
            stats = promote_from_pitch(pitch, dry_run=dry_run, body_root=body_root)
            aggregate["promoted"] += stats["promoted"]
            aggregate["skipped"] += stats["skipped"]
            aggregate["failed"] += stats["failed"]
            aggregate["files"] += 1

        if aggregate["files"] == 0:
            print("")
            print("No pending promotions found.")
            print("Approve items in pitch documents first (mark with [x]).")

        print("")
        print(bar)
        print("  Promotion complete")
        print(bar)
        return aggregate


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        print("promotion.py --pending | --promote-all [--dry-run] | --promote <pitch.md>")
        return 0

    if args[0] == "--pending":
        get_pending_promotions()
        return 0

    if args[0] == "--promote-all":
        dry = "--dry-run" in args[1:]
        promote_all(dry_run=dry)
        return 0

    if args[0] == "--promote" and len(args) >= 2:
        dry = "--dry-run" in args[2:]
        promote_from_pitch(args[1], dry_run=dry)
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
