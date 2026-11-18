#!/usr/bin/env python3
"""Native Python port of ingest.sh."""

from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path


SECTION_RE = re.compile(r"^##\s+[0-9]+\.\s+(.+)")
CHECKED_RE = re.compile(r"^-\s+\[[xX]\]\s+\*\*(.+)\*\*:?[ \t]*(.*)")
FINDING_RE = re.compile(r"^\[?(FINDING-[0-9]+)\]?\s*(.*)")
STATUS_RE = re.compile(r"\*\*Status:\*\*.*")


def _trim(value: str) -> str:
    return " ".join(value.split())


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]", "-", value.lower())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def _json_error(message: str) -> str:
    return json.dumps({"status": "error", "message": message}, separators=(",", ":"))


def _json_array(values: list[str]) -> list[str]:
    return list(values)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("Usage: ingest.sh <pitch_file>", file=sys.stderr)
        return 1

    pitch_file = Path(args[0])

    if not pitch_file.is_file():
        print(_json_error("Pitch file not found."))
        return 1

    body_root = Path(__file__).resolve().parents[2]
    layer2 = body_root / "layer2-templates"
    today = date.today().isoformat()

    created: list[str] = []
    appended: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    lines = pitch_file.read_text(encoding="utf-8").splitlines()

    engagement = "unknown"
    for line in lines:
        if "**Engagement:**" in line:
            engagement = _trim(line.split("**Engagement:**", 1)[1])
            break

    current_section = ""
    for line in lines:
        section_match = SECTION_RE.match(line)
        if section_match:
            current_section = _trim(section_match.group(1))
            continue

        checked_match = CHECKED_RE.match(line)
        if not checked_match:
            continue

        title = _trim(checked_match.group(1))
        desc = _trim(checked_match.group(2))

        if current_section == "Methodology Improvements":
            slug = _slugify(desc)
            if not slug:
                slug = _slugify(title)
            meth_file = layer2 / "methodologies" / f"{slug}.md"

            if meth_file.is_file():
                skipped.append(f"methodologies/{slug}.md (exists)")
                continue

            meth_file.parent.mkdir(parents=True, exist_ok=True)
            meth_file.write_text(
                f"# {desc} Methodology Template\n\n"
                "> **Template Version:** 1.0\n"
                f"> **Derived From:** {engagement}\n"
                f"> **Target:** {desc}\n\n"
                "---\n\n"
                "## Overview\n\n"
                f"TODO: Add overview for {desc} methodology.\n\n"
                "---\n\n"
                "## Phase 1: Reconnaissance\n\n"
                "### Objectives\n"
                "- [ ] Identify target attack surface\n"
                "- [ ] Enumerate relevant endpoints/interfaces\n"
                "- [ ] Map data flows and trust boundaries\n\n"
                "### Techniques\n\n"
                "```bash\n"
                "# TODO: Add reconnaissance commands\n"
                "```\n\n"
                "### Deliverables\n"
                "- [ ] Attack surface map\n"
                "- [ ] Target inventory\n\n"
                "---\n\n"
                "## Phase 2: Testing\n\n"
                "### Objectives\n"
                "- [ ] Test identified attack vectors\n"
                "- [ ] Validate potential vulnerabilities\n"
                "- [ ] Document exploitation steps\n\n"
                "### Techniques\n\n"
                "```bash\n"
                "# TODO: Add testing commands\n"
                "```\n\n"
                "### Deliverables\n"
                "- [ ] Test results\n"
                "- [ ] Vulnerability evidence\n\n"
                "---\n\n"
                "## Phase 3: Analysis & Reporting\n\n"
                "### Objectives\n"
                "- [ ] Analyze findings for severity and impact\n"
                "- [ ] Develop remediation recommendations\n"
                "- [ ] Document proof of concept\n\n"
                "### Deliverables\n"
                "- [ ] Finding write-ups\n"
                "- [ ] Remediation guidance\n",
                encoding="utf-8",
            )
            created.append(f"methodologies/{slug}.md")
            continue

        if current_section == "Attack Chain Patterns":
            chain_slug = _slugify(engagement)
            chain_file = layer2 / "attack-chains" / f"{today}-{chain_slug}.md"

            finding_id = ""
            finding_title = desc
            finding_match = FINDING_RE.match(desc)
            if finding_match:
                finding_id = finding_match.group(1)
                finding_title = re.sub(r"^[— -]*", "", finding_match.group(2))

            entry_parts = [
                f"\n### {title}: {finding_title}\n\n",
            ]
            if finding_id:
                entry_parts.append(f"> **Finding:** {finding_id}\n")
            entry_parts.extend(
                [
                    f"> **Source:** {engagement}\n",
                    f"> **Date:** {today}\n\n",
                    "#### Description\n\n",
                    "TODO: Document the attack pattern.\n\n",
                    "#### Steps\n\n",
                    "1. TODO\n\n",
                    "#### Indicators\n\n",
                    "- TODO\n\n",
                    "---\n",
                ]
            )
            entry = "".join(entry_parts)

            if not chain_file.is_file():
                chain_file.parent.mkdir(parents=True, exist_ok=True)
                chain_file.write_text(
                    f"# Attack Chain Patterns — {engagement}\n\n"
                    f"> **Generated:** {today}\n"
                    f"> **Source Engagement:** {engagement}\n"
                    "> **Purpose:** Reusable attack patterns extracted from engagement findings\n\n"
                    "---\n",
                    encoding="utf-8",
                )
                with chain_file.open("a", encoding="utf-8") as f:
                    f.write(entry)
                created.append(f"attack-chains/{today}-{chain_slug}.md")
            else:
                with chain_file.open("a", encoding="utf-8") as f:
                    f.write(entry)
                appended.append(f"attack-chains/{today}-{chain_slug}.md ({title})")
            continue

        if current_section == "Skill Additions":
            skill_file = layer2 / "skillset.md"
            if skill_file.is_file():
                skill_content = skill_file.read_text(encoding="utf-8")
                if "## Pending Review (from Growth Proposals)" not in skill_content:
                    with skill_file.open("a", encoding="utf-8") as f:
                        f.write(
                            "\n---\n\n"
                            "## Pending Review (from Growth Proposals)\n\n"
                            "| Skill | Description | Source |\n"
                            "|-------|-------------|--------|\n"
                        )
                with skill_file.open("a", encoding="utf-8") as f:
                    f.write(f"| {desc or title} | From {engagement} | {today} |\n")
                appended.append(f"skillset.md ({desc or title})")
            else:
                errors.append("skillset.md not found")
            continue

        if current_section == "Tool Additions":
            tool_file = layer2 / "toolset.md"
            if tool_file.is_file():
                tool_content = tool_file.read_text(encoding="utf-8")
                if "## Pending Review (from Growth Proposals)" not in tool_content:
                    with tool_file.open("a", encoding="utf-8") as f:
                        f.write(
                            "\n---\n\n"
                            "## Pending Review (from Growth Proposals)\n\n"
                            "| Tool | Purpose | Source |\n"
                            "|------|---------|--------|\n"
                        )
                with tool_file.open("a", encoding="utf-8") as f:
                    f.write(f"| {desc or title} | TODO | {engagement} ({today}) |\n")
                appended.append(f"toolset.md ({desc or title})")
            else:
                errors.append("toolset.md not found")
            continue

        skipped.append(f"{current_section}: {title} — {desc}")

    pitch_text = pitch_file.read_text(encoding="utf-8")
    updated_pitch = STATUS_RE.sub("**Status:** INGESTED", pitch_text)
    pitch_file.write_text(updated_pitch, encoding="utf-8")

    ingest_dir = body_root / "layer3-engagement" / "ingest"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    moved_path = ingest_dir / pitch_file.name
    shutil.move(str(pitch_file), str(moved_path))
    moved = f"ingest/{pitch_file.name}"

    total = len(created) + len(appended)
    payload = {
        "status": "ok",
        "message": f"Ingested {total} proposal(s) into layer2-templates.",
        "moved": moved,
        "created": _json_array(created),
        "appended": _json_array(appended),
        "skipped": _json_array(skipped),
        "errors": _json_array(errors),
    }
    print(json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
