# head/bra/core/pitch_manager.py
"""Pitch file operations for Growth view.

Handles reading, updating, and promoting proposals in pitch files.
"""

import re
from pathlib import Path
from typing import Any

from bra.core.bridge import run_script


# Section name to target file mapping
SECTION_TARGETS = {
    "Skill Additions": "layer2-templates/skillset.md",
    "Tool Additions": "layer2-templates/toolset.md",
    "Methodology Improvements": "layer2-templates/methodologies/",
    "Attack Chain Patterns": "layer2-templates/attack-chains/",
    "Attack Surface Expansion": "(manual placement required)",
}

# Status checkbox mappings
STATUS_TO_CHECKBOX = {
    "approved": "[x]",
    "denied": "[-]",
    "deferred": "[?]",
    "pending": "[ ]",
}

CHECKBOX_TO_STATUS = {
    " ": "pending",
    "x": "approved",
    "-": "denied",
    "?": "deferred",
}


def update_proposal_status(file_path: str, line_num: int, new_status: str) -> bool:
    """Update checkbox status at specific line.

    Args:
        file_path: Path to pitch file
        line_num: 1-indexed line number
        new_status: "approved" → [x], "denied" → [-], "deferred" → [?]

    Returns:
        True on success, False on error
    """
    path = Path(file_path)
    if not path.exists():
        return False

    new_checkbox = STATUS_TO_CHECKBOX.get(new_status)
    if not new_checkbox:
        return False

    try:
        lines = path.read_text().splitlines()

        # Validate line number
        if line_num < 1 or line_num > len(lines):
            return False

        line = lines[line_num - 1]

        # Match and replace checkbox pattern: - [ ], - [x], - [-], - [?]
        match = re.match(r'^(- \[)[ x\-\?](\].*)$', line)
        if not match:
            return False

        # Reconstruct line with new checkbox
        new_line = f"{match.group(1)}{new_checkbox[1]}{match.group(2)}"
        lines[line_num - 1] = new_line

        # Write back
        path.write_text('\n'.join(lines) + '\n')
        return True

    except (OSError, IOError):
        return False


def run_promotion() -> dict[str, Any]:
    """Execute promotion.py logic via bridge.

    Calls: bridge.run_script("growth.py", "--promote")

    Returns:
        {"promoted": int, "skipped": int, "failed": int, "output": str}
    """
    result = {
        "promoted": 0,
        "skipped": 0,
        "failed": 0,
        "output": "",
    }

    try:
        proc = run_script("growth.py", "--promote", timeout=60)
        result["output"] = proc.stdout or ""

        # Parse output for counts
        if proc.returncode == 0:
            # Look for patterns like "Promoted: 3" or "3 items promoted"
            promoted_match = re.search(r'[Pp]romoted[:\s]+(\d+)', proc.stdout or "")
            skipped_match = re.search(r'[Ss]kipped[:\s]+(\d+)', proc.stdout or "")
            failed_match = re.search(r'[Ff]ailed[:\s]+(\d+)', proc.stdout or "")

            if promoted_match:
                result["promoted"] = int(promoted_match.group(1))
            if skipped_match:
                result["skipped"] = int(skipped_match.group(1))
            if failed_match:
                result["failed"] = int(failed_match.group(1))
        else:
            result["failed"] = 1
            result["output"] = proc.stderr or proc.stdout or "Promotion failed"

    except FileNotFoundError:
        result["failed"] = 1
        result["output"] = "growth.sh not found"
    except Exception as e:
        result["failed"] = 1
        result["output"] = str(e)

    return result


def get_proposal_detail(file_path: str, line_num: int) -> dict[str, Any]:
    """Get full context for detail view.

    Args:
        file_path: Path to pitch file
        line_num: 1-indexed line number

    Returns:
        {
            "section": str,           # e.g., "Skill Additions"
            "target": str,            # e.g., "layer2-templates/skillset.md"
            "text": str,              # Full proposal text
            "status": str,            # Current status
            "related_findings": list, # From <details> block
        }
    """
    result = {
        "section": "",
        "target": "",
        "text": "",
        "status": "pending",
        "related_findings": [],
    }

    path = Path(file_path)
    if not path.exists():
        return result

    content = path.read_text()
    lines = content.splitlines()

    if line_num < 1 or line_num > len(lines):
        return result

    # Get the proposal line
    line = lines[line_num - 1]
    match = re.match(r'^- \[([ x\-\?])\]\s*(.*)$', line)
    if match:
        checkbox, text = match.groups()
        result["text"] = text.strip()
        result["status"] = CHECKBOX_TO_STATUS.get(checkbox, "pending")

    # Find section by scanning backwards from line_num
    for i in range(line_num - 1, -1, -1):
        section_match = re.match(r'^## \d+\.\s+(.+)', lines[i])
        if section_match:
            result["section"] = section_match.group(1).strip()
            result["target"] = get_section_target(result["section"])
            break

    # Extract related findings from <details> blocks
    result["related_findings"] = _extract_findings(content)

    return result


def get_section_target(section_name: str) -> str:
    """Map section name to target file/directory.

    Args:
        section_name: e.g., "Skill Additions"

    Returns:
        Target path or description
    """
    return SECTION_TARGETS.get(section_name, "(unknown target)")


def _extract_findings(content: str) -> list[str]:
    """Extract finding titles from <details> blocks.

    Args:
        content: Full pitch file content

    Returns:
        List of finding titles like "[LOW] Web Server DoS..."
    """
    findings = []

    # Find content inside <details> blocks
    details_pattern = r'<details>.*?</details>'
    for details_match in re.finditer(details_pattern, content, re.DOTALL):
        details_content = details_match.group()

        # Find finding headers: ### [SEVERITY] Title
        finding_pattern = r'###\s+(\[[A-Z]+\]\s+.+)'
        for finding_match in re.finditer(finding_pattern, details_content):
            findings.append(finding_match.group(1).strip())

    return findings
