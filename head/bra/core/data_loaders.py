# head/bra/core/data_loaders.py
"""Data loaders for TUI menu views.

Loads and parses engagement data from layer3-engagement files.
"""

import json
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from bra.config import settings as _settings


@dataclass
class Proposal:
    """A proposal item from a pitch file."""
    text: str           # The proposal text
    file: str           # Source pitch file path
    line_num: int       # Line number in file (for updates)
    section: str        # "Skill Additions", "Tool Additions", etc.
    status: str         # "pending" [ ], "approved" [x], "denied" [-], "deferred" [?]
    implemented: bool   # Has IMPLEMENTED marker


def load_health() -> dict[str, Any]:
    """Load health/precheck data.

    Returns:
        Dictionary with:
        - exists: bool
        - summary: dict with PASS/FIXED/FAIL/SKIP counts
        - status: overall status string
        - generated: timestamp string
        - sections: list of check sections
    """
    precheck_file = _settings._settings.BRA_STATE / "PRECHECK_REPORT.md"

    if not precheck_file.exists():
        return {"exists": False, "summary": {}, "status": None, "generated": None}

    content = precheck_file.read_text()

    result = {
        "exists": True,
        "summary": {"PASS": 0, "FIXED": 0, "FAIL": 0, "SKIP": 0},
        "status": None,
        "generated": None,
        "sections": []
    }

    # Extract generated timestamp
    gen_match = re.search(r'\*\*Generated:\*\*\s*(.+)', content)
    if gen_match:
        result["generated"] = gen_match.group(1).strip()

    # Extract status - supports both "**Overall Status:** VALUE" and "Status: **VALUE**"
    status_match = re.search(r'\*\*Overall Status:\*\*\s*(.+)', content)
    if not status_match:
        status_match = re.search(r'Status:\s*\*\*(.+?)\*\*', content)
    if status_match:
        result["status"] = status_match.group(1).strip()

    # Parse summary table (| PASS | 87 | format)
    for key in ["PASS", "FIXED", "FAIL", "SKIP"]:
        table_match = re.search(rf'\|\s*{key}\s*\|\s*(\d+)\s*\|', content)
        if table_match:
            result["summary"][key] = int(table_match.group(1))
        else:
            # Fallback to [PASS] marker counting
            result["summary"][key] = len(re.findall(rf'\[{key}\]', content))

    return result


def load_intel() -> dict[str, Any]:
    """Load intelligence data from INTEL.md.

    Returns:
        Dictionary with:
        - exists: bool
        - target: target string
        - date: date string
        - sections: list of (name, content) tuples
        - raw_content: full file content for display
    """
    intel_locations = [
        _settings.LAYER3 / "NOTES" / "INTEL.md",
        _settings.LAYER3 / "INTEL.md",
    ]

    for loc in intel_locations:
        if loc.exists():
            content = loc.read_text()
            result = {
                "exists": True,
                "target": None,
                "date": None,
                "sections": [],
                "tables": {},
                "raw_content": content
            }

            # Extract metadata - support multiple formats
            target_match = re.search(r'\*\*(?:Target|Engagement):\*\*\s*(.+)', content)
            date_match = re.search(r'\*\*(?:Date|Started):\*\*\s*(.+)', content)

            if target_match:
                result["target"] = target_match.group(1).strip()
            if date_match:
                result["date"] = date_match.group(1).strip()

            # Extract sections with content
            section_pattern = r'^##\s+(.+?)(?=\n##|\Z)'
            section_names = re.findall(r'^##\s+(.+)', content, re.MULTILINE)
            result["tables"] = {name: [] for name in section_names}

            # Split by ## headers to get section content
            parts = re.split(r'\n(?=## )', content)
            for part in parts[1:]:  # Skip the header part
                lines = part.strip().split('\n')
                if lines:
                    name = lines[0].lstrip('#').strip()
                    body = '\n'.join(lines[1:]).strip()
                    result["sections"].append((name, body))

            return result

    return {"exists": False, "target": None, "date": None, "sections": [], "tables": {}, "raw_content": ""}


def _get_target_from_scope() -> str | None:
    """Extract target name from SCOPE.md."""
    scope_file = _settings.LAYER3 / "SCOPE.md"
    if not scope_file.exists():
        return None

    content = scope_file.read_text()
    for line in content.splitlines():
        line_stripped = line.lstrip("- ").strip()
        if line_stripped.startswith("**Name:**"):
            return line_stripped.replace("**Name:**", "").strip()
    return None


def load_summary() -> dict[str, Any]:
    """Load summary/stats data from STATS.md.

    Returns:
        Dictionary with:
        - exists: bool
        - title: string
        - target: string (from SCOPE.md)
        - date: string
        - tldr: string
        - findings: dict with severity counts
        - recommendations: int count
    """
    stats_file = _settings.LAYER3 / "STATS.md"

    if stats_file.exists():
        content = stats_file.read_text()
        result = {
            "exists": True,
            "title": None,
            "target": _get_target_from_scope(),  # Get from SCOPE.md
            "date": None,
            "tldr": None,
            "findings": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "recommendations": 0
        }

        # Extract metadata
        title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
        date_match = re.search(r'Generated:\s*(.+)', content)

        if title_match:
            result["title"] = title_match.group(1).strip()
        if date_match:
            result["date"] = date_match.group(1).strip()

        # Extract TL;DR from Executive Summary section
        tldr_match = re.search(r'## Executive Summary\s*\n\n(.+?)(?=\n\n---|\n\n##)', content, re.DOTALL)
        if tldr_match:
            tldr = tldr_match.group(1).strip()
            result["tldr"] = tldr[:100] + "..." if len(tldr) > 100 else tldr

        # Count findings by severity from Finding Statistics table
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            match = re.search(rf'\|\s*{sev}\s*\|\s*(\d+)\s*\|', content, re.IGNORECASE)
            if match:
                result["findings"][sev] = int(match.group(1))

        # Count recommendations (checklist items in Coverage Gaps)
        gaps_match = re.search(r'## Coverage Gaps\s*\n\n((?:- \[.\].+\n?)+)', content)
        if gaps_match:
            result["recommendations"] = len(gaps_match.group(1).strip().split('\n'))

        return result

    return {"exists": False, "title": None, "target": None, "date": None, "tldr": None, "findings": {}, "recommendations": 0}


def load_report() -> dict[str, Any]:
    """Load disclosure report data.

    Returns:
        Dictionary with:
        - exists: bool
        - package_status: string
        - policy: string
        - day: current day number
        - total_days: policy days
        - timeline_events: int count
        - checklist_done: int
        - checklist_total: int
        - findings_count: int
    """
    disclosure_dir = _settings.LAYER3 / "disclosure"
    timeline_file = disclosure_dir / "timeline.md"
    package_file = disclosure_dir / "disclosure-package.md"

    result = {
        "exists": False,
        "package_status": None,
        "policy": None,
        "day": 0,
        "total_days": 90,
        "timeline_events": 0,
        "checklist_done": 0,
        "checklist_total": 0,
        "findings_count": 0
    }

    if timeline_file.exists():
        result["exists"] = True
        content = timeline_file.read_text()

        policy_match = re.search(r'Policy:\s*(.+)', content)
        if policy_match:
            result["policy"] = policy_match.group(1).strip()
            # Try to extract days from policy
            days_match = re.search(r'(\d+)-day', policy_match.group(1))
            if days_match:
                result["total_days"] = int(days_match.group(1))

        # Count timeline events
        result["timeline_events"] = len(re.findall(r'^\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|', content, re.MULTILINE))

        # Count checklist items
        checked = len(re.findall(r'-\s*\[[xX]\]', content))
        total = len(re.findall(r'-\s*\[[ xX]\]', content))
        result["checklist_done"] = checked
        result["checklist_total"] = total

    if package_file.exists():
        result["exists"] = True
        content = package_file.read_text()

        status_match = re.search(r'Status:\s*(.+)', content)
        if status_match:
            result["package_status"] = status_match.group(1).strip()

        # Count findings in package
        result["findings_count"] = len(re.findall(r'###\s*\[(\w+)\]', content))

    return result


def _parse_pitch_proposals(file_path: Path) -> list[Proposal]:
    """Parse a pitch file extracting all proposals with metadata.

    Args:
        file_path: Path to the pitch file

    Returns:
        List of Proposal objects with line numbers and sections
    """
    proposals = []
    current_section = ""

    try:
        content = file_path.read_text()
    except (OSError, IOError):
        return proposals

    for line_num, line in enumerate(content.splitlines(), 1):
        # Track section headers: ## N. Section Name
        section_match = re.match(r'^## \d+\.\s+(.+)', line)
        if section_match:
            current_section = section_match.group(1).strip()
            continue

        # Parse proposal lines: - [ ] text, - [x] text, - [-] text, - [?] text
        proposal_match = re.match(r'^- \[([ x\-\?])\]\s*(.*)$', line, re.IGNORECASE)
        if proposal_match:
            checkbox, text = proposal_match.groups()
            checkbox = checkbox.lower() if checkbox != ' ' else ' '
            implemented = "IMPLEMENTED" in text.upper()

            status = {
                " ": "pending",
                "x": "approved",
                "-": "denied",
                "?": "deferred"
            }.get(checkbox, "pending")

            proposals.append(Proposal(
                text=text.strip(),
                file=str(file_path),
                line_num=line_num,
                section=current_section,
                status=status,
                implemented=implemented,
            ))

    return proposals


def load_growth() -> dict[str, Any]:
    """Load growth/pitches data with full proposal tracking.

    Returns:
        Dictionary with:
        - exists: bool
        - pitch_count: int
        - pending_count: int
        - proposals: dict with pending/approved/denied/deferred counts
        - pending_proposals: list of Proposal objects needing decision
        - approved_proposals: list of Proposal objects ready to commit
        - decided_proposals: list of denied/deferred Proposal objects
        - lessons_learned: dict with exists, path, sections
        - improvements: dict from improvement_state.json
    """
    import json
    pitches_dir = _settings.LAYER3 / "pitches"

    result = {
        "exists": False,
        "pitch_count": 0,
        "pending_count": 0,
        "proposals": {"pending": 0, "approved": 0, "denied": 0, "deferred": 0},
        "pending_proposals": [],
        "approved_proposals": [],
        "decided_proposals": [],
        "lessons_learned": {"exists": False, "sections": []},
        "improvements": {"pending": 0, "counter": 0}
    }

    # Track seen proposals to avoid duplicates (by file+line_num)
    seen_proposals: set[tuple[str, int]] = set()

    def add_proposals_from_file(pitch_file: Path) -> None:
        """Parse and add proposals from a pitch file."""
        proposals = _parse_pitch_proposals(pitch_file)
        for p in proposals:
            key = (p.file, p.line_num)
            if key in seen_proposals:
                continue
            seen_proposals.add(key)

            # Count by status
            result["proposals"][p.status] = result["proposals"].get(p.status, 0) + 1

            # Group by status
            if p.status == "pending":
                result["pending_proposals"].append(p)
            elif p.status == "approved" and not p.implemented:
                result["approved_proposals"].append(p)
            else:
                result["decided_proposals"].append(p)

    # Check pitches directory
    if pitches_dir.exists():
        result["exists"] = True
        pitch_files = list(pitches_dir.glob("*.md"))
        result["pitch_count"] = len(pitch_files)

        for pitch_file in pitch_files:
            content = pitch_file.read_text()

            # Check if pending (file-level status)
            if re.search(r'Status:\s*.*PENDING', content, re.IGNORECASE):
                result["pending_count"] += 1

            add_proposals_from_file(pitch_file)

    # Check .growth_pending for additional pending pitches
    growth_pending_file = _settings.BRA_STATE / "artifacts" / ".growth_pending"
    if growth_pending_file.exists():
        result["exists"] = True
        pending_paths = growth_pending_file.read_text().strip().split('\n')
        for path_str in pending_paths:
            if path_str:
                pending_path = Path(path_str)
                if not pending_path.exists():
                    pending_path = _settings.LAYER3 / "pitches" / pending_path.name
                if pending_path.exists():
                    add_proposals_from_file(pending_path)

    # Check lessons-learned
    lessons_file = _settings.LAYER3 / "LESSONS-LEARNED.md"
    if lessons_file.exists():
        result["exists"] = True
        result["lessons_learned"]["exists"] = True
        content = lessons_file.read_text()
        sections = re.findall(r'^## \d+\.\s+(.+)', content, re.MULTILINE)
        result["lessons_learned"]["sections"] = sections

    # Check improvement state
    improvement_file = _settings.BRA_STATE / "improvement_state.json"
    if improvement_file.exists():
        result["exists"] = True
        try:
            state = json.loads(improvement_file.read_text())
            result["improvements"]["pending"] = state.get("pending_improvements", 0)
            result["improvements"]["counter"] = state.get("improvement_counter", 0)
        except (json.JSONDecodeError, KeyError):
            pass

    return result


def load_loadout() -> dict[str, Any]:
    """Load loadout data (skills, tools, methodologies, workflows).

    Returns:
        Dictionary with:
        - exists: bool
        - skills_categories: int
        - skills: list of category names
        - tools_categories: int
        - tools: list of tool category names
        - methodologies_count: int
        - methodologies: list of methodology names
        - workflows_count: int
        - workflows: list of workflow names
    """
    result = {
        "exists": False,
        "skills_categories": 0,
        "skills": [],
        "tools_categories": 0,
        "tools": [],
        "methodologies_count": 0,
        "methodologies": [],
        "workflows_count": 0,
        "workflows": [],
        "overrides_count": 0,
        "overrides_active": 0,
        "overrides": [],
    }

    # Check skillset
    skillset_file = _settings.LAYER3 / "skillset.md"
    if not skillset_file.exists():
        skillset_file = _settings.LAYER2 / "skillset.md"
    if skillset_file.exists():
        result["exists"] = True
        content = skillset_file.read_text()
        skills = re.findall(r'^## \d+\.\s+(.+)', content, re.MULTILINE)
        result["skills_categories"] = len(skills)
        result["skills"] = skills

    # Check toolset
    toolset_file = _settings.LAYER2 / "toolset.md"
    if toolset_file.exists():
        result["exists"] = True
        content = toolset_file.read_text()
        tools = re.findall(r'^###\s+(.+)', content, re.MULTILINE)
        result["tools_categories"] = len(tools)
        result["tools"] = tools

    # Check methodologies
    methods_dir = _settings.LAYER2 / "methodologies"
    if methods_dir.exists():
        result["exists"] = True
        method_files = [f for f in methods_dir.glob("*.md") if f.name != "METHODOLOGY-ROADMAP.md"]
        result["methodologies_count"] = len(method_files)
        result["methodologies"] = [f.stem.replace("-", " ").title() for f in sorted(method_files)]

    # Check workflows
    workflows_dir = _settings.LAYER2 / "workflows"
    if workflows_dir.exists():
        result["exists"] = True
        workflow_files = list(workflows_dir.glob("*.md"))
        result["workflows_count"] = len(workflow_files)
        result["workflows"] = [f.stem.replace("-", " ").title() for f in sorted(workflow_files)]

    # Check overrides
    overrides_file = _settings.BRA_STATE / "overrides.json"
    if overrides_file.exists():
        try:
            override_data = json.loads(overrides_file.read_text())
            rules = override_data.get("rules", [])
            result["overrides_count"] = len(rules)
            result["overrides_active"] = sum(1 for r in rules if r.get("enabled", True))
            result["overrides"] = rules
        except (json.JSONDecodeError, OSError):
            pass

    return result


def load_logs() -> dict[str, Any]:
    """Load log files list.

    Returns:
        Dictionary with:
        - logs: list of dicts with name, size, modified
    """
    logs_dir = _settings.BRA_STATE / "logs"

    result = {"logs": []}

    if logs_dir.exists():
        for f in sorted(logs_dir.iterdir()):
            if f.is_file():
                stat = f.stat()
                result["logs"].append({
                    "name": f.name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime
                })

    return result


def load_findings() -> dict[str, Any]:
    """Load findings data from NOTES/FINDINGS.md.

    Returns:
        Dictionary with:
        - exists: bool
        - engagement: engagement name
        - started: start date
        - findings: list of finding dicts with title, severity
        - counts: dict with severity counts
        - raw_content: full file content
    """
    findings_file = _settings.LAYER3 / "NOTES" / "FINDINGS.md"

    if not findings_file.exists():
        return {
            "exists": False,
            "engagement": None,
            "started": None,
            "findings": [],
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "raw_content": ""
        }

    content = findings_file.read_text()
    result = {
        "exists": True,
        "engagement": None,
        "started": None,
        "findings": [],
        "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "raw_content": content
    }

    # Extract metadata
    engagement_match = re.search(r'\*\*Engagement:\*\*\s*(.+)', content)
    started_match = re.search(r'\*\*Started:\*\*\s*(.+)', content)

    if engagement_match:
        result["engagement"] = engagement_match.group(1).strip()
    if started_match:
        result["started"] = started_match.group(1).strip()

    # Extract findings — supports two heading formats:
    #   Format A: ### [SEVERITY] Title
    #   Format B: ## [FINDING-NNN] Title (severity in table row)
    # Split by ## or ### finding headers
    finding_sections = re.split(r'\n(?=##+ \[)', content)

    for section in finding_sections:
        # Try Format A: ### [SEVERITY] Title
        match = re.match(r'^###? \[([A-Z]+)\]\s*(.+)', section)
        # Try Format B: ## [FINDING-NNN] Title
        if not match:
            match = re.match(r'^##+ \[(FINDING-\d+)\]\s*(.+)', section)
        if not match:
            continue

        header_tag = match.group(1)
        title = match.group(2).strip()

        # Get the body (everything after the title line)
        body_start = section.find('\n')
        body = section[body_start:].strip() if body_start != -1 else ""

        # Determine severity — from header tag or from table/body
        if header_tag.startswith("FINDING-"):
            # Format B: extract severity from table row or body text
            sev_match = re.search(
                r'\|\s*\*\*Severity\*\*\s*\|\s*(\w+)',
                body
            )
            severity = sev_match.group(1).upper() if sev_match else "INFO"
        else:
            severity = header_tag

        # Parse structured fields from body
        finding = {
            "severity": severity,
            "title": title,
            "body": body,
            "affected": None,
            "description": None,
            "impact": None,
            "attack_vector": None,
            "reproduction": None,
            "poc": None,
            "evidence": None,
            "cvss": None,
            "likelihood": None,
            "remediation": None,
            "tools": None,
        }

        # Extract specific fields — try both inline (**Key:** val) and
        # section-header (### Key\n\nval) formats
        field_patterns = [
            ("affected", r'\*\*Affected(?: artifact)?:\*\*\s*(.+)'),
            ("affected", r'### Affected Artifact\s*\n+\*\*Artifact:\*\*\s*(.+)'),
            ("description", r'\*\*(?:Short )?[Dd]escription:\*\*\s*(.+)'),
            ("description", r'### Description\s*\n+(.+)'),
            ("impact", r'\*\*Impact:\*\*\s*(.+)'),
            ("attack_vector", r'\*\*Attack [Vv]ector:\*\*\s*(.+)'),
            ("poc", r'\*\*Proof of Concept:\*\*\s*(.+)'),
            ("evidence", r'\*\*Observed [Ee]vidence:\*\*\s*(.+)'),
            ("cvss", r'\*\*CVSS Score:\*\*\s*(.+)'),
            ("cvss", r'\*\*CVSS Vector:\*\*\s*(.+)'),
            ("likelihood", r'\*\*Likelihood:\*\*\s*(.+)'),
            ("likelihood", r'### Likelihood\s*\n+\*\*(\w+)\*\*'),
            ("remediation", r'\*\*Remediation:\*\*\s*(.+)'),
            ("tools", r'\*\*Tools(?:\s*&\s*[Vv]ersions)?:\*\*\s*(.+)'),
        ]

        for field_name, pattern in field_patterns:
            if finding[field_name] is not None:
                continue  # already matched by earlier pattern
            field_match = re.search(pattern, body)
            if field_match:
                finding[field_name] = field_match.group(1).strip()

        # Extract reproduction steps (multi-line)
        repro_match = re.search(r'\*\*Reproduction [Ss]teps:\*\*\s*\n((?:\s+\d+\..+\n?)+)', body)
        if not repro_match:
            repro_match = re.search(r'### Reproduction Steps\s*\n+((?:.*\n?)+?)(?=\n###|\Z)', body)
        if repro_match:
            finding["reproduction"] = repro_match.group(1).strip()

        result["findings"].append(finding)

        if severity in result["counts"]:
            result["counts"][severity] += 1

    return result


def load_leads() -> dict[str, Any]:
    """Load leads data from NOTES/LEADS.md.

    Returns:
        Dictionary with:
        - exists: bool
        - leads: list of lead dicts with title, status
        - counts: dict with status counts
        - raw_content: full file content
    """
    leads_file = _settings.LAYER3 / "NOTES" / "LEADS.md"

    if not leads_file.exists():
        return {
            "exists": False,
            "leads": [],
            "counts": {"OPEN": 0, "INVESTIGATING": 0, "RULED_OUT": 0, "CLOSED": 0},
            "raw_content": ""
        }

    content = leads_file.read_text()
    result = {
        "exists": True,
        "leads": [],
        "counts": {"OPEN": 0, "INVESTIGATING": 0, "RULED_OUT": 0, "CLOSED": 0},
        "raw_content": content
    }

    # Extract leads - format: ### Title or - [STATUS] Description
    for match in re.finditer(r'^### (.+)', content, re.MULTILINE):
        title = match.group(1).strip()
        status = "OPEN"
        if "RULED" in title.upper():
            status = "RULED_OUT"
        elif "CLOSED" in title.upper():
            status = "CLOSED"
        elif "INVESTIGATING" in title.upper():
            status = "INVESTIGATING"

        result["leads"].append({"title": title, "status": status})
        if status in result["counts"]:
            result["counts"][status] += 1

    # Also check for list items with status markers
    for match in re.finditer(r'^-\s*\[([A-Z_]+)\]\s*(.+)', content, re.MULTILINE):
        status = match.group(1).replace(".", "_").upper()
        title = match.group(2).strip()

        if "RULED" in status:
            status = "RULED_OUT"
        elif status not in result["counts"]:
            status = "OPEN"

        result["leads"].append({"title": title, "status": status})
        if status in result["counts"]:
            result["counts"][status] += 1

    return result


def load_override_recommendations(overrides_md_path: Path | None = None) -> list[dict]:
    """Load cross-engagement override recommendations from layer2-templates/overrides.md.

    Args:
        overrides_md_path: Path to overrides.md. Defaults to layer2-templates/overrides.md.

    Returns:
        List of recommendation dicts with keys: type, match, rationale, engagements, action
    """
    if overrides_md_path is None:
        overrides_md_path = _settings.LAYER3 / "OVERRIDES.md"
        if not overrides_md_path.exists():
            overrides_md_path = _settings.LAYER2 / "overrides.md"

    if not overrides_md_path.exists():
        return []

    content = overrides_md_path.read_text()
    recommendations = []

    pattern = re.compile(
        r'^### (\w+)\s+(\w+=\S+)\s*\n'
        r'(?:- \*\*Rationale:\*\*\s*(.+)\n)?'
        r'(?:- \*\*Engagements:\*\*\s*(\d+)\n)?'
        r'(?:- \*\*Action:\*\*\s*(\S+))?',
        re.MULTILINE,
    )

    for m in pattern.finditer(content):
        rule_type = m.group(1)
        match_kv = m.group(2)
        rationale = m.group(3) or ""
        engagements = int(m.group(4)) if m.group(4) else 1
        action = m.group(5) or "allow"

        # Parse match key=value
        key, _, value = match_kv.partition("=")
        match_dict = {key: value}

        recommendations.append({
            "type": rule_type,
            "match": match_dict,
            "rationale": rationale.strip(),
            "engagements": engagements,
            "action": action.strip(),
        })

    return recommendations


def load_override_decisions(overrides_md_path: Path | None = None) -> list[dict]:
    """Load engagement decision history from OVERRIDES.md.

    Parses the "Engagement Decisions" section for structured entries.

    Args:
        overrides_md_path: Path to OVERRIDES.md. Defaults to layer3.

    Returns:
        List of decision dicts with keys: timestamp, type, subtype,
        decision, command, override_id, context
    """
    if overrides_md_path is None:
        overrides_md_path = _settings.LAYER3 / "OVERRIDES.md"

    if not overrides_md_path.exists():
        return []

    content = overrides_md_path.read_text()

    # Find "Engagement Decisions" section
    decisions_start = content.find("## Engagement Decisions")
    if decisions_start == -1:
        return []

    decisions_content = content[decisions_start:]
    decisions: list[dict] = []

    # Match decision headers: ### [timestamp] TYPE Subtype \u2014 DECISION
    header_pattern = re.compile(
        r'^### \[(.+?)\] (\w+) (.+?) \u2014 (.+)$',
        re.MULTILINE,
    )

    matches = list(header_pattern.finditer(decisions_content))

    for i, m in enumerate(matches):
        # Extract detail lines between this header and the next (or end)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(decisions_content)
        detail_block = decisions_content[start:end]

        details: dict[str, str] = {}
        for line in detail_block.split("\n"):
            line = line.strip()
            detail_match = re.match(r'^- \*\*(.+?):\*\*\s*(.+)', line)
            if detail_match:
                key = detail_match.group(1).lower()
                value = detail_match.group(2).strip().strip("`")
                details[key] = value

        decisions.append({
            "timestamp": m.group(1),
            "type": m.group(2),
            "subtype": m.group(3),
            "decision": m.group(4),
            "command": details.get("command", ""),
            "override_id": details.get("override id", ""),
            "context": details.get("context", ""),
        })

    return decisions
