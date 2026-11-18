"""
Layer 4 Telemetry — standalone module.

Computes live stats from existing body/ files, maintains cumulative counters
in body/layer4-telemetry/stats.json, and derives a gamified "Battle Card".

Zero imports from head/, data_loaders, or any other boots module.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Live parsers — read existing body/ files, compute on each call
# ---------------------------------------------------------------------------

def _safe_json(path: Path, default=None):
    """Read a JSON file, return *default* on any failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _parse_findings(body: Path) -> dict:
    """Parse FINDINGS.md for total count and severity breakdown."""
    fp = body / "layer3-engagement" / "NOTES" / "FINDINGS.md"
    result = {"total": 0, "by_severity": {}}
    try:
        text = fp.read_text(encoding="utf-8")
    except Exception:
        return result
    # Match ## [FINDING-NNN] lines then look for severity in the table
    blocks = re.split(r"(?=^## \[FINDING-\d+\])", text, flags=re.MULTILINE)
    for block in blocks:
        if not block.strip().startswith("## [FINDING-"):
            continue
        result["total"] += 1
        sev_match = re.search(
            r"\*\*Severity\*\*\s*\|\s*(Critical|High|Medium|Low|Info|INFO)",
            block, re.IGNORECASE,
        )
        if sev_match:
            sev = sev_match.group(1).capitalize()
            if sev == "Info":
                sev = "Info"
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
    return result


def _parse_leads(body: Path) -> dict:
    """Parse LEADS.md table rows."""
    fp = body / "layer3-engagement" / "NOTES" / "LEADS.md"
    result = {"total": 0, "by_status": {}}
    try:
        text = fp.read_text(encoding="utf-8")
    except Exception:
        return result
    for m in re.finditer(
        r"^\|\s*\d+\s*\|.*?\|.*?\|.*?\|\s*(\w+)\s*\|",
        text, re.MULTILINE,
    ):
        result["total"] += 1
        status = m.group(1).capitalize()
        result["by_status"][status] = result["by_status"].get(status, 0) + 1
    return result


def _parse_artifacts(body: Path) -> dict:
    """Parse artifacts manifest."""
    data = _safe_json(body / ".bra" / "artifacts" / "manifest.json", {})
    arts = data.get("artifacts", [])
    if arts:
        return {"total": len(arts)}

    artifacts_dir = body / ".bra" / "artifacts"
    if not artifacts_dir.exists():
        return {"total": 0}

    fallback_total = 0
    for candidate in artifacts_dir.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.name == "manifest.json":
            continue
        if candidate.name.startswith("."):
            continue
        fallback_total += 1
    return {"total": fallback_total}


def _parse_overrides(body: Path) -> dict:
    """Parse overrides.json for rule stats."""
    data = _safe_json(body / ".bra" / "overrides.json", {})
    rules = data.get("rules", [])
    active = [r for r in rules if r.get("enabled", True)]
    by_type = {}
    by_layer = {}
    tools_used = set()
    for r in rules:
        rtype = r.get("type", "UNKNOWN")
        by_type[rtype] = by_type.get(rtype, 0) + 1
        layer = str(r.get("layer", "?"))
        by_layer[layer] = by_layer.get(layer, 0) + 1
        # Extract tool name from match
        match = r.get("match", {})
        tool = match.get("tool_name")
        if tool:
            tools_used.add(tool)
        cmd = match.get("command", "")
        # Extract the first token of the command as a tool
        if cmd:
            first = cmd.split()[0] if cmd.split() else ""
            if first:
                tools_used.add(first)
    return {
        "total": len(rules),
        "active": len(active),
        "by_type": by_type,
        "by_layer": by_layer,
        "tools_used": sorted(tools_used),
    }


def _parse_tokens(body: Path) -> dict:
    """List granted approval tokens."""
    approvals_dir = body / ".bra" / "approvals"
    granted = []
    try:
        for f in sorted(approvals_dir.iterdir()):
            if f.is_file():
                granted.append(f.name)
    except Exception:
        pass
    return {"granted": granted, "total_granted": len(granted)}


def _parse_tools(body: Path) -> dict:
    """Parse toolset.md for tool categories."""
    fp = body / "layer2-templates" / "toolset.md"
    result = {"total": 0, "categories": []}
    try:
        text = fp.read_text(encoding="utf-8")
    except Exception:
        return result
    cats = re.findall(r"^##\s+(.+)", text, re.MULTILINE)
    # Count list items (tool entries) as rough tool count
    tools = re.findall(r"^[-*]\s+\*\*(.+?)\*\*", text, re.MULTILINE)
    if not tools:
        tools = re.findall(r"^[-*]\s+`(.+?)`", text, re.MULTILINE)
    if not tools:
        # Fallback: count all list items
        tools = re.findall(r"^[-*]\s+\S", text, re.MULTILINE)
    result["total"] = len(tools)
    result["categories"] = cats
    return result


def _parse_skills(body: Path) -> dict:
    """Parse skillset.md (layer3 first, fallback layer2)."""
    for rel in [
        "layer3-engagement/skillset.md",
        "layer2-templates/skillset.md",
    ]:
        fp = body / rel
        if fp.exists():
            try:
                text = fp.read_text(encoding="utf-8")
                cats = re.findall(r"^##\s+(.+)", text, re.MULTILINE)
                items = re.findall(r"^[-*]\s+\S", text, re.MULTILINE)
                return {"total": len(items), "categories": cats, "source": rel}
            except Exception:
                continue
    return {"total": 0, "categories": [], "source": None}


def _parse_methodologies(body: Path) -> dict:
    """List methodology .md files."""
    d = body / "layer2-templates" / "methodologies"
    names = []
    try:
        for f in sorted(d.iterdir()):
            if f.suffix == ".md" and not f.name.startswith("."):
                names.append(f.stem)
    except Exception:
        pass
    return {"total": len(names), "names": names}


def _parse_workflows(body: Path) -> dict:
    """List workflow .md files."""
    d = body / "layer2-templates" / "workflows"
    names = []
    try:
        for f in sorted(d.iterdir()):
            if f.suffix == ".md" and not f.name.startswith("."):
                names.append(f.stem)
    except Exception:
        pass
    return {"total": len(names), "names": names}


def _parse_engagement(body: Path) -> dict:
    """Derive engagement state from meta + pipeline."""
    meta = _safe_json(body / ".bra" / "engagement_meta.json", {})
    pipe = _safe_json(body / ".bra" / "pipeline_state.json", {})
    started = meta.get("started_at")
    ended = meta.get("ended_at")
    active = bool(started and not ended)
    duration_s = None
    if started:
        try:
            t0 = datetime.fromisoformat(started.replace("Z", "+00:00"))
            t1_str = ended or datetime.now(timezone.utc).isoformat()
            t1 = datetime.fromisoformat(t1_str.replace("Z", "+00:00"))
            duration_s = int((t1 - t0).total_seconds())
        except Exception:
            pass
    current_phase = pipe.get("last_phase")
    phase_status = pipe.get("status")
    return {
        "active": active,
        "started_at": started,
        "ended_at": ended,
        "duration_seconds": duration_s,
        "current_phase": current_phase,
        "phase_status": phase_status,
    }


def _parse_service_health(body: Path) -> dict:
    """Parse service_state.json for target health."""
    data = _safe_json(body / ".bra" / "service_state.json", {})
    services = data.get("services", {})
    total = len(services)
    responding = sum(1 for s in services.values() if s.get("responding"))
    return {"targets_total": total, "targets_responding": responding}


# ---------------------------------------------------------------------------
# Cumulative stats — read/write layer4-telemetry/stats.json
# ---------------------------------------------------------------------------

def _stats_path(body: Path) -> Path:
    return body / "layer4-telemetry" / "stats.json"


def _load_cumulative(body: Path) -> dict:
    return _safe_json(_stats_path(body), {
        "schema_version": 1,
        "engagements_started": 0,
        "engagements_completed": 0,
        "total_sessions": 0,
        "first_engagement_at": None,
        "last_engagement_at": None,
        "tool_usage": {},
        "methodology_usage": {},
        "workflow_usage": {},
        "tokens_granted_history": {},
        "achievements": [],
    })


def _save_cumulative(body: Path, data: dict):
    sp = _stats_path(body)
    sp.parent.mkdir(parents=True, exist_ok=True)
    tmp = sp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(str(tmp), str(sp))


def update_cumulative_stats(body: Path, live: dict) -> dict:
    """Update cumulative stats based on current live data."""
    cum = _load_cumulative(body)

    # Update tool usage from overrides
    for tool in live.get("overrides", {}).get("tools_used", []):
        cum["tool_usage"][tool] = cum["tool_usage"].get(tool, 0) + 1

    # Track engagement state
    eng = live.get("engagement", {})
    if eng.get("started_at") and not cum.get("first_engagement_at"):
        cum["first_engagement_at"] = eng["started_at"]
    if eng.get("started_at"):
        cum["last_engagement_at"] = eng["started_at"]

    # Track token grants
    for token in live.get("tokens", {}).get("granted", []):
        cum["tokens_granted_history"][token] = (
            cum["tokens_granted_history"].get(token, 0) + 1
        )

    _save_cumulative(body, cum)
    return cum


# ---------------------------------------------------------------------------
# Battle Card calculator
# ---------------------------------------------------------------------------

_SEVERITY_MULT = {
    "Critical": 4.0,
    "High": 3.0,
    "Medium": 2.0,
    "Low": 1.0,
    "Info": 0.5,
}

_TITLES = [
    (0, "Recon Initiate"),
    (5, "Script Runner"),
    (15, "Exploit Developer"),
    (30, "Red Team Operator"),
    (50, "APT Emulator"),
    (75, "Ghost Protocol"),
]

_RARITY_THRESHOLDS = [
    (76, "Legendary", "#ff8000"),
    (51, "Epic", "#a335ee"),
    (26, "Rare", "#0070dd"),
    (11, "Uncommon", "#1eff00"),
    (0, "Common", "#9d9d9d"),
]


def _compute_xp(live: dict, cumulative: dict) -> int:
    """Compute total XP from live and cumulative data."""
    xp = 0
    # Findings: 100 * severity multiplier
    findings = live.get("findings", {})
    for sev, count in findings.get("by_severity", {}).items():
        mult = _SEVERITY_MULT.get(sev, 1.0)
        xp += int(100 * mult * count)
    # Leads: 25 each
    xp += live.get("leads", {}).get("total", 0) * 25
    # Tools used: 50 each
    xp += len(live.get("overrides", {}).get("tools_used", [])) * 50
    # Methodologies: 75 each
    xp += live.get("methodologies", {}).get("total", 0) * 75
    # Workflows: 75 each
    xp += live.get("workflows", {}).get("total", 0) * 75
    # Overrides: 15 each
    xp += live.get("overrides", {}).get("total", 0) * 15
    # Tokens: 10 each
    xp += live.get("tokens", {}).get("total_granted", 0) * 10
    # Completed engagements: 200 each
    xp += cumulative.get("engagements_completed", 0) * 200
    return xp


def _compute_level(xp: int) -> int:
    return min(99, 1 + int(xp ** 0.5 / 10))


def _get_rarity(level: int) -> tuple:
    for threshold, name, color in _RARITY_THRESHOLDS:
        if level >= threshold:
            return name, color
    return "Common", "#9d9d9d"


def _get_title(level: int) -> str:
    title = "Recon Initiate"
    for threshold, t in _TITLES:
        if level >= threshold:
            title = t
    return title


def _compute_stats(live: dict) -> dict:
    """Compute the 6-stat block."""
    tools_used = len(live.get("overrides", {}).get("tools_used", []))
    tools_total = max(live.get("tools", {}).get("total", 1), 1)
    methods_total = max(live.get("methodologies", {}).get("total", 1), 1)
    workflows_total = max(live.get("workflows", {}).get("total", 1), 1)
    skills_total = max(live.get("skills", {}).get("total", 1), 1)
    overrides_total = live.get("overrides", {}).get("total", 0)
    findings_total = live.get("findings", {}).get("total", 0)
    leads_total = live.get("leads", {}).get("total", 0)

    # Normalize to 0-99 range
    def cap(v):
        return min(99, max(0, int(v)))

    return {
        "ATK": cap(tools_used * 99 / tools_total) if tools_total else 0,
        "ATK_label": "Tools Used",
        "DEF": cap(methods_total * 12),
        "DEF_label": "Methodologies",
        "INT": cap(workflows_total * 12),
        "INT_label": "Workflows",
        "WIS": cap(skills_total * 5),
        "WIS_label": "Skill Coverage",
        "STL": cap(overrides_total * 10),
        "STL_label": "Override Ratio",
        "PER": cap((findings_total + leads_total) * 8),
        "PER_label": "Findings + Leads",
    }


def _check_achievements(live: dict, cumulative: dict) -> list:
    """Compute earned achievement badges."""
    achievements = []
    findings = live.get("findings", {})
    if findings.get("total", 0) >= 1:
        achievements.append({
            "id": "first_blood",
            "name": "First Blood",
            "desc": "Document your first finding",
            "icon": "drop",
        })
    tools_used = live.get("overrides", {}).get("tools_used", [])
    if len(tools_used) >= 3:
        achievements.append({
            "id": "arsenal_loaded",
            "name": "Arsenal Loaded",
            "desc": "Use 3+ distinct tools",
            "icon": "wrench",
        })
    if live.get("methodologies", {}).get("total", 0) >= 3:
        achievements.append({
            "id": "methodology_master",
            "name": "Methodology Master",
            "desc": "Have 3+ methodologies loaded",
            "icon": "book",
        })
    if (live.get("methodologies", {}).get("total", 0) >= 1
            and live.get("workflows", {}).get("total", 0) >= 1
            and live.get("skills", {}).get("total", 0) >= 1
            and live.get("tools", {}).get("total", 0) >= 1):
        achievements.append({
            "id": "full_spectrum",
            "name": "Full Spectrum",
            "desc": "Have skills, tools, methodologies, and workflows",
            "icon": "star",
        })
    tokens = live.get("tokens", {})
    if tokens.get("total_granted", 0) >= 3:
        achievements.append({
            "id": "token_collector",
            "name": "Token Collector",
            "desc": "Earn 3+ approval tokens",
            "icon": "key",
        })
    overrides = live.get("overrides", {})
    if overrides.get("total", 0) >= 5:
        achievements.append({
            "id": "override_artist",
            "name": "Override Artist",
            "desc": "Create 5+ override rules",
            "icon": "sliders",
        })
    return achievements


def compute_battle_card(live: dict, cumulative: dict) -> dict:
    """Compute the full battle card payload."""
    xp = _compute_xp(live, cumulative)
    level = _compute_level(xp)
    rarity, rarity_color = _get_rarity(level)
    title = _get_title(level)
    # XP to next level — level formula: level = 1 + floor(sqrt(xp)/10)
    # so xp threshold for level N = ((N-1)*10)^2
    xp_for_current = ((level - 1) * 10) ** 2
    xp_for_next = (level * 10) ** 2 if level < 99 else None
    xp_progress = xp - xp_for_current if xp_for_next else 0
    xp_needed = (xp_for_next - xp_for_current) if xp_for_next else 1

    stats = _compute_stats(live)
    achievements = _check_achievements(live, cumulative)

    # Collection progress
    tools_available = live.get("tools", {}).get("total", 0)
    tools_used = len(live.get("overrides", {}).get("tools_used", []))
    methods_available = live.get("methodologies", {}).get("total", 0)
    workflows_available = live.get("workflows", {}).get("total", 0)

    return {
        "xp": xp,
        "level": level,
        "title": title,
        "rarity": rarity,
        "rarity_color": rarity_color,
        "xp_progress": xp_progress,
        "xp_needed": xp_needed,
        "stats": stats,
        "achievements": achievements,
        "collection": {
            "tools": {"used": tools_used, "available": tools_available},
            "methodologies": {"loaded": methods_available, "available": methods_available},
            "workflows": {"loaded": workflows_available, "available": workflows_available},
        },
        "passive_buffs": {
            "l2_global_overrides": live.get("overrides", {}).get("by_layer", {}).get("2", 0),
            "l3_engagement_overrides": live.get("overrides", {}).get("by_layer", {}).get("3", 0),
        },
    }


# ---------------------------------------------------------------------------
# Master function
# ---------------------------------------------------------------------------

def compute_telemetry(body_root: Path) -> dict:
    """Compute full telemetry payload: live, cumulative, and battle card."""
    live = {
        "findings": _parse_findings(body_root),
        "leads": _parse_leads(body_root),
        "artifacts": _parse_artifacts(body_root),
        "overrides": _parse_overrides(body_root),
        "tokens": _parse_tokens(body_root),
        "tools": _parse_tools(body_root),
        "skills": _parse_skills(body_root),
        "methodologies": _parse_methodologies(body_root),
        "workflows": _parse_workflows(body_root),
        "engagement": _parse_engagement(body_root),
        "service_health": _parse_service_health(body_root),
    }
    cumulative = update_cumulative_stats(body_root, live)
    battle_card = compute_battle_card(live, cumulative)
    return {"live": live, "cumulative": cumulative, "battle_card": battle_card}
