#!/usr/bin/env python3
"""Handoff prompt generation utilities for multi-phase orchestration."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path


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


def _ho_log(message: str, body_root: Path | None = None) -> None:
    """Write handoff log entry."""
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "agentic.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [HANDOFF] {message}\n")
    except OSError:
        pass


def _scope_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "SCOPE.md"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _extract_markdown_field(text: str, field: str) -> str:
    match = re.search(rf"\*\*{re.escape(field)}:\*\*\s*(.+)", text)
    return match.group(1).strip() if match else ""


def _extract_section_items(text: str, *headings: str) -> list[str]:
    for heading in headings:
        match = re.search(
            rf"^##+#\s*{re.escape(heading)}(?:\s*\([^)]*\))?\s*$([\s\S]*?)(?=^---\s*$|^##+#\s|\Z)",
            text,
            re.MULTILINE,
        )
        if not match:
            continue
        items: list[str] = []
        for line in match.group(1).splitlines():
            stripped = line.strip()
            if not stripped.startswith("- "):
                continue
            value = stripped[2:].strip()
            if value and value.lower() not in {"none", "none specified", "none provided"}:
                items.append(value)
        if items:
            return items
    return []


def _classify_target(value: str) -> str:
    target = str(value or "").strip()
    lowered = target.lower()
    if not target:
        return "local"
    if re.match(r"^https?://", target, re.IGNORECASE):
        return "network"
    if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?$", target):
        return "network"
    if ":" in target and re.match(r"^[0-9a-fA-F:]+(?:/\d{1,3})?$", target):
        return "network"
    if re.search(r"\b[a-z0-9-]+\.[a-z0-9.-]+\b", lowered):
        return "network"
    if lowered.startswith("/dev/") or lowered.startswith("usb:"):
        return "local"
    if target.startswith("/") or target.startswith("./"):
        return "local"
    if "usb" in lowered or "bluetooth" in lowered or "ble" in lowered:
        return "local"
    return "local"


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _scope_targets(text: str) -> tuple[list[str], list[str]]:
    network = _extract_section_items(text, "Network Targets")
    local = _extract_section_items(text, "Local Targets")
    unified = _extract_section_items(text, "Targets")
    for item in unified:
        if _classify_target(item) == "network":
            network.append(item)
        else:
            local.append(item)
    return _dedupe_preserve_order(network), _dedupe_preserve_order(local)


def get_network_targets(body_root: Path | None = None) -> list[str]:
    """Return network targets from `SCOPE.md` network section."""
    text = _read(_scope_file(body_root))
    network, _ = _scope_targets(text)
    return network


def get_local_targets(body_root: Path | None = None) -> list[str]:
    """Return local targets from `SCOPE.md` local section."""
    text = _read(_scope_file(body_root))
    _, local = _scope_targets(text)
    return local


def get_target_name(body_root: Path | None = None) -> str:
    """Return engagement target name from scope file, if present."""
    text = _read(_scope_file(body_root))
    return _extract_markdown_field(text, "Name")


def get_target_type(body_root: Path | None = None) -> str:
    text = _read(_scope_file(body_root))
    return _extract_markdown_field(text, "Target Type")


def get_target_version(body_root: Path | None = None) -> str:
    text = _read(_scope_file(body_root))
    return _extract_markdown_field(text, "Version")


def get_active_testing_status(body_root: Path | None = None) -> str:
    text = _read(_scope_file(body_root))
    match = re.search(r"ACTIVE-TESTING-APPROVAL:\s*([A-Z]+)", text)
    value = match.group(1).strip().upper() if match else "ASK"
    return {
        "YES": "Granted",
        "NO": "Denied",
        "ASK": "Ask First",
    }.get(value, value.title())


def get_authorization_confirmation(body_root: Path | None = None) -> str:
    text = _read(_scope_file(body_root))
    match = re.search(r"Authorization.*?\bat\s+([0-9TZ:\-]+)", text)
    return match.group(1) if match else _utc_now()


def _token_status(token_name: str, body_root: Path | None = None) -> str:
    root = _detect_body_root() if body_root is None else body_root
    token_path = root / ".bra" / "approvals" / token_name
    return "**GRANTED**" if token_path.exists() else "Not Set"


def _targets_block(network_targets: list[str], local_targets: list[str]) -> list[str]:
    lines: list[str] = []
    if network_targets:
        lines.append("Network:")
        lines.extend([f"  - {item}" for item in network_targets])
    if local_targets:
        lines.append("Local:")
        lines.extend([f"  - {item}" for item in local_targets])
    if not network_targets and not local_targets:
        lines.append("  No targets defined in layer3-engagement/SCOPE.md")
    return lines


def summarize_artifacts(phase_name: str = "", body_root: Path | None = None) -> list[str]:
    """Return compact summary lines for discovered artifact files."""
    root = _detect_body_root() if body_root is None else body_root
    artifacts = root / ".bra" / "artifacts"

    if phase_name:
        name = phase_name.lower()
        if "intel" in name:
            artifacts = artifacts / "intel"
        elif "static" in name:
            artifacts = artifacts / "static"
        elif "dynamic" in name:
            artifacts = artifacts / "dynamic"

    if not artifacts.is_dir():
        return ["No artifacts found."]

    lines: list[str] = []
    file_count = 0
    total_lines = 0
    for path in sorted(artifacts.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".txt", ".md", ".xml"}:
            continue
        file_count += 1
        preview = ""
        line_count = 0
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            line_count = len(raw)
            total_lines += line_count
            for row in raw[:5]:
                if row.strip() and not row.strip().startswith("#"):
                    preview = row.strip()[:60]
                    break
        except OSError:
            pass

        if preview:
            lines.append(f"- {path.name} ({line_count} lines): {preview}...")
        else:
            lines.append(f"- {path.name} ({line_count} lines)")

        if file_count >= 20:
            break

    if not lines:
        return [f"No artifacts found in {artifacts}"]
    lines.append("")
    lines.append(f"Total: {file_count} files, ~{total_lines} lines")
    return lines


def get_key_findings(body_root: Path | None = None) -> list[str]:
    """Return heuristic key findings from artifact corpus."""
    root = _detect_body_root() if body_root is None else body_root
    artifacts = root / ".bra" / "artifacts"
    if not artifacts.is_dir():
        return ["No key findings yet."]

    corpus_parts: list[str] = []
    for path in artifacts.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".txt", ".md", ".xml"}:
            corpus_parts.append(_read(path)[:50000])
    corpus = "\n".join(corpus_parts)

    findings: list[str] = []
    if re.search(r"VALID:|password\s*[:=]|credential|secret\s*[:=]", corpus, re.IGNORECASE):
        findings.append("Potential credentials found in artifacts")

    open_ports = len(re.findall(r"/(tcp|udp)\s+open", corpus, re.IGNORECASE))
    if open_ports:
        findings.append(f"{open_ports} open ports discovered")

    if re.search(r"HTTP/[0-9]|Server:\s", corpus, re.IGNORECASE):
        findings.append("Web services detected")

    path_hits = len(re.findall(r"/(admin|api|login|config|backup|debug|internal)\b", corpus, re.IGNORECASE))
    if path_hits:
        findings.append(f"{path_hits} interesting paths found")

    return findings or ["No key findings yet."]


def get_methodology_suggestions(phase_pattern: str, methodology_file: str = "", body_root: Path | None = None) -> list[str]:
    """Return methodology-aware suggestions for current phase."""
    suggestions: list[str] = []

    meth_path = Path(methodology_file) if methodology_file else None
    if meth_path and meth_path.is_file():
        text = _read(meth_path)
        section_match = re.search(rf"^##\s*{re.escape(phase_pattern)}\s*$([\s\S]*?)(?=^##\s|\Z)", text, re.MULTILINE)
        if section_match:
            section = section_match.group(1)
            objectives = re.findall(r"^-\s+(.+)$", section, re.MULTILINE)
            if objectives:
                suggestions.append("Objectives:")
                suggestions.extend([f"  - {obj.strip()}" for obj in objectives[:5]])

            tools = sorted(set(re.findall(r"^([a-zA-Z0-9_.-]+)\s", section, re.MULTILINE)))
            if tools:
                suggestions.append("Tools:")
                suggestions.extend([f"  - {tool}" for tool in tools[:10]])

    if not suggestions:
        suggestions.extend(
            [
                "Methodology not yet determined.",
                "Claude should:",
                "  1. Read layer3-engagement/SCOPE.md for target details",
                "  2. Determine target type through intelligence",
                "  3. Load a methodology from layer2-templates/methodologies/",
                "  4. Cross-check tools in layer2-templates/toolset.md",
            ]
        )

    return suggestions


def generate_handoff_prompt(phase_pattern: str = "Intelligence", methodology_file: str = "", body_root: Path | None = None) -> str:
    """Generate full handoff prompt text for the current phase."""
    root = _detect_body_root() if body_root is None else body_root
    _ho_log(f"Generating handoff for phase: {phase_pattern}", root)

    target = get_target_name(root) or "Unknown"
    network_targets = get_network_targets(root)
    local_targets = get_local_targets(root)
    artifacts_summary = summarize_artifacts(body_root=root)
    key_findings = get_key_findings(root)
    methodology_guidance = get_methodology_suggestions(phase_pattern, methodology_file, body_root=root)
    targets_block = _targets_block(network_targets, local_targets)

    lines = [
        "You are the main engagement agent for this BRA session.",
        "",
        "## Engagement Summary",
        "",
        f"Target: {target}",
        f"Phase: {phase_pattern}",
        f"Time: {_utc_now()}",
        "",
        "## FIRST ACTION: Validate Scope",
        "",
        "Before proceeding with any methodology work, you MUST:",
        "",
        "  1. Read layer3-engagement/SCOPE.md completely",
        "  2. Validate and normalize the scope data:",
        "     - Fix formatting issues (IP addresses, paths, URLs)",
        "     - Clarify ambiguous targets",
        "     - Ensure target type matches actual target",
        "     - Verify network constraints are parseable",
        "  3. If scope needs corrections, update SCOPE.md with clean data",
        "  4. Present a BRIEF summary of the validated scope",
        "  5. End with 'What would you like to do?' followed by these exact options:",
        "",
        "     1. Confirm scope and proceed",
        "     2. Revise scope (tell me what to change)",
        "     3. Ask a clarifying question",
        "     4. Cancel engagement",
        "",
        "Do NOT list issues as numbered items - put issues in prose or bullet points.",
        "ONLY use numbered lists for selectable options.",
        "",
        "## Layer References",
        "",
        "| Layer | Path | Purpose |",
        "|-------|------|---------|",
        "| Layer 1 | layer1/rules/ | Governance, tokens, ROE policy (rarely changes) |",
        "| Layer 2 | layer2-templates/ | Skillset, toolset, methodologies, workflows (grows) |",
        "| Layer 3 | layer3-engagement/ | Scope, ROE, engagement-specific config |",
        "",
        "## Targets (From Layer 3)",
        "",
        *targets_block,
        "",
        "## Existing Artifacts",
        "",
        *artifacts_summary,
        "",
        "## Key Findings",
        "",
        *key_findings,
        "",
        "## Methodology Guidance (Layer 2)",
        "",
        *methodology_guidance,
        "",
        "## Intel Capture Format",
        "",
        "As you work, emit structured markers whenever you discover something —",
        "a port, an endpoint, a target property, a lead, or other security-relevant",
        "intel. Do NOT save these up.",
        "Emit them inline, as they happen, on their own line.",
        "",
        "For vulnerabilities, FINDING markers must include severity, CVSS, and attack surface:",
        "  [FINDING] <SEVERITY>: <title> | cvss: <0.0-10.0> | attack_surface: <category> | capture_id: <id>",
        "Do not emit bare FINDING markers without cvss and attack_surface.",
        "source is optional when capture_id is present and resolvable.",
        "",
        "The framework captures markers automatically into the intel record.",
        "Just emit markers and keep working.",
        "",
        "The examples below show common marker types. If valuable intel does not fit one",
        "of these examples, you may create a concise uppercase marker [CATEGORY].",
        "",
        "Example flow:",
        "  1. You run nmap and see port 443 open with nginx",
        "     → emit: [SERVICE] 443/tcp | open | HTTPS | nginx/1.24 | source: NOTES/reqs/nmap-scan.txt",
        "  2. You curl the web service and find a login page",
        "     → emit: [ENDPOINT] /login | GET | Authentication | source: NOTES/reqs/index.html",
        "  3. You notice something worth investigating later",
        "     → emit: [LEAD] Check admin panel for default creds | priority: High | rationale: Login page has no rate limiting",
        "  4. You keep working — markers accumulate automatically",
        "",
        "## Token Status (Layer 1: tokens.md)",
        "",
        "| Token | Status |",
        "|-------|--------|",
        f"| ACTIVE-TESTING-APPROVAL | {_token_status('ACTIVE-TESTING-APPROVAL', root)} |",
        f"| DESTRUCTIVE-APPROVAL | {_token_status('DESTRUCTIVE-APPROVAL', root)} |",
        "",
        "## Questions for You",
        "",
        "  - Any specific areas you want me to focus on?",
        "  - Should I dig deeper on any findings?",
        "  - Any techniques from the methodology you want to prioritize?",
        "  - Any scope changes or additions?",
        "",
        "## CRITICAL: Human-in-the-Loop Requirement",
        "",
        "WARNING: You MUST stop and wait for human approval before EVERY action.",
        "",
        "MANDATORY RULES:",
        "",
        "  1. DO NOT execute commands without explicit user approval",
        "  2. DO NOT chain multiple actions together",
        "  3. DO NOT scan, probe, or test ANYTHING without asking first",
        "  4. DO NOT modify files without asking first",
        "  5. STOP after EVERY response and wait for user input",
        "",
        "WORKFLOW FOR EVERY ACTION:",
        "",
        "  Step 1: Describe what you WANT to do (do not do it yet)",
        "  Step 2: Present options including the proposed action",
        "  Step 3: STOP and WAIT for user to select",
        "  Step 4: Only execute AFTER user explicitly approves",
        "",
        "EXAMPLE - CORRECT:",
        "",
        "  I'd like to scan the network to find the device.",
        "",
        "  What would you like to do?",
        "  1. Approve network scan (192.168.8.0/24)",
        "  2. Skip scanning - provide IP manually",
        "  3. Something else",
        "",
        "  [STOP HERE - wait for user response]",
        "",
        "EXAMPLE - WRONG:",
        "",
        "  Let me scan the network... [runs nmap]",
        "  Found device at 192.168.8.5, let me probe it... [runs curl]",
        "  Found web interface, checking endpoints... [runs more commands]",
        "",
        "  ^^^ THIS IS FORBIDDEN - never chain actions without approval",
        "",
        "FORMAT RULES:",
        "  - ONLY use numbered lists (1. 2. 3.) for SELECTABLE OPTIONS",
        "  - Use bullet points (-) or prose for information",
        "  - Always end with 'What would you like to do?' then options",
        "",
        "OUTPUT STYLE RULES:",
        "  - Do not mention internal document names, file paths, markdown filenames, or repository structure in operator-facing chat output.",
        "  - Selectable options must be plain action labels only.",
        "  - Do not use first-person phrasing in options such as \"I'll\", \"I will\", or parenthetical planning text.",
        "  - After the initial scope-validation turn, do not restate unchanged target, authorization, interface, scope, hotspot, or other engagement-context facts in later replies.",
        "  - On later turns, summarize only what changed, what was learned, or why the next step is being proposed.",
        "  - Do not repeat \"Scope confirmed\" or re-issue the scope summary after the initial scope-validation turn unless the scope actually changed.",
        "",
        "═══════════════════════════════════════════════════════════════",
        "  Ready to Execute",
        "═══════════════════════════════════════════════════════════════",
        "",
        'Tell me what to pursue, or say "continue" for methodology-driven next step.',
    ]

    return "\n".join(lines)


def generate_brief_handoff(action: str = "", result: str = "", body_root: Path | None = None) -> str:
    """Generate brief mid-loop handoff after an action completes."""
    lines = [
        "",
        "───────────────────────────────────────────────────────────────",
        f"  Action Complete: {action}" if action else "  Action Complete: ",
        "───────────────────────────────────────────────────────────────",
        "",
    ]
    if result:
        lines.append("Result:")
        for row in result.splitlines()[:10]:
            lines.append(f"  {row}")
        lines.append("")
    lines.extend([
        "What next?",
        "  - Continue with methodology (layer2-templates/)",
        "  - Dig deeper on this finding",
        "  - Switch focus to something else",
        "  - Document and move on (layer3-engagement/NOTES/)",
        "",
    ])
    return "\n".join(lines)


def generate_phase_complete_handoff(
    phase_pattern: str,
    methodology_file: str = "",
    body_root: Path | None = None,
) -> str:
    """Generate checkpoint-style handoff after phase completion."""
    root = _detect_body_root() if body_root is None else body_root

    lines = [
        "",
        "═══════════════════════════════════════════════════════════════",
        f"  Phase Complete: {phase_pattern}",
        "═══════════════════════════════════════════════════════════════",
        "",
    ]

    # Show deliverables from Layer 2 methodology if available
    meth_path = Path(methodology_file) if methodology_file else None
    if meth_path and meth_path.is_file():
        text = _read(meth_path)
        deliv_match = re.search(
            rf"^##\s*{re.escape(phase_pattern)}\s*$[\s\S]*?deliverables?\s*:?\s*$([^\n]*(?:\n(?!^##\s)[^\n]*)*)",
            text,
            re.MULTILINE | re.IGNORECASE,
        )
        if deliv_match:
            deliverables = re.findall(r"^-\s+(.+)$", deliv_match.group(1), re.MULTILINE)
            if deliverables:
                lines.append("Deliverables (from Layer 2 methodology):")
                lines.extend([f"  - [?] {d.strip()}" for d in deliverables])
                lines.append("")

    # Get next phase from methodology
    next_phase = ""
    if meth_path and meth_path.is_file():
        text = _read(meth_path)
        phases = re.findall(r"^##\s+(.+)$", text, re.MULTILINE)
        for i, p in enumerate(phases):
            if phase_pattern.lower() in p.lower() and i + 1 < len(phases):
                next_phase = phases[i + 1]
                break

    lines.append("Options:")
    if next_phase:
        lines.append(f"  1. Continue to {next_phase}")
    else:
        lines.append("  1. All phases complete - generate report")
    lines.extend([
        "  2. Discuss findings first",
        "  3. Re-run this phase with different parameters",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "--brief":
        action = args[1] if len(args) >= 2 else ""
        result = args[2] if len(args) >= 3 else ""
        print(generate_brief_handoff(action, result))
        return 0

    if args and args[0] == "--phase-complete":
        phase = args[1] if len(args) >= 2 else "Intelligence"
        meth = args[2] if len(args) >= 3 else ""
        print(generate_phase_complete_handoff(phase, meth))
        return 0

    phase = args[0] if args else "Intelligence"
    methodology = args[1] if len(args) >= 2 else ""
    print(generate_handoff_prompt(phase, methodology))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
