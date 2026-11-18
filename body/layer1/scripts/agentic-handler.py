#!/usr/bin/env python3
"""Native handoff generator for the agentic engagement loop.

Handles /agentic command — plays banner, runs preflight, detects methodology,
generates phase context, and produces handoff prompt.

Layer References:
  Layer 1 (layer1/rules/): Governance — CLAUDE.md, tokens.md (rarely changes)
  Layer 2 (layer2-templates/): Skillset, toolset, methodologies, workflows (grows)
  Layer 3 (layer3-engagement/): Scope, ROE, engagement-specific config
"""

from __future__ import annotations

import os
import re
import sys
from types import SimpleNamespace
from datetime import UTC, datetime
from pathlib import Path


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(path: Path) -> str:
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
    if re.search(r"\b[a-z0-9-]+\.[a-z0-9.-]+\b", lowered):
        return "network"
    if lowered.startswith("/dev/") or lowered.startswith("usb:"):
        return "local"
    if target.startswith("/") or target.startswith("./"):
        return "local"
    if "usb" in lowered or "bluetooth" in lowered or "ble" in lowered:
        return "local"
    return "local"


def _token_status(body_root: Path, token_name: str) -> str:
    token_path = body_root / ".bra" / "approvals" / token_name
    return "**GRANTED**" if token_path.exists() else "Not Set"


def _summarize_artifacts(body_root: Path, phase_name: str = "") -> list[str]:
    artifacts = body_root / ".bra" / "artifacts"
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


def _get_key_findings(body_root: Path) -> list[str]:
    artifacts = body_root / ".bra" / "artifacts"
    if not artifacts.is_dir():
        return ["No key findings yet."]

    corpus_parts: list[str] = []
    for path in artifacts.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".txt", ".md", ".xml"}:
            corpus_parts.append(_read_text(path)[:50000])
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


def _get_methodology_guidance(phase_pattern: str, methodology_file: str) -> list[str]:
    suggestions: list[str] = []
    meth_path = Path(methodology_file) if methodology_file else None
    if meth_path and meth_path.is_file():
        text = _read_text(meth_path)
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
                "",
                "Claude should:",
                "  1. Read layer3-engagement/SCOPE.md for target details",
                "  2. Determine target type through intelligence",
                "  3. Load appropriate methodology from layer2-templates/methodologies/",
                "  4. Consult layer2-templates/toolset.md for available tools",
            ]
        )

    return suggestions


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


def _agentic_log(body_root: Path, message: str) -> None:
    log_dir = body_root / ".bra" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        with (log_dir / "agentic.log").open("a", encoding="utf-8") as f:
            f.write(f"[{_utc_now()}] [AGENTIC] {message}\n")
    except OSError:
        pass


# ============== LIBRARY IMPORTS ==============

def _add_lib_path(body_root: Path) -> None:
    lib_dir = str(body_root / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)


def _import_libs(body_root: Path) -> dict:
    """Import library modules, returning dict of available modules."""
    _add_lib_path(body_root)
    libs = {}
    for name in (
        "killswitch", "scope_validate", "methodology_loader",
        "target_type_detector", "phase_invoker", "tokens",
        "tool_resolver", "pipeline_state", "handoff",
    ):
        try:
            libs[name] = __import__(name)
        except ImportError:
            pass
    # Optional modules
    for name in ("banner_agentic",):
        mod_path = body_root / "layer1" / "lib" / f"{name.replace('_', '-')}.py"
        if mod_path.exists():
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(name, mod_path)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    libs[name] = mod
            except Exception:
                pass
    return libs


# ============== PREFLIGHT ==============

def _run_preflight(body_root: Path, libs: dict) -> bool:
    print("▶ PREFLIGHT CHECK")
    print()

    # Kill switch check (Layer 1: CLAUDE.md)
    ks = libs.get("killswitch")
    print("  Kill switch (CLAUDE.md)... ", end="")
    if ks and ks.is_killswitch_active(body_root):
        print("ACTIVE - HALTED")
        _agentic_log(body_root, "HALT: Kill switch active")
        return False
    print("CLEAR")

    # Governance files (Layer 1)
    print("  Governance files (layer1/rules/)... ", end="")
    if (body_root / "CLAUDE.md").exists():
        print("OK")
    else:
        print("WARNING")
        _agentic_log(body_root, "WARNING: CLAUDE.md not found")

    # Scope validation (Layer 3)
    sv = libs.get("scope_validate")
    print("  Scope configured (layer3-engagement/SCOPE.md)... ", end="")
    scope_ok = False
    if sv:
        try:
            scope_ok = sv.scope_is_ready(body_root)
        except Exception:
            pass
    if scope_ok:
        print("OK")
    else:
        print("MISSING")
        print()
        print("  Run /scope-intake first to configure engagement scope.")
        _agentic_log(body_root, "ERROR: No scope configured")
        return False

    # Directory structure
    print("  Directory structure... ", end="")
    artifacts_dir = body_root / ".bra" / "artifacts"
    log_dir = body_root / ".bra" / "logs"
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    for d in (artifacts_dir, log_dir, notes_dir):
        d.mkdir(parents=True, exist_ok=True)
    print("OK")

    # Initialize session log
    ps = libs.get("pipeline_state")
    if ps:
        try:
            ps.init_session(body_root)
        except Exception:
            pass

    print()
    _agentic_log(body_root, "Preflight checks passed")
    return True


# ============== TARGET/METHODOLOGY DETECTION ==============

def _detect_and_load_methodology(body_root: Path, libs: dict) -> tuple[str, str, str]:
    """Detect target type and load methodology.

    Returns (target_type, methodology_file, current_phase).
    """
    print("▶ METHODOLOGY DETECTION")
    print()

    ttd = libs.get("target_type_detector")
    ml = libs.get("methodology_loader")
    ps = libs.get("pipeline_state")

    # Detect target type from Layer 3 scope
    target_type = "unknown"
    if ttd:
        try:
            target_type = ttd.detect_target_type(body_root) or "unknown"
        except Exception:
            pass
    print(f"  Target type: {target_type}")

    # Handle pending-intel or auto-detect
    if target_type in ("pending-intel", "auto-detect", "unknown"):
        print("  Target type requires intelligence to determine methodology.")
        print("  Source: layer3-engagement/SCOPE.md")
        _agentic_log(body_root, f"Target type: {target_type} - methodology pending intel")
        if ps:
            try:
                ps.update_pipeline_state("intel", "ready", body_root)
                ps.init_phase_work_dir("intel", body_root)
            except Exception:
                pass
        print()
        return target_type, "", "Intelligence"

    # Get methodology file from Layer 2
    methodology_file = ""
    if ttd:
        try:
            methodology_file = ttd.get_methodology_for_type(target_type, body_root) or ""
        except Exception:
            pass

    current_phase = "Intelligence"

    if methodology_file and Path(methodology_file).is_file():
        meth_title = Path(methodology_file).stem
        if ml:
            try:
                meth_title = ml.get_methodology_title(methodology_file) or meth_title
            except Exception:
                pass
        print(f"  Methodology: {meth_title}")
        rel_path = methodology_file
        try:
            rel_path = str(Path(methodology_file).relative_to(body_root))
        except ValueError:
            pass
        print(f"  Source: {rel_path}")

        # Get current phase from methodology
        if ml:
            try:
                current_phase = ml.get_current_phase(methodology_file) or ""
            except Exception:
                current_phase = ""

        if current_phase:
            print(f"  Current phase: {current_phase}")
        else:
            # Check if all phases complete → wrap-up
            phase_state_dir = body_root / ".bra" / "phase_state"
            if phase_state_dir.is_dir() and list(phase_state_dir.glob("*.complete")):
                print()
                print("  All methodology phases complete!")
                print()
                print("METHODOLOGY_STATUS: COMPLETE")
                print("NEXT_PHASE: wrap-up")
                print()
                print("Post-engagement wrap-up steps:")
                print("  1. /validate-findings - Validate all findings")
                print("  2. ./layer1/scripts/stats.py - Generate engagement statistics")
                print("  3. ./layer1/scripts/disclose.py - Generate disclosure packages")
                print("  4. ./layer1/scripts/lessons-learned.py - Capture lessons (auto-runs growth.py)")
                print()
                current_phase = "wrap-up"
                _agentic_log(body_root, "All phases complete - entering wrap-up")
                return target_type, methodology_file, current_phase
            else:
                # Get first phase if no state
                if ml:
                    try:
                        phases = ml.extract_phases(methodology_file)
                        if phases:
                            current_phase = phases[0]
                    except Exception:
                        pass
                if not current_phase:
                    current_phase = "Intelligence"
                print(f"  Starting phase: {current_phase}")

        _agentic_log(body_root, f"Loaded methodology: {meth_title}, phase: {current_phase}")

        # Update pipeline state and initialize work directory
        if ps:
            try:
                ps.update_pipeline_state(current_phase, "ready", body_root)
                phase_slug = current_phase.lower().replace(" ", "_")
                ps.init_phase_work_dir(phase_slug, body_root)
            except Exception:
                pass
    else:
        print(f"  No specific methodology for {target_type} in layer2-templates/methodologies/")
        _agentic_log(body_root, f"No methodology for {target_type}")
        if ps:
            try:
                ps.update_pipeline_state("intel", "ready", body_root)
                ps.init_phase_work_dir("intel", body_root)
            except Exception:
                pass

    print()
    return target_type, methodology_file, current_phase


# ============== CONTEXT GENERATION ==============

def _generate_phase_context(body_root: Path, libs: dict,
                            target_type: str, methodology_file: str,
                            current_phase: str) -> None:
    print("▶ GENERATING PHASE CONTEXT")
    print()

    pi = libs.get("phase_invoker")
    tk = libs.get("tokens")
    context_file = body_root / ".bra" / "phase_context.md"
    context_file.parent.mkdir(parents=True, exist_ok=True)

    if methodology_file and Path(methodology_file).is_file() and pi:
        try:
            pi.output_phase_context(current_phase, methodology_file, body_root)
            _agentic_log(body_root, f"Phase context generated: {context_file}")
            return
        except Exception:
            pass

    # Generate fallback context referencing layers
    active_status = "Not Set"
    destructive_status = "Not Set"
    if tk:
        try:
            if tk.has_token("ACTIVE-TESTING-APPROVAL", body_root):
                active_status = "**GRANTED**"
        except Exception:
            pass
        try:
            if tk.has_token("DESTRUCTIVE-APPROVAL", body_root):
                destructive_status = "**GRANTED**"
        except Exception:
            pass

    content = f"""# Phase Execution Context

> **Generated:** {_utc_now()}
> **Target Type:** {target_type}
> **Phase:** {current_phase}

---

## Layer References

| Layer | Path | Purpose |
|-------|------|---------|
| Layer 1 | layer1/rules/ | Governance, tokens, ROE policy (rarely changes) |
| Layer 2 | layer2-templates/ | Skillset, toolset, methodologies, workflows (grows) |
| Layer 3 | layer3-engagement/ | Scope, ROE, engagement-specific config |

---

## Current Phase

**{current_phase}**

Target type is `{target_type}`. Once intelligence determines the appropriate
methodology, context will be loaded from `layer2-templates/methodologies/`.

---

## Governance (Layer 1)

- **Toolset:** See layer2-templates/toolset.md for approved tools
- **Tokens:** See layer1/rules/tokens.md for approval requirements
- **ROE:** See layer1/rules/roe.md for rules template

---

## Engagement Scope (Layer 3)

See layer3-engagement/SCOPE.md for:
- Authorized targets
- In-scope/out-of-scope definitions
- Token status

---

## Token Status

| Token | Status |
|-------|--------|
| ACTIVE-TESTING-APPROVAL | {active_status} |
| DESTRUCTIVE-APPROVAL | {destructive_status} |

---

## Artifacts Directory

All artifacts should be saved to: `.bra/artifacts/`

---
"""
    context_file.write_text(content, encoding="utf-8")
    print(f"  Phase context written to: {context_file}")
    _agentic_log(body_root, f"Phase context generated: {context_file}")


# ============== HANDOFF GENERATION ==============

def _generate_handoff(body_root: Path, libs: dict,
                      target_type: str, methodology_file: str,
                      current_phase: str) -> None:
    ho = libs.get("handoff")
    if ho and hasattr(ho, "generate_handoff_prompt"):
        try:
            result = ho.generate_handoff_prompt(current_phase, methodology_file, body_root)
            print(result)
            _agentic_log(body_root, f"Handoff generated for phase: {current_phase}")
            return
        except Exception:
            pass

    # Inline handoff generation referencing layers
    _generate_layer_aware_handoff(body_root, libs, target_type, methodology_file, current_phase)
    _agentic_log(body_root, f"Handoff generated for phase: {current_phase}")


def _generate_layer_aware_handoff(body_root: Path, libs: dict,
                                  target_type: str, methodology_file: str,
                                  current_phase: str) -> None:
    scope_file = body_root / "layer3-engagement" / "SCOPE.md"
    content = _read_text(scope_file)
    target_name = _extract_markdown_field(content, "Name") or "Unknown"
    target_version = _extract_markdown_field(content, "Version") or "Unknown"
    scope_target_type = _extract_markdown_field(content, "Target Type") or target_type or "unknown"
    active_match = re.search(r"ACTIVE-TESTING-APPROVAL:\s*([A-Z]+)", content)
    active_testing = (active_match.group(1).strip().upper() if active_match else "ASK")
    active_label = {
        "YES": "Granted",
        "NO": "Denied",
        "ASK": "Ask First",
    }.get(active_testing, active_testing.title())
    auth_match = re.search(r"Authorization.*?\bat\s+([0-9TZ:\-]+)", content)
    authorization = auth_match.group(1) if auth_match else _utc_now()

    network_targets = _extract_section_items(content, "Network Targets")
    local_targets = _extract_section_items(content, "Local Targets")
    unified_targets = _extract_section_items(content, "Targets")
    for item in unified_targets:
        if _classify_target(item) == "network":
            network_targets.append(item)
        else:
            local_targets.append(item)

    network_targets = list(dict.fromkeys(network_targets))
    local_targets = list(dict.fromkeys(local_targets))
    frontier_scope = (body_root / ".bra" / "approvals" / "FRONTIER-SCOPE").exists()
    lines = [
        "You are the main engagement agent for this BRA session.",
        "",
        "## Engagement Summary",
        "",
        f"Target: {target_name}",
        f"Phase: {current_phase}",
        f"Time: {_utc_now()}",
        "",
        "## FIRST ACTION: Validate Scope",
        "",
        "Before proceeding with any methodology work, you MUST:",
        "",
        "  1. Read layer3-engagement/SCOPE.md completely",
        "  2. Validate and normalize the scope data:",
        "     - Fix formatting issues only for literal raw values (IP addresses, paths, URLs), not intentional anonymized placeholders",
        "     - Clarify ambiguous targets only when operator intent is unclear, not when the target is anonymized",
        "     - Ensure target type matches actual target",
        "     - Verify network constraints are parseable, while accepting intentional anonymized placeholders as valid scope entries",
        "  3. If scope needs corrections, update SCOPE.md with clean data while preserving intentional anonymized placeholders",
        "  4. Present a BRIEF summary of the validated scope",
        "  5. End with 'What would you like to do?' followed by these exact options:",
        "",
        "     1. Confirm scope and proceed",
        "     2. Revise scope (tell me what to change)",
        "     3. Ask a clarifying question",
        "     4. Cancel engagement",
        "",
        "Governed files may contain anonymized values.",
        "Do not treat anonymized nouns in SCOPE.md as placeholders, dummy data, or bad scope.",
        "Do not ask for the real value solely because a governed file contains anonymized nouns.",
        "Validate structure and operator intent, not whether anonymized nouns look like literal IPs or hostnames.",
        "An anonymized IP/hostname placeholder is a valid scope entry during initial scope review.",
        "Do not ask for the real IP/hostname during the initial scope-validation turn.",
        "Do not describe anonymized values as hostname aliases, unresolved names, placeholders that need fixing, or non-routable addresses during initial scope review.",
        "Do not ask the operator to provide the actual IP, hostname, CIDR, or subnet during the initial scope-validation turn merely because the governed scope uses anonymized values.",
        "For network actions and scans, use the anonymized value directly as the target (e.g. `nmap blanket`, `curl http://blanket/`). Do NOT ask for or discover the real address -- the masking layer resolves it to the real value at execution time.",
        "Anonymized values are stable within a single engagement.",
        "If one value is anonymized as one noun, that noun refers to the same underlying value throughout the engagement.",
        "Different anonymized nouns refer to different underlying values.",
        "Treat anonymized target values already present in governed scope as valid command placeholders.",
        "Propose commands using the anonymized target value from scope instead of replacing it with placeholders like <target-ip>.",
        "Do not ask the operator for the actual IP or hostname solely because the governed target value is anonymized.",
        "A masked target is a KNOWN target for the ENTIRE engagement, not just scope review. Never run host or network discovery to 'find the IP' of a target that scope already provides. Never say a target 'has no IP', is 'unknown', or 'must be discovered' because its value is a word rather than a literal IP/MAC/URL -- use the masked value as-is.",
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
        *_targets_block(network_targets, local_targets),
        "",
        "## Existing Artifacts",
        "",
        *_summarize_artifacts(body_root),
        "",
        "## Key Findings",
        "",
        *_get_key_findings(body_root),
        "",
        "## Methodology Guidance (Layer 2)",
        "",
        *_get_methodology_guidance(current_phase, methodology_file),
        "",
        "## Intel Capture Format",
        "",
        "As you work, emit structured markers whenever you discover something —",
        "a port, an endpoint, a target property, a lead, or other security-relevant",
        "intel. Do NOT save these up.",
        "Emit them inline, as they happen, on their own line.",
        "Use the narrowest marker that matches the observation.",
        "SERVICE is only for service discovery facts such as port, state, protocol, or version.",
        "Do not re-emit SERVICE markers during web or app-layer analysis unless the service fact itself changed.",
        "Do not bury those observations in prose when they can be emitted as markers.",
        "If an observation is both useful intel and a reportable security issue, emit both the intel marker and the FINDING marker.",
        "When saving a response body to an artifact file, do not append shell status text such as ; echo \"EXIT:$?\" into the same redirected artifact.",
        "",
        "For vulnerabilities, FINDING markers must include severity, CVSS, and attack surface:",
        "  [FINDING] <SEVERITY>: <title> | cvss: <0.0-10.0> | attack_surface: <category> | capture_id: <id>",
        "Do not emit bare FINDING markers without cvss and attack_surface.",
        "source is optional when capture_id is present and resolvable.",
        "The framework queues finding documentation automatically after you emit a FINDING marker.",
        "Emit the marker, keep working, and do not narrate that you are now writing FINDINGS.md.",
        "Only take over direct findings writing if the runner explicitly announces 'Findings handoff active'.",
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
        "     → emit: [LEAD] Check admin panel for default creds | priority: High | rationale: Login page has no rate limiting | source: NOTES/reqs/index.html",
        "  4. You keep working — markers accumulate automatically",
        "",
        "## Token Status (Layer 1: tokens.md)",
        "",
        "| Token | Status |",
        "|-------|--------|",
        f"| ACTIVE-TESTING-APPROVAL | {_token_status(body_root, 'ACTIVE-TESTING-APPROVAL')} |",
        f"| DESTRUCTIVE-APPROVAL | {_token_status(body_root, 'DESTRUCTIVE-APPROVAL')} |",
        "",
        "## Questions for You",
        "",
        "  - Any specific areas you want me to focus on?",
        "  - Should I dig deeper on any findings?",
        "  - Any techniques from the methodology you want to prioritize?",
        "  - Any scope changes or additions?",
        "",
    ]
    if frontier_scope:
        lines.extend(
            [
                "Note any values I should apply a privacy mask to.",
                "",
            ]
        )
    lines.extend(
        [
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
        "",
    ])
    print("\n".join(lines))


# ============== STATUS DISPLAY ==============

def _show_status(body_root: Path, libs: dict) -> None:
    print()
    print("═══════════════════════════════════════════════════════════════")
    print("  AGENTIC STATUS")
    print("═══════════════════════════════════════════════════════════════")
    print()

    ks = libs.get("killswitch")
    sv = libs.get("scope_validate")
    ttd = libs.get("target_type_detector")
    ml = libs.get("methodology_loader")
    tk = libs.get("tokens")

    # Layer 1: Kill switch
    print("Layer 1 (Governance)")
    ks_active = False
    if ks:
        try:
            ks_active = ks.is_killswitch_active(body_root)
        except Exception:
            pass
    print(f"  Kill switch: {'ACTIVE' if ks_active else 'CLEAR'}")
    print("  Source: CLAUDE.md")
    print()

    # Layer 3: Scope
    print("Layer 3 (Engagement)")
    scope_ok = False
    if sv:
        try:
            scope_ok = sv.scope_is_ready(body_root)
        except Exception:
            pass
    print(f"  Scope: {'Configured' if scope_ok else 'Not configured'}")
    print("  Source: layer3-engagement/SCOPE.md")

    # Target type
    target_type = "unknown"
    if ttd:
        try:
            target_type = ttd.detect_target_type(body_root) or "unknown"
        except Exception:
            pass
    print(f"  Target type: {target_type}")
    print()

    # Layer 2: Methodology
    print("Layer 2 (Methodology)")
    meth_file = ""
    if ttd:
        try:
            meth_file = ttd.get_methodology_for_type(target_type, body_root) or ""
        except Exception:
            pass
    if meth_file and Path(meth_file).is_file():
        title = Path(meth_file).stem
        if ml:
            try:
                title = ml.get_methodology_title(meth_file) or title
            except Exception:
                pass
        print(f"  Methodology: {title}")
        try:
            print(f"  Source: {Path(meth_file).relative_to(body_root)}")
        except ValueError:
            print(f"  Source: {meth_file}")
        current = ""
        if ml:
            try:
                current = ml.get_current_phase(meth_file) or ""
            except Exception:
                pass
        print(f"  Current phase: {current or 'Not started'}")
    else:
        print("  Methodology: Pending detection")
        print("  Source: layer2-templates/methodologies/")
    print()

    # Tokens
    print("Tokens (layer1/rules/tokens.md)")
    for token_name in ("ACTIVE-TESTING-APPROVAL", "DESTRUCTIVE-APPROVAL"):
        granted = False
        if tk:
            try:
                granted = tk.has_token(token_name, body_root)
            except Exception:
                pass
        print(f"  {token_name}: {'GRANTED' if granted else 'Not set'}")
    print()

    # Artifacts
    print("Artifacts")
    artifacts_dir = body_root / ".bra" / "artifacts"
    if artifacts_dir.is_dir():
        count = sum(1 for _ in artifacts_dir.rglob("*") if _.is_file())
        print(f"  Files: {count}")
        print("  Location: .bra/artifacts/")
    else:
        print("  None")
    print()


# ============== MAIN ==============

def _show_help() -> None:
    print("Usage: agentic-handler.py [--status|--resume|--help]")
    print("")
    print("Handles /agentic command for Claude-first engagement loop.")
    print("")
    print("Three-Layer Architecture:")
    print("  Layer 1: layer1/rules/     - Governance, tokens (rarely changes)")
    print("  Layer 2: layer2-templates/ - Skillset, toolset, methodologies (grows)")
    print("  Layer 3: layer3-engagement/ - Scope, ROE, engagement config")
    print("")
    print("Options:")
    print("  (no args)   Full startup with banner and preflight")
    print("  --resume    Resume without banner")
    print("  --status    Show current status only")


def parse_args(argv: list[str]) -> SimpleNamespace:
    args = SimpleNamespace(resume=False, status=False, help=False)
    for raw in argv:
        if raw == "--resume":
            args.resume = True
        elif raw == "--status":
            args.status = True
        elif raw in {"--help", "-h"}:
            args.help = True
        else:
            args.invalid = raw
            return args
    args.invalid = ""
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if getattr(args, "invalid", ""):
        _show_help()
        return 1
    if args.help:
        _show_help()
        return 0
    body_root = _detect_body_root(Path(__file__).resolve())
    os.chdir(body_root)

    libs = _import_libs(body_root)

    if args.status:
        _show_status(body_root, libs)
        return 0

    # Full startup or resume
    if not _run_preflight(body_root, libs):
        return 99 if libs.get("killswitch") and libs["killswitch"].is_killswitch_active(body_root) else 1

    target_type, methodology_file, current_phase = _detect_and_load_methodology(body_root, libs)

    if not args.resume:
        _generate_phase_context(body_root, libs, target_type, methodology_file, current_phase)

    _generate_handoff(body_root, libs, target_type, methodology_file, current_phase)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
