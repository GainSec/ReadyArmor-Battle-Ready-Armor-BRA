#!/usr/bin/env python3
"""precheck.py -- Project Readiness Check & Preparation

Native Python port of precheck.sh.  Verifies the project environment is ready
for engagement and creates any missing directories/files needed throughout the
lifecycle.  Safe to run multiple times (idempotent).

Usage:
    precheck.py                     Run full precheck with auto-fix
    precheck.py --fix               Auto-fix missing items (default)
    precheck.py --check-only        Check only, don't create anything
    precheck.py --tools             Check tools availability only
    precheck.py --structure         Check/create structure only
    precheck.py --quiet             Minimal output
    precheck.py --help              Show this help

Exit Codes:
    0 - All checks passed (or fixed)
    1 - Some checks failed and couldn't be fixed
    2 - Check-only mode, issues found
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ANSI colours
_RED = "\033[0;31m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_BLUE = "\033[0;34m"
_CYAN = "\033[0;36m"
_MAGENTA = "\033[0;35m"
_BOLD = "\033[1m"
_NC = "\033[0m"

# ---------------------------------------------------------------------------
# .bra/ schema -- known dirs, files, hidden entries (mirrors bra_schema.py)
# ---------------------------------------------------------------------------

_BRA_REQUIRED_DIRS: list[str] = [
    "artifacts",
    "artifacts/raw",
    "artifacts/intel_work",
    "artifacts/static_work",
    "artifacts/dynamic_work",
    "artifacts/report_work",
    "logs",
    "approvals",
    "one-time-approvals",
    "phase_state",
    "specs",
    "snapshots",
    "tmp",
    "config",
    "improvements",
    "locks",
    "dry-run",
    "ui",
]

_BRA_KNOWN_DIRS: list[str] = [
    "artifacts",
    "logs",
    "approvals",
    "one-time-approvals",
    "phase_state",
    "specs",
    "ui",
    "snapshots",
    "tmp",
    "improvements",
    "locks",
    "dry-run",
    "config",
]

_BRA_KNOWN_FILES: list[str] = [
    "pipeline_state.json",
    "hunt_state.json",
    "improvement_state.json",
    "engagement_meta.json",
    "approved_targets.json",
    "anon_map.json",
    "PRECHECK_REPORT.md",
    "phase_context.md",
    "last_capture.json",
    "service_state.json",
    "web-config.json",
    "overrides.json",
    "pending_findings.json",
    "report_findings_filter.json",
    "STOP",
    "paths-remote.md",
    "TOOL_APPROVAL_DISABLED",
]

_BRA_KNOWN_HIDDEN: list[str] = [".claude", ".config", ".cache", ".local"]

# Tools -- grouped exactly as the shell version
_TOOL_GROUPS: dict[str, list[str]] = {
    "Static Analysis": ["strings", "file", "hexdump", "xxd", "objdump"],
    "Reverse Engineering": ["radare2", "r2", "ghidra", "ida", "objdump", "nm", "readelf"],
    "Mobile Analysis": ["apktool", "jadx", "dex2jar", "aapt", "adb"],
    "Firmware/Embedded": ["binwalk", "firmwalker", "sasquatch", "jefferson"],
    "Network": ["nmap", "tcpdump", "wireshark", "tshark", "netcat", "nc", "curl", "wget"],
    "Debugging": ["gdb", "lldb", "strace", "ltrace", "dtrace", "frida"],
    "Fuzzing": ["afl-fuzz", "honggfuzz", "radamsa"],
    "Utilities": ["python3", "python", "ruby", "perl", "jq", "yq", "tree", "git"],
}

# Instance documents for layer3-engagement/
_INSTANCE_DOCS: dict[str, str] = {
    "SCOPE.md": (
        "# Scope (Instance)\n\n> Populate from scope-intake.md template.\n\n"
        "## In-Scope\n\n_TBD_\n\n## Out-of-Scope\n\n_TBD_\n"
    ),
    "ROE.md": (
        "# ROE -- Rules of Engagement (Instance)\n\n> Populate during scope intake.\n\n"
        "## Active Tokens\n\n| Token | Status |\n|-------|--------|\n| _TBD_ | _TBD_ |\n"
    ),
    "PLAN.md": (
        "# Plan (Instance)\n\n> Populate during planning phase.\n\n"
        "## Phases\n\n1. Intel\n2. Static\n3. Dynamic\n4. Report\n"
    ),
    "REPORT.md": "# Report (Instance)\n\n> Generate using /report-ready command.\n",
    "REVIEW.md": "# Review (Instance)\n\n> Populate during review phase.\n",
    "RETRO.md": "# Retrospective (Instance)\n\n> Generate using retro.sh script.\n",
    "README-PROJECTOVERVIEW.md": (
        "# Project Overview (Instance)\n\n> Populate during scope intake.\n\n"
        "## Target\n\n_TBD_\n\n## Timeline\n\n_TBD_\n"
    ),
    "BACKUPS.md": "# Backups (Instance)\n\n> Document backup procedures.\n",
    "CNA-SUBMISSION.md": "# CNA Submission (Instance)\n\n> Populate for CVE submission.\n",
    "DISCLOSURE-PACKAGE.md": "# Disclosure Package (Instance)\n\n> Populate for vendor disclosure.\n",
    "VENDOR-SUBMISSION.md": "# Vendor Submission (Instance)\n\n> Populate for vendor notification.\n",
    "TOOLSUITES.md": (
        "# Tool Configuration (Instance)\n\n"
        "> Document tools allowed for this engagement.\n"
        "> Reference: layer2-templates/toolset.md\n"
    ),
    "SKILLSUITES.md": (
        "# Skill Selection (Instance)\n\n"
        "> Document skills applicable to this engagement.\n"
        "> Reference: layer2-templates/skillset.md\n"
    ),
}

_OVERRIDES_TEMPLATE_CONTENT = textwrap.dedent("""\
    # Override Recommendations

    > Cross-engagement advisory overrides. Promoted from engagement pitch docs.
    > These are recommendations only -- never auto-materialized into `.bra/overrides.json`.

    ---

    ## Recommended Overrides

    <!-- FORMAT:
    ### [TYPE] match_key=match_value
    - **Rationale:** Why this override is recommended
    - **Engagements:** Number of engagements where this was used
    - **Action:** grant_session | allow | FULL | LIMITED
    -->

    ---

    ## Engagement Decisions

    <!-- Populated during engagement by engage.py -->
    <!-- Each decision is appended as it occurs -->
""")

# Script label map (for executability checks)
_SCRIPT_LABELS: dict[str, str] = {
    "agentic-handler": "Agent loop handler ready",
    "danger_check": "Safety gate check ready",
    "ref_harvest": "Reference harvester ready",
    "notes_guard": "Evidence guard ready",
    "audit": "Audit trail logger ready",
    "packup": "Package builder ready",
    "reset": "Environment reset ready",
    "precheck": "Self-check runner ready",
    "backup": "Backup manager ready",
    "retro": "Retrospective runner ready",
    "stats": "Stats collector ready",
    "report-ready": "Report finalizer ready",
    "disclose": "Disclosure builder ready",
    "ingest": "Growth ingest pipeline ready",
}


# ---------------------------------------------------------------------------
# Counters and report state
# ---------------------------------------------------------------------------

@dataclass
class Counts:
    passed: int = 0
    fixed: int = 0
    failed: int = 0
    skipped: int = 0
    report_lines: list[str] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit(msg: str, *, quiet: bool) -> None:
    if not quiet:
        print(msg)


def _result_pass(check: str, message: str, *, quiet: bool, c: Counts) -> None:
    c.passed += 1
    _emit(f"{_GREEN}[PASS]{_NC} {check}: {message}", quiet=quiet)
    c.log_lines.append(f"[PASS] {check}: {message}")
    c.report_lines.append(f"- [x] **{check}**: {message}")


def _result_fail(check: str, message: str, *, quiet: bool, c: Counts) -> None:
    c.failed += 1
    _emit(f"{_RED}[FAIL]{_NC} {check}: {message}", quiet=quiet)
    c.log_lines.append(f"[FAIL] {check}: {message}")
    c.report_lines.append(f"- [ ] **{check}**: {message}")


def _result_fixed(check: str, message: str, *, quiet: bool, c: Counts) -> None:
    c.fixed += 1
    _emit(f"{_YELLOW}[FIXED]{_NC} {check}: {message}", quiet=quiet)
    c.log_lines.append(f"[FIXED] {check}: {message}")
    c.report_lines.append(f"- [~] **{check}**: {message} (auto-fixed)")


def _result_skip(check: str, message: str, *, quiet: bool, c: Counts) -> None:
    c.skipped += 1
    _emit(f"{_CYAN}[SKIP]{_NC} {check}: {message}", quiet=quiet)
    c.log_lines.append(f"[SKIP] {check}: {message}")
    c.report_lines.append(f"- [-] **{check}**: {message} (skipped)")


def _section(title: str, *, quiet: bool, c: Counts) -> None:
    _emit("", quiet=quiet)
    _emit(f"{_BOLD}{_MAGENTA}=== {title} ==={_NC}", quiet=quiet)
    _emit("", quiet=quiet)
    c.log_lines.append("")
    c.log_lines.append(f"=== {title} ===")
    c.report_lines.append("")
    c.report_lines.append(f"### {title}")
    c.report_lines.append("")


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Core check helpers
# ---------------------------------------------------------------------------

def _check_directory(
    path: Path, description: str, *, fix: bool, check_only: bool,
    quiet: bool, root: Path, c: Counts,
) -> None:
    label = _rel(path, root)
    if path.is_dir():
        _result_pass(label, f"{description} exists", quiet=quiet, c=c)
    elif fix and not check_only:
        try:
            path.mkdir(parents=True, exist_ok=True)
            _result_fixed(label, f"{description} created", quiet=quiet, c=c)
        except OSError as exc:
            _result_fail(label, f"Could not create: {exc}", quiet=quiet, c=c)
    else:
        _result_fail(label, f"{description} missing", quiet=quiet, c=c)


def _check_file(
    path: Path, description: str, default_content: str = "", *,
    fix: bool, check_only: bool, quiet: bool, root: Path, c: Counts,
) -> None:
    label = _rel(path, root)
    if path.is_file():
        _result_pass(label, f"{description} exists", quiet=quiet, c=c)
    elif fix and not check_only:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(default_content, encoding="utf-8")
            _result_fixed(label, f"{description} created", quiet=quiet, c=c)
        except OSError as exc:
            _result_fail(label, f"Could not create: {exc}", quiet=quiet, c=c)
    else:
        _result_fail(label, f"{description} missing", quiet=quiet, c=c)


def _check_tool(tool: str, category: str, *, quiet: bool, c: Counts) -> None:
    if shutil.which(tool):
        _result_pass(tool, category, quiet=quiet, c=c)
    else:
        _result_skip(tool, category, quiet=quiet, c=c)


def _check_script(
    script: Path, *, fix: bool, check_only: bool,
    quiet: bool, root: Path, c: Counts,
) -> None:
    label = _rel(script, root)
    stem = script.stem
    friendly = _SCRIPT_LABELS.get(stem, "Ready")

    if not script.is_file():
        _result_skip(label, "Script not found", quiet=quiet, c=c)
    elif os.access(script, os.X_OK):
        _result_pass(label, friendly, quiet=quiet, c=c)
    elif fix and not check_only:
        try:
            script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            _result_fixed(label, "Made executable", quiet=quiet, c=c)
        except OSError as exc:
            _result_fail(label, f"Could not chmod: {exc}", quiet=quiet, c=c)
    else:
        _result_fail(label, "Not executable", quiet=quiet, c=c)


# ---------------------------------------------------------------------------
# Findings schema skeleton sync (mirrors sync_findings_schema_skeleton)
# ---------------------------------------------------------------------------

def _sync_findings_schema_skeleton(
    notes_dir: Path, templates_dir: Path, *,
    fix: bool, check_only: bool, quiet: bool, root: Path, c: Counts,
) -> None:
    if not fix or check_only:
        return

    findings_file = notes_dir / "FINDINGS.md"
    schema_file = templates_dir / "reference" / "evidence" / "findings-schema.md"

    if not findings_file.is_file() or not schema_file.is_file():
        return

    # Never rewrite if real findings already exist
    text = findings_file.read_text(encoding="utf-8")
    if re.search(r'^## \[FINDING-\d{3}\]', text, re.MULTILINE):
        return

    # Only replace legacy empty stub
    compact = re.sub(r'\s+', '', text)
    if compact != "#Findings>Documentfindingshereduringengagement.---":
        return

    # Extract template block from schema file
    schema_text = schema_file.read_text(encoding="utf-8")
    capturing = False
    template_lines: list[str] = []
    for line in schema_text.splitlines():
        if re.match(r'^## \[FINDING-XXX\] Title\s*$', line):
            capturing = True
        if re.match(r'^## Status Values\s*$', line):
            capturing = False
        if capturing:
            template_lines.append(line)

    # Trim trailing separators / fences
    while template_lines:
        stripped = template_lines[-1].strip()
        if stripped == "" or stripped == "---" or stripped == "```":
            template_lines.pop()
        else:
            break

    if not template_lines:
        return

    template_block = "\n".join(template_lines)
    new_content = (
        "# Findings\n\n"
        "> Document findings here during engagement.\n"
        "> Template source: layer2-templates/reference/evidence/findings-schema.md\n\n"
        "---\n\n"
        "## Finding Template\n\n"
        f"{template_block}\n\n"
        "---\n\n"
        "## Findings\n\n"
        "_Append findings below this line._\n\n"
        "---\n"
    )
    findings_file.write_text(new_content, encoding="utf-8")
    label = _rel(findings_file, root)
    _result_fixed(label, "Upgraded empty stub to schema-aligned findings skeleton", quiet=quiet, c=c)


# ---------------------------------------------------------------------------
# CHECK SECTIONS
# ---------------------------------------------------------------------------

def _check_structure(
    root: Path, *, fix: bool, check_only: bool, quiet: bool, c: Counts,
) -> None:
    _section("DIRECTORY STRUCTURE", quiet=quiet, c=c)

    bra_dir = root / ".bra"
    notes_dir = root / "layer3-engagement" / "NOTES"
    agent_dir = root / "layer3-engagement"

    # .bra root
    _check_directory(bra_dir, "BRA state directory", fix=fix, check_only=check_only,
                     quiet=quiet, root=root, c=c)

    # NOTES directories
    _check_directory(notes_dir, "Notes directory", fix=fix, check_only=check_only,
                     quiet=quiet, root=root, c=c)
    _check_directory(notes_dir / "reqs", "Requirements directory", fix=fix,
                     check_only=check_only, quiet=quiet, root=root, c=c)
    _check_directory(notes_dir / "reqs" / "reqfiles", "Requirement files directory",
                     fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # Engagement directories
    _check_directory(agent_dir, "Engagement docs directory", fix=fix,
                     check_only=check_only, quiet=quiet, root=root, c=c)
    _check_directory(agent_dir / "disclosure", "Disclosure directory", fix=fix,
                     check_only=check_only, quiet=quiet, root=root, c=c)
    _check_directory(agent_dir / "pitches", "Pitches directory", fix=fix,
                     check_only=check_only, quiet=quiet, root=root, c=c)
    _check_directory(agent_dir / "ingest", "Ingest directory", fix=fix,
                     check_only=check_only, quiet=quiet, root=root, c=c)

    # Rogue NOTES/ at project root
    if (root / "NOTES").is_dir():
        _result_fail("NOTES/",
                     "Rogue NOTES/ at project root - should be layer3-engagement/NOTES/",
                     quiet=quiet, c=c)
        _emit(f"  {_YELLOW}Hint:{_NC} Move content to layer3-engagement/NOTES/ then delete root NOTES/",
              quiet=quiet)


def _check_files(
    root: Path, *, fix: bool, check_only: bool, quiet: bool, c: Counts,
) -> None:
    _section("REQUIRED FILES", quiet=quiet, c=c)

    notes_dir = root / "layer3-engagement" / "NOTES"
    agent_dir = root / "layer3-engagement"
    templates_dir = root / "layer2-templates"

    # NOTES files
    _check_file(notes_dir / "FINDINGS.md", "Findings document",
                "# Findings\n\n> Document findings here during engagement.\n\n---\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _sync_findings_schema_skeleton(notes_dir, templates_dir, fix=fix,
                                   check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "LEADS.md", "Leads document",
                "# Leads\n\n> Track investigation leads here.\n\n---\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "INTEL.md", "Intel document",
                "# Intelligence Notes\n\n> Document intelligence findings here.\n\n---\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "EXECUTIVE_SUMMARY.md", "Executive summary",
                "# Executive Summary\n\n> High-level summary for stakeholders.\n\n---\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "SESSION.md", "Session log",
                "# Session Log\n\n> Session notes will be recorded here.\n\n---\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "reqs" / "_refmap.csv", "Reference map",
                "ref_id,source,description",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)
    _check_file(notes_dir / "reqs" / "reqfiles" / ".gitkeep", "Gitkeep", "",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # Instance documents
    for doc_name, doc_content in _INSTANCE_DOCS.items():
        _check_file(agent_dir / doc_name, doc_name, doc_content,
                     fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)


def _check_templates(
    root: Path, *, fix: bool, check_only: bool, quiet: bool, c: Counts,
) -> None:
    _section("TEMPLATES & METHODOLOGIES", quiet=quiet, c=c)

    templates_dir = root / "layer2-templates"
    agent_dir = root / "layer3-engagement"

    if templates_dir.is_dir():
        _result_pass("templates/", "Templates directory exists", quiet=quiet, c=c)

        # Methodology templates
        meth_dir = templates_dir / "methodologies"
        if meth_dir.is_dir():
            meth_count = len(list(meth_dir.glob("*.md")))
            if meth_count > 0:
                _result_pass("methodologies/", f"{meth_count} methodology templates available",
                             quiet=quiet, c=c)
            else:
                _result_skip("methodologies/", "No methodology templates found", quiet=quiet, c=c)
        else:
            _result_skip("methodologies/", "Methodologies directory not found", quiet=quiet, c=c)

        # Workflow templates
        wf_dir = templates_dir / "workflows"
        if wf_dir.is_dir():
            wf_count = len(list(wf_dir.glob("*.md")))
            if wf_count > 0:
                _result_pass("workflows/", f"{wf_count} workflow templates available",
                             quiet=quiet, c=c)
            else:
                _result_skip("workflows/", "No workflow templates found", quiet=quiet, c=c)
        else:
            _result_skip("workflows/", "Workflows directory not found", quiet=quiet, c=c)
    else:
        _result_skip("templates/", "Templates directory not found", quiet=quiet, c=c)

    # Core template files
    _core_templates = {
        "scope-intake.md": "Scope intake workflow ready",
        "plan.md": "Engagement plan template ready",
        "report.md": "Report generation template ready",
        "retro.md": "Retrospective template ready",
    }
    for tmpl_name, tmpl_label in _core_templates.items():
        tmpl_path = templates_dir / tmpl_name
        if tmpl_path.is_file():
            _result_pass(f"templates/{tmpl_name}", tmpl_label, quiet=quiet, c=c)
        else:
            _result_skip(f"templates/{tmpl_name}", "Not found", quiet=quiet, c=c)

    # Override recommendations template
    overrides_template = templates_dir / "overrides.md"
    if overrides_template.is_file():
        _result_pass("layer2-templates/overrides.md",
                     "Override recommendations template available", quiet=quiet, c=c)
    elif fix and not check_only:
        try:
            templates_dir.mkdir(parents=True, exist_ok=True)
            overrides_template.write_text(_OVERRIDES_TEMPLATE_CONTENT, encoding="utf-8")
            _result_fixed("layer2-templates/overrides.md",
                          "Created default override recommendations template", quiet=quiet, c=c)
        except OSError as exc:
            _result_fail("layer2-templates/overrides.md", f"Could not create: {exc}",
                         quiet=quiet, c=c)
    else:
        _result_fail("layer2-templates/overrides.md",
                     "Missing override recommendations template", quiet=quiet, c=c)

    # layer3 OVERRIDES.md
    l3_overrides = agent_dir / "OVERRIDES.md"
    if l3_overrides.is_file():
        _result_pass("layer3-engagement/OVERRIDES.md",
                     "Override audit trail exists", quiet=quiet, c=c)
    elif overrides_template.is_file():
        if fix and not check_only:
            try:
                shutil.copy2(overrides_template, l3_overrides)
                _result_fixed("layer3-engagement/OVERRIDES.md",
                              "Copied from template", quiet=quiet, c=c)
            except OSError as exc:
                _result_fail("layer3-engagement/OVERRIDES.md",
                             f"Could not copy: {exc}", quiet=quiet, c=c)
        else:
            _result_fail("layer3-engagement/OVERRIDES.md",
                         "Missing -- run with --fix to copy from template", quiet=quiet, c=c)
    else:
        _result_skip("layer3-engagement/OVERRIDES.md",
                     "No template to copy from", quiet=quiet, c=c)


def _check_tools(*, quiet: bool, c: Counts) -> None:
    _section("TOOL AVAILABILITY", quiet=quiet, c=c)

    for group_name, tools in _TOOL_GROUPS.items():
        c.report_lines.append(f"#### {group_name}")
        for tool in tools:
            _check_tool(tool, group_name.lower(), quiet=quiet, c=c)
        c.report_lines.append("")

    # Python runtime + key modules
    _section("PYTHON RUNTIME", quiet=quiet, c=c)
    _result_pass("python3", f"Runtime: {sys.executable} ({sys.version.split()[0]})",
                 quiet=quiet, c=c)

    key_modules = ["json", "pathlib", "shutil", "hashlib", "subprocess", "re"]
    for mod_name in key_modules:
        try:
            __import__(mod_name)
            _result_pass(f"module:{mod_name}", "importable", quiet=quiet, c=c)
        except ImportError:
            _result_fail(f"module:{mod_name}", "not importable", quiet=quiet, c=c)


def _check_scripts(
    root: Path, *, fix: bool, check_only: bool, quiet: bool, c: Counts,
) -> None:
    _section("SCRIPT EXECUTABILITY", quiet=quiet, c=c)

    scripts_dir = root / "layer1" / "scripts"
    lib_dir = root / "layer1" / "lib"

    # Check all .py scripts in layer1/scripts/
    if scripts_dir.is_dir():
        for script in sorted(scripts_dir.iterdir()):
            if script.suffix == ".py" and script.is_file():
                _check_script(script, fix=fix, check_only=check_only,
                              quiet=quiet, root=root, c=c)

    # Check lib scripts
    if lib_dir.is_dir():
        for lib in sorted(lib_dir.iterdir()):
            if lib.suffix == ".py" and lib.is_file():
                _check_script(lib, fix=fix, check_only=check_only,
                              quiet=quiet, root=root, c=c)


def _check_governance(
    root: Path, *, quiet: bool, c: Counts,
) -> None:
    _section("GOVERNANCE FILES", quiet=quiet, c=c)

    gov_files = {
        "CLAUDE.md": "Central governance hub loaded",
        "layer1/rules/tokens.md": "Approval token definitions loaded",
        "layer1/rules/scope.md": "Scope boundary rules loaded",
        "layer1/rules/roe.md": "Rules of engagement loaded",
    }
    for gf, gov_label in gov_files.items():
        if (root / gf).is_file():
            _result_pass(gf, gov_label, quiet=quiet, c=c)
        else:
            _result_skip(gf, "Not found (may be optional)", quiet=quiet, c=c)

    # Toolset / skillset
    if (root / "layer2-templates" / "toolset.md").is_file():
        _result_pass("layer2-templates/toolset.md", "Tool reference available",
                     quiet=quiet, c=c)
    else:
        _result_skip("layer2-templates/toolset.md", "Not found", quiet=quiet, c=c)

    if (root / "layer2-templates" / "skillset.md").is_file():
        _result_pass("layer2-templates/skillset.md", "Skill reference available",
                     quiet=quiet, c=c)
    else:
        _result_skip("layer2-templates/skillset.md", "Not found", quiet=quiet, c=c)


def _check_bra_schema(
    root: Path, *, fix: bool, check_only: bool, quiet: bool, c: Counts,
) -> None:
    _section(".BRA/ SCHEMA VALIDATION", quiet=quiet, c=c)

    bra_dir = root / ".bra"

    # Required subdirectories
    for subdir in _BRA_REQUIRED_DIRS:
        _check_directory(bra_dir / subdir, f".bra/{subdir} directory",
                         fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # Pipeline state
    pipeline_state_path = bra_dir / "pipeline_state.json"
    pipeline_state_content = json.dumps({
        "last_phase": "",
        "status": "initialized",
        "timestamp": _TIMESTAMP,
        "phases": {
            "intel": {"status": "pending"},
            "static": {"status": "pending"},
            "dynamic": {"status": "pending"},
            "report": {"status": "pending"},
        },
        "intel_complete": False,
        "static_complete": False,
        "dynamic_complete": False,
        "report_complete": False,
    }, indent=2) + "\n"
    _check_file(pipeline_state_path, "Pipeline state", pipeline_state_content,
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # Artifacts manifest
    manifest_content = json.dumps({
        "created": _TIMESTAMP,
        "artifacts": [],
    }, indent=2) + "\n"
    _check_file(bra_dir / "artifacts" / "manifest.json", "Artifacts manifest",
                manifest_content, fix=fix, check_only=check_only,
                quiet=quiet, root=root, c=c)
    _check_file(bra_dir / "artifacts" / "README.md", "Artifacts readme",
                "# Artifacts\n\nPhase artifacts are stored here.\n",
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # Overrides
    _check_file(bra_dir / "overrides.json", "Overrides", '{"rules":[]}',
                fix=fix, check_only=check_only, quiet=quiet, root=root, c=c)

    # State file presence re-checks
    if pipeline_state_path.is_file():
        _result_pass(".bra/pipeline_state.json", "Pipeline state present", quiet=quiet, c=c)
    else:
        _result_skip(".bra/pipeline_state.json", "Created by pipeline initialization",
                     quiet=quiet, c=c)

    manifest_path = bra_dir / "artifacts" / "manifest.json"
    if manifest_path.is_file():
        _result_pass(".bra/artifacts/manifest.json", "Artifacts manifest present",
                     quiet=quiet, c=c)
    else:
        _result_skip(".bra/artifacts/manifest.json", "Created by pipeline initialization",
                     quiet=quiet, c=c)

    # Validate overrides.json format
    overrides_path = bra_dir / "overrides.json"
    if overrides_path.is_file():
        try:
            data = json.loads(overrides_path.read_text(encoding="utf-8"))
            if "rules" in data:
                _result_pass("overrides.json", "Valid format", quiet=quiet, c=c)
            else:
                _result_fail("overrides.json", "Invalid format (missing 'rules' key)",
                             quiet=quiet, c=c)
        except (json.JSONDecodeError, OSError):
            _result_fail("overrides.json", "Invalid JSON", quiet=quiet, c=c)

    # Cross-reference with bra_schema.py if importable
    _cross_ref_bra_schema(bra_dir, quiet=quiet, c=c)

    # Rogue file/directory detection
    rogue_count = 0
    if bra_dir.is_dir():
        for entry in sorted(bra_dir.iterdir()):
            name = entry.name
            if name.startswith("."):
                continue  # handled below
            is_known = False
            if entry.is_dir():
                is_known = name in _BRA_KNOWN_DIRS
            elif entry.is_file():
                is_known = name in _BRA_KNOWN_FILES
            if not is_known:
                _result_fail(f".bra/{name}", "Rogue entry not in .bra/ schema",
                             quiet=quiet, c=c)
                rogue_count += 1

        # Hidden entries
        for entry in sorted(bra_dir.iterdir()):
            name = entry.name
            if not name.startswith("."):
                continue
            if name in (".", ".."):
                continue
            if name not in _BRA_KNOWN_HIDDEN:
                _result_fail(f".bra/{name}", "Rogue hidden entry not in .bra/ schema",
                             quiet=quiet, c=c)
                rogue_count += 1

    if rogue_count == 0:
        _result_pass("Rogue file check", "No unknown files in .bra/", quiet=quiet, c=c)


def _cross_ref_bra_schema(bra_dir: Path, *, quiet: bool, c: Counts) -> None:
    """Attempt to import bra_schema.py and cross-reference schema entries."""
    # Resolve path to head/bra/core/bra_schema.py relative to body root
    body_root = bra_dir.parent
    schema_module_path = body_root.parent / "head" / "bra" / "core" / "bra_schema.py"
    if not schema_module_path.is_file():
        # Also check if we are already at project level (body/ is root)
        for candidate in [
            body_root / ".." / "head" / "bra" / "core" / "bra_schema.py",
        ]:
            resolved = candidate.resolve()
            if resolved.is_file():
                schema_module_path = resolved
                break
        else:
            _result_skip("bra_schema.py", "Schema module not found for cross-reference",
                         quiet=quiet, c=c)
            return

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("bra_schema", schema_module_path)
        if spec is None or spec.loader is None:
            _result_skip("bra_schema.py", "Could not load schema module", quiet=quiet, c=c)
            return
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        schema: dict[str, dict[str, str]] = getattr(mod, "BRA_SCHEMA", {})
        if schema:
            _result_pass("bra_schema.py",
                         f"Cross-referenced with {len(schema)} schema entries",
                         quiet=quiet, c=c)
        else:
            _result_skip("bra_schema.py", "Schema loaded but empty", quiet=quiet, c=c)
    except Exception as exc:
        _result_skip("bra_schema.py", f"Could not load: {exc}", quiet=quiet, c=c)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _get_status_text(c: Counts) -> str:
    if c.failed == 0:
        if c.fixed > 0:
            return "READY (with fixes applied)"
        return "READY"
    return f"NOT READY - {c.failed} issues require attention"


def _generate_report(report_path: Path, root: Path, c: Counts, *, check_only: bool) -> None:
    mode_str = "Check Only" if check_only else "Auto-Fix"
    lines = [
        "# Precheck Report",
        "",
        f"**Generated:** {_TIMESTAMP}",
        f"**Project:** {root}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Result | Count |",
        "|--------|-------|",
        f"| PASS | {c.passed} |",
        f"| FIXED | {c.fixed} |",
        f"| FAIL | {c.failed} |",
        f"| SKIP | {c.skipped} |",
        "",
        f"**Overall Status:** {_get_status_text(c)}",
        "",
        "---",
        "",
        "## Configuration",
        "",
        f"- **Mode:** {mode_str}",
        f"- **Project:** `{root}`",
        "",
        "---",
        "",
        "## Detailed Results",
        "",
    ]
    lines.extend(c.report_lines)
    lines.extend([
        "",
        "---",
        "",
        "## Recommendations",
        "",
    ])
    if c.failed > 0:
        lines.append(f"- [ ] Address the {c.failed} failed checks above")
        lines.append("- [ ] Run `precheck.py --fix` to auto-fix fixable issues")
    if c.skipped > 10:
        lines.append("- [ ] Consider installing missing tools for full capability")
    lines.extend(["", "---", "", "*Report generated by precheck.py*", ""])

    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("\n".join(lines), encoding="utf-8")
    except OSError:
        pass


def _write_log(log_path: Path, root: Path, c: Counts) -> None:
    header = [
        f"Precheck started: {_TIMESTAMP}",
        f"Project: {root}",
        "",
    ]
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(header + c.log_lines) + "\n", encoding="utf-8")
    except OSError:
        pass


def _print_summary(root: Path, c: Counts, *, quiet: bool) -> None:
    if quiet:
        return

    report_path = root / ".bra" / "PRECHECK_REPORT.md"
    log_path = root / ".bra" / "logs" / "precheck.log"

    print()
    print(f"{_BOLD}{'=' * 79}{_NC}")
    print(f"{_BOLD}{'PRECHECK SUMMARY':^79}{_NC}")
    print(f"{_BOLD}{'=' * 79}{_NC}")
    print()
    print(f"  {_GREEN}PASS:{_NC} {c.passed}    "
          f"{_YELLOW}FIXED:{_NC} {c.fixed}    "
          f"{_RED}FAIL:{_NC} {c.failed}    "
          f"{_CYAN}SKIP:{_NC} {c.skipped}")
    print()

    if c.failed == 0:
        if c.fixed > 0:
            print(f"  {_GREEN}{_BOLD}STATUS: READY{_NC} (with {c.fixed} items auto-fixed)")
        else:
            print(f"  {_GREEN}{_BOLD}STATUS: READY{_NC}")
        print()
        print("  Project is ready for engagement.")
    else:
        print(f"  {_RED}{_BOLD}STATUS: NOT READY{_NC}")
        print()
        print(f"  {c.failed} issues require manual attention.")
        print("  Run with --fix to attempt auto-fix.")

    print()
    print(f"  Report: {report_path}")
    print(f"  Log: {log_path}")
    print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="precheck.py",
        description="Project Readiness Check & Preparation for BRA body runtime.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Checks performed:
              1. Directory structure (.bra/, layer3-engagement/, NOTES/)
              2. Required files (FINDINGS.md, LEADS.md, state files)
              3. Template accessibility (methodologies, workflows)
              4. Tool availability (static, RE, mobile, network, etc.)
              5. Script executability
              6. .bra/ schema validation
              7. Governance files

            Exit codes:
              0 - All checks passed (or fixed)
              1 - Some checks failed and couldn't be fixed
              2 - Check-only mode, issues found
        """),
    )
    parser.add_argument("--fix", action="store_true", default=False,
                        help="Auto-fix missing items (default behaviour when no --check-only).")
    parser.add_argument("--check-only", action="store_true", default=False,
                        help="Check only, don't create anything.")
    parser.add_argument("--tools", action="store_true", default=False,
                        help="Check tools availability only.")
    parser.add_argument("--structure", action="store_true", default=False,
                        help="Check/create structure only.")
    parser.add_argument("--quiet", "-q", action="store_true", default=False,
                        help="Minimal output.")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Resolve project root.  cwd is expected to be body/ (set by bridge.py)."""
    # body/layer1/scripts/precheck.py -> body/
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    root = _project_root()
    fix_mode = not args.check_only  # --fix is default; --check-only disables
    check_only = args.check_only
    quiet = args.quiet

    c = Counts()

    bra_dir = root / ".bra"
    log_dir = bra_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    _emit("", quiet=quiet)
    _emit(f"{_BOLD}{_CYAN}+{'=' * 77}+{_NC}", quiet=quiet)
    _emit(f"{_BOLD}{_CYAN}|{'PROJECT PRECHECK':^77}|{_NC}", quiet=quiet)
    _emit(f"{_BOLD}{_CYAN}+{'=' * 77}+{_NC}", quiet=quiet)
    _emit("", quiet=quiet)
    _emit(f"Project: {root}", quiet=quiet)
    mode_label = "check-only" if check_only else "auto-fix"
    _emit(f"Mode: {mode_label}", quiet=quiet)

    c.report_lines.append("## Configuration")
    c.report_lines.append("")
    c.report_lines.append(f"- **Mode:** {'Check Only' if check_only else 'Auto-Fix'}")
    c.report_lines.append(f"- **Project:** `{root}`")
    c.report_lines.append("")

    # Run appropriate checks
    if args.tools and not args.structure:
        _check_tools(quiet=quiet, c=c)
    elif args.structure and not args.tools:
        _check_structure(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_files(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_bra_schema(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
    else:
        _check_structure(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_files(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_bra_schema(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_templates(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_tools(quiet=quiet, c=c)
        _check_scripts(root, fix=fix_mode, check_only=check_only, quiet=quiet, c=c)
        _check_governance(root, quiet=quiet, c=c)

    # Generate report and log
    report_path = bra_dir / "PRECHECK_REPORT.md"
    log_path = log_dir / "precheck.log"
    _generate_report(report_path, root, c, check_only=check_only)
    _write_log(log_path, root, c)

    # Summary
    _print_summary(root, c, quiet=quiet)

    # Exit code
    if c.failed > 0:
        return 2 if check_only else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
