#!/usr/bin/env python3
"""report-ready.py -- Engagement Report + Disclosure Profile Prep

Purpose: Generate layer3-engagement/REPORT.md and collect disclosure metadata.
Invariant: Uses local engagement artifacts only, no external transmission.

Faithfully ported from report-ready.sh.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TYPES: tuple[str, ...] = ("generic", "vendor", "cna")

# Canonical disclosure placeholders
TBD_RESEARCH_TARGET = "_TBD: Product/Service name_"
TBD_VENDOR_NAME = "_TBD: Vendor name_"
TBD_FIRMWARE_VERSION = "_TBD: Version tested_"
TBD_RESEARCHER_NAME = "_TBD: Name_"
TBD_RESEARCHER_EMAIL = "_TBD: Email_"
TBD_PGP_KEY_ID = "_TBD: Key ID or link_"
TBD_VENDOR_CONTACT = "_TBD: Vendor contact (email or portal URL)_"

# ---------------------------------------------------------------------------
# Path helpers  (cwd == body/ when invoked via bridge.py)
# ---------------------------------------------------------------------------

def _body_root() -> Path:
    """Return the body/ root.  cwd is body/ when bridge.py calls us."""
    return Path.cwd()


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class _Logger:
    def __init__(self, log_path: Path) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = log_path

    def _write(self, level: str, message: str) -> None:
        ts = _timestamp()
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] [{level}] {message}\n")

    def info(self, message: str) -> None:
        print(f"[INFO] {message}")
        self._write("INFO", message)

    def warn(self, message: str) -> None:
        print(f"[WARN] {message}")
        self._write("WARN", message)

    def report(self, message: str) -> None:
        print(f"[REPORT] {message}")
        self._write("REPORT", message)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    cvss: str = ""
    status: str = ""


@dataclass
class DisclosureProfile:
    research_target: str = ""
    vendor_name: str = ""
    firmware_version: str = ""
    researcher_name: str = ""
    researcher_email: str = ""
    pgp_key_id: str = ""
    vendor_contact: str = ""
    report_types: str = "generic,vendor,cna"

# ---------------------------------------------------------------------------
# Markdown / metadata helpers
# ---------------------------------------------------------------------------

def _strip_markdown_value(value: str) -> str:
    """Strip markdown formatting from a value string."""
    value = value.replace("\r", "")
    value = value.replace("**", "")
    value = value.replace("#", "")
    value = value.strip().lstrip("- ").strip()
    return value


def _extract_scope_field(scope_path: Path, label: str) -> str:
    """Extract a **Label:** value from SCOPE.md."""
    if not scope_path.exists():
        return ""
    content = scope_path.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(rf"^\*\*{re.escape(label)}:\*\*\s*(.+)$", re.MULTILINE)
    m = pattern.search(content)
    if not m:
        return ""
    return _strip_markdown_value(m.group(1))


def _extract_meta_value(meta_path: Path, key: str) -> str:
    """Extract a value from engagement_meta.json."""
    if not meta_path.exists():
        return ""
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8", errors="ignore"))
        return str(data.get(key, "") or "")
    except (json.JSONDecodeError, OSError):
        return ""

# ---------------------------------------------------------------------------
# Findings parser  (replaces the awk-based extract_findings_tsv)
# ---------------------------------------------------------------------------

def _parse_findings(findings_path: Path, filter_path: Path) -> list[Finding]:
    """Parse FINDINGS.md into structured Finding records, respecting filter."""
    if not findings_path.exists():
        return []

    # Load optional include filter
    include_set: set[int] | None = None
    if filter_path.exists():
        try:
            data = json.loads(filter_path.read_text(encoding="utf-8", errors="ignore"))
            ids = data.get("include", [])
            include_set = {int(i) for i in ids}
        except (json.JSONDecodeError, ValueError, OSError):
            pass

    content = findings_path.read_text(encoding="utf-8", errors="ignore")
    findings: list[Finding] = []
    current: Finding | None = None

    for line in content.splitlines():
        # New finding header: ## [FINDING-NNN] Title text
        m = re.match(r"^## \[(FINDING-\d+)\]\s*(.*)", line)
        if m:
            if current is not None:
                findings.append(current)
            fid = m.group(1)
            title = m.group(2).strip()
            current = Finding(finding_id=fid, title=title)
            continue

        if current is None:
            continue

        # Severity row
        m = re.match(r"^\| \*\*Severity\*\* \| (.+?) \|", line)
        if m:
            current.severity = m.group(1).strip()
            continue

        # CVSS row
        m = re.match(r"^\| \*\*CVSS\*\* \| (.+?) \|", line)
        if m:
            current.cvss = m.group(1).strip()
            continue

        # Status row
        m = re.match(r"^\| \*\*Status\*\* \| (.+?) \|", line)
        if m:
            current.status = m.group(1).strip()
            continue

    if current is not None:
        findings.append(current)

    # Apply include filter
    if include_set is not None:
        def _numeric_id(fid: str) -> int:
            num_str = fid.replace("FINDING-", "")
            try:
                return int(num_str)
            except ValueError:
                return -1
        findings = [f for f in findings if _numeric_id(f.finding_id) in include_set]

    return findings


def _count_severity(findings: list[Finding], sev: str) -> int:
    return sum(1 for f in findings if f.severity.upper() == sev.upper())


def _render_findings_rows_by_severity(findings: list[Finding], sev: str) -> str:
    rows = [
        f"| {f.finding_id} | {f.title} | {f.cvss} | {f.status} |"
        for f in findings
        if f.severity.upper() == sev.upper()
    ]
    if rows:
        return "\n".join(rows)
    return f"| _None_ | _No {sev} findings_ | - | - |"


def _render_low_info_rows(findings: list[Finding]) -> str:
    rows = [
        f"| {f.finding_id} | {f.title} | {f.severity} |"
        for f in findings
        if f.severity.upper() in ("LOW", "INFO")
    ]
    if rows:
        return "\n".join(rows)
    return "| _None_ | _No low/informational findings_ | - |"

# ---------------------------------------------------------------------------
# Report type helpers
# ---------------------------------------------------------------------------

def _normalize_report_types(raw: str) -> str:
    """Normalize and deduplicate report types string."""
    seen: dict[str, bool] = {}
    out: list[str] = []
    for item in raw.split(","):
        item = item.strip().lower()
        if item in ("generic", "vendor", "cna") and item not in seen:
            seen[item] = True
            out.append(item)
    if not out:
        out = ["generic", "vendor", "cna"]
    return ",".join(out)


def _report_type_selected(report_types: str, wanted: str) -> bool:
    return wanted in report_types.split(",")

# ---------------------------------------------------------------------------
# Disclosure profile
# ---------------------------------------------------------------------------

def _load_existing_profile(profile_path: Path) -> dict[str, str]:
    """Load existing .disclosure-profile.env key=value pairs."""
    result: dict[str, str] = {}
    if not profile_path.exists():
        return result
    for line in profile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            # Unquote the value (handles shell quoting like $'...' or "..." or bare)
            val = val.strip()
            if val.startswith("$'") and val.endswith("'"):
                val = val[2:-1]
            elif (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            result[key] = val
    return result


def _safe_default(value: str, fallback: str) -> str:
    return value if value else fallback


def _git_config(body_root: Path, key: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(body_root), "config", "--get", key],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _is_interactive() -> bool:
    """Check if stdin and stdout are connected to a terminal."""
    try:
        return os.isatty(0) and os.isatty(1)
    except Exception:
        return False


def _ask_with_default(prompt: str, default: str) -> str:
    """Prompt for input with a default value."""
    if default:
        answer = input(f"  {prompt} [{default}]: ").strip()
        return answer if answer else default
    else:
        return input(f"  {prompt}: ").strip()


def _validate_required_profile_fields(
    profile: DisclosureProfile,
    non_interactive: bool,
    log: _Logger,
) -> int:
    """Validate required fields based on selected report types. Returns 0 or 2."""
    missing: list[str] = []

    if _report_type_selected(profile.report_types, "cna"):
        if not profile.researcher_name or profile.researcher_name == TBD_RESEARCHER_NAME:
            missing.append("researcher_name")

    if _report_type_selected(profile.report_types, "vendor") or _report_type_selected(profile.report_types, "cna"):
        if not profile.vendor_name or profile.vendor_name == TBD_VENDOR_NAME:
            missing.append("vendor_name")
        if not profile.researcher_email or profile.researcher_email == TBD_RESEARCHER_EMAIL:
            missing.append("researcher_email")
        if not profile.pgp_key_id or profile.pgp_key_id == TBD_PGP_KEY_ID:
            missing.append("pgp_key_id")
        if not profile.vendor_contact or profile.vendor_contact == TBD_VENDOR_CONTACT:
            missing.append("vendor_contact")

    if not missing:
        return 0

    if non_interactive:
        log.warn(f"End engagement intake incomplete for selected report types ({profile.report_types}).")
        print(f"MISSING_REQUIRED_FIELDS: {','.join(missing)}")
        return 2

    return 0


def _prepare_disclosure_profile(
    body_root: Path,
    profile_path: Path,
    scope_path: Path,
    cli_report_types: str,
    non_interactive: bool,
    log: _Logger,
) -> tuple[DisclosureProfile, int]:
    """Build the disclosure profile, optionally prompting interactively.

    Returns (profile, exit_code) where exit_code is 0 on success or 2 on
    missing required fields in non-interactive mode.
    """
    target_name = _extract_scope_field(scope_path, "Name")
    target_version = _extract_scope_field(scope_path, "Version")
    git_name = _git_config(body_root, "user.name")
    git_email = _git_config(body_root, "user.email")
    project_name = body_root.parent.name
    if target_name:
        project_name = target_name

    # Load any existing profile values
    existing = _load_existing_profile(profile_path)

    profile = DisclosureProfile()
    profile.research_target = project_name
    profile.vendor_name = existing.get("VENDOR_NAME", os.environ.get("BRA_VENDOR", ""))
    profile.firmware_version = existing.get("FIRMWARE_VERSION", target_version)
    profile.researcher_name = existing.get("RESEARCHER_NAME", os.environ.get("BRA_RESEARCHER", git_name))
    profile.researcher_email = existing.get("RESEARCHER_EMAIL", os.environ.get("BRA_EMAIL", git_email))
    profile.pgp_key_id = existing.get("PGP_KEY_ID", os.environ.get("BRA_PGP_KEY", ""))
    profile.vendor_contact = existing.get("VENDOR_CONTACT", os.environ.get("BRA_VENDOR_CONTACT", ""))
    profile.report_types = existing.get("REPORT_TYPES", "generic,vendor,cna")

    if cli_report_types:
        profile.report_types = cli_report_types
    profile.report_types = _normalize_report_types(profile.report_types)

    # Interactive intake
    if _is_interactive() and not non_interactive:
        print("")
        log.report("Disclosure metadata intake")
        profile.vendor_name = _ask_with_default(
            "Vendor", _safe_default(profile.vendor_name, TBD_VENDOR_NAME))
        profile.firmware_version = _ask_with_default(
            "Firmware/Version", _safe_default(profile.firmware_version, TBD_FIRMWARE_VERSION))
        profile.researcher_name = _ask_with_default(
            "Researcher name", _safe_default(profile.researcher_name, os.environ.get("USER", TBD_RESEARCHER_NAME)))
        profile.researcher_email = _ask_with_default(
            "Researcher email", _safe_default(profile.researcher_email, TBD_RESEARCHER_EMAIL))
        profile.pgp_key_id = _ask_with_default(
            "PGP key id / fingerprint", _safe_default(profile.pgp_key_id, TBD_PGP_KEY_ID))
        profile.vendor_contact = _ask_with_default(
            "Vendor contact (email/portal)", _safe_default(profile.vendor_contact, TBD_VENDOR_CONTACT))
        profile.report_types = _ask_with_default(
            "Report types (generic,vendor,cna)", profile.report_types)
        profile.report_types = _normalize_report_types(profile.report_types)

    # Validate
    rc = _validate_required_profile_fields(profile, non_interactive, log)
    if rc != 0:
        return profile, rc

    # Fill TBD placeholders for any still-empty fields
    profile.research_target = project_name
    profile.vendor_name = _safe_default(profile.vendor_name, TBD_VENDOR_NAME)
    profile.firmware_version = _safe_default(profile.firmware_version, TBD_FIRMWARE_VERSION)
    profile.researcher_name = _safe_default(
        profile.researcher_name, os.environ.get("USER", TBD_RESEARCHER_NAME))
    profile.researcher_email = _safe_default(profile.researcher_email, TBD_RESEARCHER_EMAIL)
    profile.pgp_key_id = _safe_default(profile.pgp_key_id, TBD_PGP_KEY_ID)
    profile.vendor_contact = _safe_default(profile.vendor_contact, TBD_VENDOR_CONTACT)
    profile.report_types = _normalize_report_types(profile.report_types)

    # Write profile file
    profile_path.parent.mkdir(parents=True, exist_ok=True)

    def _shell_quote(s: str) -> str:
        return shlex.quote(s)

    lines = [
        "# Disclosure profile generated by report-ready.py",
        f"RESEARCH_TARGET={_shell_quote(profile.research_target)}",
        f"VENDOR_NAME={_shell_quote(profile.vendor_name)}",
        f"FIRMWARE_VERSION={_shell_quote(profile.firmware_version)}",
        f"RESEARCHER_NAME={_shell_quote(profile.researcher_name)}",
        f"RESEARCHER_EMAIL={_shell_quote(profile.researcher_email)}",
        f"PGP_KEY_ID={_shell_quote(profile.pgp_key_id)}",
        f"VENDOR_CONTACT={_shell_quote(profile.vendor_contact)}",
        f"REPORT_TYPES={_shell_quote(profile.report_types)}",
    ]
    profile_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("Disclosure profile updated: layer3-engagement/disclosure/.disclosure-profile.env")

    return profile, 0

# ---------------------------------------------------------------------------
# Artifact hash finalization
# ---------------------------------------------------------------------------

def _finalize_artifact_hashes(body_root: Path, findings_path: Path, log: _Logger) -> None:
    """Replace deferred hash markers with computed SHA-256 or N/A."""
    if not findings_path.exists():
        return

    content = findings_path.read_text(encoding="utf-8", errors="ignore")

    marker_legacy = "(Hash generated during report creation)"
    marker_computed = "(computed during report creation)"

    if marker_legacy not in content and marker_computed not in content:
        return

    log.warn("Deferred artifact hash markers detected; normalizing to SHA256 or N/A.")

    current_local_path = ""
    output_lines: list[str] = []

    for line in content.splitlines():
        # Track local artifact path
        m = re.match(r"^- Local: `(.+)`$", line)
        if m:
            current_local_path = m.group(1)

        # Replace hash markers
        if marker_legacy in line or marker_computed in line:
            replacement = "N/A"
            if current_local_path:
                resolved = body_root / current_local_path
                if resolved.is_file():
                    sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
                    replacement = sha
                    log.info(f"  Hash finalized for: {current_local_path}")
                else:
                    log.warn(f"  Artifact not found, using N/A hash: {resolved}")
            else:
                log.warn("  Missing local artifact path, using N/A hash.")

            line = line.replace(marker_legacy, replacement)
            line = line.replace(marker_computed, replacement)

        output_lines.append(line)

    findings_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")

# ---------------------------------------------------------------------------
# Stub / overwrite detection
# ---------------------------------------------------------------------------

def _is_stub_report(report_path: Path) -> bool:
    if not report_path.exists():
        return False
    content = report_path.read_text(encoding="utf-8", errors="ignore")
    return "# Report (Instance)" in content


def _should_write_report(report_path: Path, force: bool, log: _Logger) -> bool:
    if force:
        return True
    if not report_path.exists():
        return True
    if _is_stub_report(report_path):
        return True
    log.warn("Preserving existing REPORT.md (use --force to overwrite).")
    return False

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_report(
    body_root: Path,
    profile: DisclosureProfile,
    force: bool,
    log: _Logger,
) -> None:
    """Generate the full REPORT.md from engagement artifacts."""
    layer3 = body_root / "layer3-engagement"
    notes_dir = layer3 / "NOTES"
    report_path = layer3 / "REPORT.md"
    scope_path = layer3 / "SCOPE.md"
    findings_path = notes_dir / "FINDINGS.md"
    meta_path = body_root / ".bra" / "engagement_meta.json"
    filter_path = body_root / ".bra" / "report_findings_filter.json"

    # Finalize artifact hashes before generating report
    _finalize_artifact_hashes(body_root, findings_path, log)

    # Extract metadata
    target_name = _extract_scope_field(scope_path, "Name")
    target_version = _extract_scope_field(scope_path, "Version")
    target_type = _extract_scope_field(scope_path, "Target Type")
    methodology = _extract_scope_field(scope_path, "Methodology")
    start_ts = _extract_meta_value(meta_path, "started_at")
    end_ts = _extract_meta_value(meta_path, "ended_at")

    # Parse findings
    findings = _parse_findings(findings_path, filter_path)
    critical = _count_severity(findings, "CRITICAL")
    high = _count_severity(findings, "HIGH")
    medium = _count_severity(findings, "MEDIUM")
    low = _count_severity(findings, "LOW")
    info = _count_severity(findings, "INFO")
    total = len(findings)

    if not target_name:
        target_name = profile.research_target

    # Period
    if start_ts and end_ts:
        period = f"{start_ts} to {end_ts}"
    elif start_ts:
        period = f"{start_ts} to ongoing"
    else:
        period = _today()

    # Scope summary
    scope_summary = "Defined in engagement scope" if scope_path.exists() else "_TBD_"

    if not methodology:
        methodology = "_TBD_"

    # Risk / recommendations placeholders
    risk_summary = "_Pending AI-generated risk summary._"
    recommendations = "_Pending AI-generated recommendations based on findings._"

    # Intel highlights placeholder
    intel_highlights = "- _Pending AI-generated highlights from INTEL.md._"

    # Testing coverage
    artifacts_dir = body_root / ".bra" / "artifacts"
    intel_status = "Complete" if (artifacts_dir / ".intel_complete").exists() else "Not run"
    static_status = "Complete" if (artifacts_dir / ".static_complete").exists() else "Not run"
    dynamic_status = "Complete" if (artifacts_dir / ".dynamic_complete").exists() else "Not run"

    # Check whether we should write
    if not _should_write_report(report_path, force, log):
        return

    # Build the report
    tv = target_version or "_TBD_"
    tt = target_type or "_TBD_"

    report = f"""\
# Engagement Report

> Generated: {_timestamp()}

---

## Executive Summary

### Engagement Overview

| Field | Value |
|-------|-------|
| Client | _TBD_ |
| Target | {target_name} |
| Version | {tv} |
| Target Type | {tt} |
| Methodology | {methodology} |
| Period | {period} |

### Key Findings

| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| Informational | {info} |
| Total | {total} |

### Risk Summary

{risk_summary}

### Recommendations Summary

{recommendations}

---

## Technical Summary

### Methodology

{methodology}

### Intelligence Highlights

{intel_highlights}

### Tools Used

| Tool | Purpose |
|------|---------|
| _See engagement statistics_ | Full tool inventory and usage details |

### Testing Coverage

| Area | Coverage | Notes |
|------|----------|-------|
| Intel | {intel_status} | Based on .bra/artifacts/.intel_complete |
| Static | {static_status} | Based on .bra/artifacts/.static_complete |
| Dynamic | {dynamic_status} | Based on .bra/artifacts/.dynamic_complete |

---

## Findings Summary

### Critical Findings

| ID | Title | CVSS | Status |
|----|-------|------|--------|
{_render_findings_rows_by_severity(findings, "CRITICAL")}

### High Findings

| ID | Title | CVSS | Status |
|----|-------|------|--------|
{_render_findings_rows_by_severity(findings, "HIGH")}

### Medium Findings

| ID | Title | CVSS | Status |
|----|-------|------|--------|
{_render_findings_rows_by_severity(findings, "MEDIUM")}

### Low/Informational

| ID | Title | Severity |
|----|-------|----------|
{_render_low_info_rows(findings)}

---

## Remediation Roadmap

### Immediate (0-30 days)

| Finding | Action | Owner |
|---------|--------|-------|
| _Pending_ | _AI-generated from findings_ | _TBD_ |

### Short-term (30-90 days)

| Finding | Action | Owner |
|---------|--------|-------|
| _Pending_ | _AI-generated from findings_ | _TBD_ |

### Long-term (90+ days)

| Finding | Action | Owner |
|---------|--------|-------|
| _Pending_ | _AI-generated from findings_ | _TBD_ |

---

## Appendices

- Appendix A: Detailed Findings
- Appendix B: Evidence Artifacts
- Appendix C: Scope Definition
- Appendix D: Disclosure Profile

---

## Distribution

| Recipient | Version | Date |
|-----------|---------|------|
| _TBD_ | 1.0-draft | {_today()} |

---
"""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    log.report("Generated: layer3-engagement/REPORT.md")

# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _show_status(
    body_root: Path,
    report_types: str,
) -> None:
    """Print report-ready status."""
    layer3 = body_root / "layer3-engagement"
    report_path = layer3 / "REPORT.md"
    scope_path = layer3 / "SCOPE.md"
    findings_path = layer3 / "NOTES" / "FINDINGS.md"
    meta_path = body_root / ".bra" / "engagement_meta.json"
    filter_path = body_root / ".bra" / "report_findings_filter.json"
    profile_path = layer3 / "disclosure" / ".disclosure-profile.env"

    target_name = _extract_scope_field(scope_path, "Name")
    target_version = _extract_scope_field(scope_path, "Version")
    started = _extract_meta_value(meta_path, "started_at")
    ended = _extract_meta_value(meta_path, "ended_at")

    findings = _parse_findings(findings_path, filter_path)
    critical = _count_severity(findings, "CRITICAL")
    high = _count_severity(findings, "HIGH")
    medium = _count_severity(findings, "MEDIUM")
    low = _count_severity(findings, "LOW")
    info = _count_severity(findings, "INFO")

    # Load existing profile for display
    existing = _load_existing_profile(profile_path)

    print("=== Report Ready Status ===")
    print("")
    print(f"REPORT.md: {'present' if report_path.exists() else 'missing'}")
    print(f"Profile:   {'present' if profile_path.exists() else 'missing'}")
    print("")
    print(f"Target:    {target_name or 'Unknown'}")
    print(f"Version:   {target_version or 'Unknown'}")
    print(f"Started:   {started or 'Unknown'}")
    print(f"Ended:     {ended or 'Ongoing'}")
    print("")
    print(f"Findings:  CRIT={critical} HIGH={high} MED={medium} LOW={low} INFO={info}")
    print("")
    print("Disclosure Metadata")
    print(f"  Research Target: {existing.get('RESEARCH_TARGET', TBD_RESEARCH_TARGET)}")
    print(f"  Vendor:          {existing.get('VENDOR_NAME', TBD_VENDOR_NAME)}")
    print(f"  Firmware:        {existing.get('FIRMWARE_VERSION', TBD_FIRMWARE_VERSION)}")
    print(f"  Researcher:      {existing.get('RESEARCHER_NAME', os.environ.get('USER', TBD_RESEARCHER_NAME))}")
    print(f"  Email:           {existing.get('RESEARCHER_EMAIL', TBD_RESEARCHER_EMAIL)}")
    print(f"  PGP:             {existing.get('PGP_KEY_ID', TBD_PGP_KEY_ID)}")
    print(f"  Vendor Contact:  {existing.get('VENDOR_CONTACT', TBD_VENDOR_CONTACT)}")
    print(f"  Report Types:    {existing.get('REPORT_TYPES', 'generic,vendor,cna')}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

HELP_TEXT = """\
report-ready.py -- Engagement Report + Disclosure Profile Prep

USAGE:
    report-ready.py                    Generate report and disclosure profile
    report-ready.py --force            Overwrite existing REPORT.md
    report-ready.py --status           Show detected metadata/profile values
    report-ready.py --types <list>     Report types: generic,vendor,cna
    report-ready.py --non-interactive  Fail if required intake fields are missing
    report-ready.py --help             Show this help

DESCRIPTION:
    Generates layer3-engagement/REPORT.md with auto-populated fields
    and prepares disclosure metadata consumed by disclose.py.
"""


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)

    body_root = _body_root()
    log_dir = body_root / ".bra" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = _Logger(log_dir / "report_ready.log")

    # Parse arguments manually to match shell behaviour exactly
    mode = "run"
    force = False
    cli_report_types = ""
    non_interactive = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--help", "-h"):
            mode = "help"
        elif arg in ("--status", "-s"):
            mode = "status"
        elif arg in ("--force", "-f"):
            force = True
        elif arg == "--types":
            i += 1
            if i < len(args):
                cli_report_types = _normalize_report_types(args[i])
            else:
                cli_report_types = _normalize_report_types("")
        elif arg.startswith("--types="):
            cli_report_types = _normalize_report_types(arg.split("=", 1)[1])
        elif arg == "--non-interactive":
            non_interactive = True
        else:
            print(f"[ERROR] Unknown option: {arg}", file=sys.stderr)
            print(HELP_TEXT)
            return 1
        i += 1

    # Dispatch
    if mode == "help":
        print(HELP_TEXT)
        return 0

    if mode == "status":
        rt = cli_report_types if cli_report_types else "generic,vendor,cna"
        _show_status(body_root, rt)
        return 0

    # --- run mode ---
    layer3 = body_root / "layer3-engagement"
    scope_path = layer3 / "SCOPE.md"
    disclosure_dir = layer3 / "disclosure"
    disclosure_dir.mkdir(parents=True, exist_ok=True)
    profile_path = disclosure_dir / ".disclosure-profile.env"

    profile, rc = _prepare_disclosure_profile(
        body_root, profile_path, scope_path,
        cli_report_types, non_interactive, log,
    )
    if rc != 0:
        return rc

    _generate_report(body_root, profile, force, log)
    log.info("Report-ready sequence complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
