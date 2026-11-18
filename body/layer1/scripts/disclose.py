#!/usr/bin/env python3
"""Native disclosure package generator."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TYPES = ("generic", "vendor", "cna")
PROFILE_REL = Path("layer3-engagement") / "disclosure" / ".disclosure-profile.env"

TBD_RESEARCH_TARGET = "_TBD: Product/Service name_"
TBD_VENDOR_NAME = "_TBD: Vendor name_"
TBD_FIRMWARE_VERSION = "_TBD: Version tested_"
TBD_RESEARCHER_NAME = "_TBD: Name_"
TBD_RESEARCHER_EMAIL = "_TBD: Email_"
TBD_PGP_KEY_ID = "_TBD: Key ID or link_"
TBD_VENDOR_CONTACT = "_TBD: Vendor contact (email or portal URL)_"


@dataclass(slots=True)
class Finding:
    fid: str
    title: str
    severity: str = "UNKNOWN"
    cvss: str = "0.0"
    cwe: str = ""
    status: str = "Open"


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _append_log(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(f"[{_timestamp()}] [{level}] {message}\n")


def _compute_hash(path: Path) -> str:
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _md_escape(value: str) -> str:
    return value.replace("|", "\\|")


def _parse_types(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return DEFAULT_TYPES
    output: list[str] = []
    for item in raw.split(","):
        normalized = item.strip().lower()
        if normalized in DEFAULT_TYPES and normalized not in output:
            output.append(normalized)
    return tuple(output or DEFAULT_TYPES)


# ── Findings parsing ──────────────────────────────────────────────────────

def _extract_findings(findings_path: Path) -> list[Finding]:
    """Parse FINDINGS.md into structured finding records (mirrors awk TSV parser)."""
    if not findings_path.is_file():
        return []

    findings: list[Finding] = []
    current: Finding | None = None

    for line in findings_path.read_text(encoding="utf-8", errors="replace").splitlines():
        header = re.match(r"^## \[(FINDING-\d+)\]\s*(.*)", line)
        if header:
            if current is not None:
                findings.append(current)
            current = Finding(fid=header.group(1), title=header.group(2).strip())
            continue
        if current is None:
            continue

        if line.startswith("| **Severity** | "):
            parts = line.split("|")
            if len(parts) >= 3:
                current.severity = parts[2].strip().upper().split("(")[0].strip().split("/")[0].strip()
        elif line.startswith("| **CVSS** | "):
            m = re.search(r"(\d+\.?\d*)", line)
            if m:
                current.cvss = m.group(1)
        elif line.startswith("| **CWE** | "):
            parts = line.split("|")
            if len(parts) >= 3:
                current.cwe = parts[2].strip()
        elif line.startswith("| **Status** | "):
            parts = line.split("|")
            if len(parts) >= 3:
                current.status = parts[2].strip()

    if current is not None:
        findings.append(current)
    return findings


def _severity_summary(findings: list[Finding]) -> str:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        for level in counts:
            if level in f.severity.upper():
                counts[level] += 1
                break

    total = sum(counts.values())
    rows = ["| Severity | Count |", "|----------|-------|"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        rows.append(f"| {sev} | {counts[sev]} |")
    rows.append("")
    rows.append(f"**Total: {total} findings**")
    return "\n".join(rows)


def _render_findings_digest(findings: list[Finding]) -> str:
    if not findings:
        return "### [INFO] No Parsed Findings\n**Short description:** No finding records were parsed from FINDINGS.md.\n"

    rows: list[str] = []
    for f in findings:
        sev = f.severity or "UNKNOWN"
        rating = sev.capitalize()
        rows.extend([
            f"### [{sev}] {f.title}",
            f"**Affected artifact:** `{f.fid}`",
            "**Short description:** See the detailed findings record for the complete validated entry.",
            f"CVSS = {f.cvss} ({rating})",
            "**Remediation:**",
            f"1. Apply remediation documented under `{f.fid}` in FINDINGS.md.",
            "2. Re-test and confirm status update to Fixed.",
            f"**Status:** {f.status}",
            "",
        ])
    return "\n".join(rows)


# ── Profile loading ───────────────────────────────────────────────────────

def _load_profile(profile_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not profile_path.exists():
        return values
    for line in profile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        values[key.strip()] = raw_value.strip().strip('"')
    return values


def _scope_field(scope_path: Path, field: str) -> str:
    if not scope_path.is_file():
        return "_TBD_"
    text = scope_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(rf"\*\*{re.escape(field)}:\*\*\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else "_TBD_"


def _scope_name(scope_path: Path) -> str:
    result = _scope_field(scope_path, "Name")
    return result if result != "_TBD_" else _scope_field(scope_path, "Target Name")


def _research_period(meta_file: Path) -> str:
    if not meta_file.is_file():
        return "_TBD: Start_ to _TBD: End_"
    try:
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        start = data.get("started_at", "")
        end = data.get("ended_at", "")
        if start and end:
            return f"{start} to {end}"
        if start:
            return f"{start} to ongoing"
    except (OSError, json.JSONDecodeError):
        pass
    return "_TBD: Start_ to _TBD: End_"


# ── Validation ────────────────────────────────────────────────────────────

def _validate_required_fields(
    profile: dict[str, str], selected: tuple[str, ...], non_interactive: bool
) -> list[str]:
    missing: list[str] = []
    researcher_name = profile.get("RESEARCHER_NAME", TBD_RESEARCHER_NAME)
    vendor_name = profile.get("VENDOR_NAME", TBD_VENDOR_NAME)
    researcher_email = profile.get("RESEARCHER_EMAIL", TBD_RESEARCHER_EMAIL)
    pgp = profile.get("PGP_KEY_ID", TBD_PGP_KEY_ID)
    vendor_contact = profile.get("VENDOR_CONTACT", TBD_VENDOR_CONTACT)

    if "cna" in selected:
        if not researcher_name or researcher_name == TBD_RESEARCHER_NAME:
            missing.append("researcher_name")

    if "vendor" in selected or "cna" in selected:
        if not vendor_name or vendor_name == TBD_VENDOR_NAME:
            missing.append("vendor_name")
        if not researcher_email or researcher_email == TBD_RESEARCHER_EMAIL:
            missing.append("researcher_email")
        if not pgp or pgp == TBD_PGP_KEY_ID:
            missing.append("pgp_key_id")
        if not vendor_contact or vendor_contact == TBD_VENDOR_CONTACT:
            missing.append("vendor_contact")

    if missing and non_interactive:
        print(f"MISSING_REQUIRED_FIELDS: {','.join(missing)}", file=sys.stderr)
    return missing


# ── Write helper ──────────────────────────────────────────────────────────

def _write_if_needed(path: Path, content: str, *, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


# ── Document generators ──────────────────────────────────────────────────

def _generate_package(
    body_root: Path, findings: list[Finding], profile: dict[str, str],
    scope_path: Path, meta_file: Path, artifacts_dir: Path,
    output_path: Path, *, force: bool,
) -> bool:
    target = _md_escape(profile.get("RESEARCH_TARGET", _scope_name(scope_path)))
    vendor = _md_escape(profile.get("VENDOR_NAME", TBD_VENDOR_NAME))
    firmware = _md_escape(profile.get("FIRMWARE_VERSION", TBD_FIRMWARE_VERSION))
    researcher = _md_escape(profile.get("RESEARCHER_NAME", TBD_RESEARCHER_NAME))
    email = _md_escape(profile.get("RESEARCHER_EMAIL", TBD_RESEARCHER_EMAIL))
    pgp = _md_escape(profile.get("PGP_KEY_ID", TBD_PGP_KEY_ID))
    vendor_contact = _md_escape(profile.get("VENDOR_CONTACT", TBD_VENDOR_CONTACT))
    methodology = _scope_field(scope_path, "Methodology")
    period = _research_period(meta_file)

    # CVE submission table
    cve_rows = []
    for f in findings:
        cve_rows.append(f"| {f.fid} | {f.title} | {f.cvss} | {f.cwe} |")
    cve_table = "\n".join(cve_rows) if cve_rows else "| N/A | No findings | — | — |"

    # Evidence manifest
    evidence_rows: list[str] = []
    if artifacts_dir.is_dir():
        for path in sorted(artifacts_dir.rglob("*"))[:20]:
            if path.is_file() and path.suffix in (".md", ".txt", ".json"):
                h = _compute_hash(path)
                evidence_rows.append(f"| {path.name} | {h[:16]}... | _TBD: Description_ |")

    content = "\n".join([
        "# Disclosure Package",
        "",
        f"> Generated: {_timestamp()}",
        "> Status: DRAFT - Review before submission",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Research Target | {target} |",
        f"| Vendor | {vendor} |",
        f"| Firmware/Version | {firmware} |",
        f"| Methodology | {methodology} |",
        f"| Research Period | {period} |",
        f"| Disclosure Date | {_today()} |",
        "",
        "---",
        "",
        "## Vulnerability Summary",
        "",
        _severity_summary(findings),
        "",
        "---",
        "",
        "## Vulnerability Summary for CVE Submission",
        "",
        "| ID | Title | CVSS | CWE |",
        "|----|-------|------|-----|",
        cve_table,
        "",
        "---",
        "",
        "## Findings Overview",
        "",
        _render_findings_digest(findings),
        "---",
        "",
        "## Evidence Manifest",
        "",
        "| File | SHA256 | Description |",
        "|------|--------|-------------|",
        *evidence_rows,
        "",
        "---",
        "",
        "## Disclosure Timeline",
        "",
        "| Date | Action | Status |",
        "|------|--------|--------|",
        "| [Discovery Date] | Vulnerability discovered | Complete |",
        "| [Today] | Disclosure package prepared | Complete |",
        "| [Day +7] | Vendor notification sent | Pending |",
        "| [Day +30] | Vendor response deadline | Pending |",
        "| [Day +90] | Public disclosure | Pending |",
        "",
        "---",
        "",
        "## Contact Information",
        "",
        "| Role | Contact |",
        "|------|---------|",
        f"| Researcher | {researcher} |",
        f"| Email | {email} |",
        f"| PGP Key | {pgp} |",
        f"| Vendor Contact | {vendor_contact} |",
        "",
        "---",
        "",
        "## Files in This Package",
        "",
        "| File | Purpose |",
        "|------|---------|",
        "| disclosure-package.md | This summary document |",
        "| vendor-submission.md | Full technical disclosure for vendor |",
        "| cna-submission.md | Redacted CNA/CVE submission |",
        "| timeline.md | Disclosure timeline tracker |",
        "",
        "---",
        "",
        "**CONFIDENTIAL - Do not distribute without authorization**",
        "",
    ])
    return _write_if_needed(output_path, content, force=force)


def _generate_vendor(
    body_root: Path, findings: list[Finding], profile: dict[str, str],
    scope_path: Path, meta_file: Path,
    output_path: Path, *, force: bool,
) -> bool:
    target = _md_escape(profile.get("RESEARCH_TARGET", _scope_name(scope_path)))
    vendor = _md_escape(profile.get("VENDOR_NAME", TBD_VENDOR_NAME))
    firmware = _md_escape(profile.get("FIRMWARE_VERSION", TBD_FIRMWARE_VERSION))
    researcher = _md_escape(profile.get("RESEARCHER_NAME", TBD_RESEARCHER_NAME))
    email = _md_escape(profile.get("RESEARCHER_EMAIL", TBD_RESEARCHER_EMAIL))
    pgp = _md_escape(profile.get("PGP_KEY_ID", TBD_PGP_KEY_ID))
    vendor_contact = _md_escape(profile.get("VENDOR_CONTACT", TBD_VENDOR_CONTACT))
    target_type = _scope_field(scope_path, "Target Type")
    methodology = _scope_field(scope_path, "Methodology")
    period = _research_period(meta_file)

    # Vulnerability type table
    vuln_rows = []
    for f in findings:
        vuln_rows.append(f"| {f.fid} | CWE: {f.cwe}, CVSS: {f.cvss} |")
    vuln_table = "\n".join(vuln_rows) if vuln_rows else "| N/A | No findings |"

    # Remediation
    remediation = []
    for f in findings:
        remediation.append(f"- **{f.fid}** ({f.title}): Apply remediation documented in the finding record.")

    # Attachments
    attachments = []
    for f in findings:
        attachments.append(f"| {f.fid} | See evidence artifacts for {f.title} |")

    content = "\n".join([
        "# Vendor Security Disclosure",
        "",
        f"> Generated: {_timestamp()}",
        "> Status: DRAFT - Review before sending to vendor",
        "",
        "---",
        "",
        "## Introduction",
        "",
        f"This document contains a security disclosure for vulnerabilities identified",
        f"in {target}. We are committed to responsible disclosure and request",
        "acknowledgment within 7 days.",
        "",
        "---",
        "",
        "## Affected Product",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Vendor | {vendor} |",
        f"| Product | {target} |",
        f"| Version(s) | {firmware} |",
        f"| Target Type | {target_type} |",
        f"| Methodology | {methodology} |",
        f"| Research Period | {period} |",
        "| Component | _TBD_ |",
        "",
        "---",
        "",
        "## Vulnerability Type",
        "",
        "| Field | Value |",
        "|-------|-------|",
        vuln_table,
        "",
        "---",
        "",
        "## Description",
        "",
        "_TBD_",
        "",
        "---",
        "",
        "## Impact",
        "",
        "_TBD_",
        "",
        "---",
        "",
        "## Findings Summary",
        "",
        _severity_summary(findings),
        "",
        "---",
        "",
        "## Vulnerability Details",
        "",
        _render_findings_digest(findings),
        "---",
        "",
        "## Proof of Concept",
        "",
        "PoC artifacts are referenced per finding in the evidence directory.",
        "",
        "---",
        "",
        "## Suggested Remediation",
        "",
        *remediation,
        "",
        "---",
        "",
        "## References",
        "",
        "| Type | URL |",
        "|------|-----|",
        "| Vendor Advisory | _TBD: If available_ |",
        "| Researcher Advisory | _TBD: If publishing_ |",
        "| Patch | _TBD: If available_ |",
        "",
        "---",
        "",
        "## Disclosure Timeline",
        "",
        "We follow a 90-day disclosure policy:",
        "",
        "| Milestone | Date | Status |",
        "|-----------|------|--------|",
        f"| Initial Report | {_today()} | Sending |",
        "| Acknowledgment Due | [+7 days] | Pending |",
        "| Status Update Due | [+30 days] | Pending |",
        "| Remediation Target | [+60 days] | Pending |",
        "| Public Disclosure | [+90 days] | Pending |",
        "",
        "---",
        "",
        "## Researcher Contact",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Name | {researcher} |",
        f"| Email | {email} |",
        f"| PGP | {pgp} |",
        f"| Vendor Contact | {vendor_contact} |",
        "| Organization | _TBD_ |",
        "",
        "---",
        "",
        "## Attachments",
        "",
        "Evidence artifacts are collected during the disclosure packaging process.",
        "",
        "| Finding | Evidence |",
        "|---------|----------|",
        *attachments,
        "",
        "---",
        "",
        "**This disclosure is provided in good faith to improve security.**",
        "",
    ])
    return _write_if_needed(output_path, content, force=force)


def _generate_cna(
    findings: list[Finding], profile: dict[str, str],
    scope_path: Path, meta_file: Path,
    output_path: Path, *, force: bool,
) -> bool:
    target = _md_escape(profile.get("RESEARCH_TARGET", _scope_name(scope_path)))
    vendor = _md_escape(profile.get("VENDOR_NAME", TBD_VENDOR_NAME))
    firmware = _md_escape(profile.get("FIRMWARE_VERSION", TBD_FIRMWARE_VERSION))
    researcher = _md_escape(profile.get("RESEARCHER_NAME", TBD_RESEARCHER_NAME))
    period = _research_period(meta_file)

    # Candidate findings table
    cand_rows = []
    for f in findings:
        cand_rows.append(f"| {f.fid} | {f.title} | {f.cwe} |")
    cand_table = "\n".join(cand_rows) if cand_rows else "| N/A | No findings | — |"

    content = "\n".join([
        "# CVE Request Submission",
        "",
        f"> Generated: {_timestamp()}",
        "> Status: DRAFT - Review redactions before CNA submission",
        "",
        "---",
        "",
        "## Vulnerability Information",
        "",
        "### Product",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Vendor | {vendor} |",
        f"| Product | {target} |",
        f"| Version | {firmware} |",
        f"| Research Period | {period} |",
        "| Component | _TBD_ |",
        "",
        "### Vulnerability Type",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| CWE ID | _TBD: CWE-XXX_ |",
        "| CVSS Score | _TBD: X.X_ |",
        "| CVSS Vector | _TBD: CVSS:3.1/..._ |",
        "| Attack Vector | _TBD: Network/Adjacent/Local/Physical_ |",
        "",
        "---",
        "",
        "## Description",
        "",
        "_TBD: Provide a concise vulnerability description suitable for public CVE entry._",
        "",
        "---",
        "",
        "## Impact",
        "",
        "_TBD: Describe impact without exploitation details._",
        "",
        "---",
        "",
        "## Candidate Findings in Scope",
        "",
        "| ID | Title | CWE |",
        "|----|-------|-----|",
        cand_table,
        "",
        "---",
        "",
        "## References",
        "",
        "| Type | URL |",
        "|------|-----|",
        "| Vendor Advisory | _TBD: If available_ |",
        "| Researcher Advisory | _TBD: If publishing_ |",
        "| Patch | _TBD: If available_ |",
        "",
        "---",
        "",
        "## Disclosure Timeline",
        "",
        "| Date | Event |",
        "|------|-------|",
        "| [Discovery] | Vulnerability discovered |",
        "| [Vendor Notice] | Vendor notified |",
        "| [Public] | Public disclosure |",
        "",
        "---",
        "",
        "## Credit",
        "",
        researcher,
        "",
        "---",
        "",
        "## REDACTION CHECKLIST",
        "",
        "Before submitting to CNA, verify:",
        "",
        "- [ ] No exploitation code or detailed PoC",
        "- [ ] No internal/private URLs or paths",
        "- [ ] No customer/user data",
        "- [ ] No unremediated vulnerability details (if within embargo)",
        "- [ ] CWE accurately categorizes the vulnerability",
        "- [ ] CVSS score calculated correctly",
        "",
        "---",
        "",
        "**For CNA submission only - Contains redacted information**",
        "",
    ])
    return _write_if_needed(output_path, content, force=force)


def _generate_timeline(output_path: Path, *, force: bool) -> bool:
    content = "\n".join([
        "# Disclosure Timeline",
        "",
        f"> Created: {_timestamp()}",
        "> Policy: 90-day responsible disclosure",
        "",
        "---",
        "",
        "## Timeline",
        "",
        "| Date | Day | Event | Status | Notes |",
        "|------|-----|-------|--------|-------|",
        f"| {_today()} | 0 | Discovery documented | Complete | Initial finding |",
        "| _TBD_ | 1 | Disclosure package prepared | Complete | |",
        "| _TBD_ | 7 | Vendor notification sent | Pending | |",
        "| _TBD_ | 14 | Vendor acknowledgment due | Pending | |",
        "| _TBD_ | 30 | Vendor status update due | Pending | |",
        "| _TBD_ | 60 | Remediation target | Pending | |",
        "| _TBD_ | 90 | Public disclosure | Pending | |",
        "",
        "---",
        "",
        "## Communication Log",
        "",
        "| Date | Direction | Summary |",
        "|------|-----------|---------|",
        "| | | |",
        "",
        "---",
        "",
        "## Status",
        "",
        "- [ ] Vendor contacted",
        "- [ ] Vendor acknowledged",
        "- [ ] Vendor confirmed issue",
        "- [ ] Patch developed",
        "- [ ] Patch released",
        "- [ ] CVE assigned",
        "- [ ] Public disclosure",
        "",
        "---",
        "",
        "## Notes",
        "",
        "[Add any relevant notes about the disclosure process]",
        "",
    ])
    return _write_if_needed(output_path, content, force=force)


def _collect_evidence(body_root: Path, output_dir: Path, log_file: Path) -> None:
    """Collect evidence files with hashes into disclosure/evidence/."""
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    artifacts_dir = body_root / ".bra" / "artifacts"
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    for label, src in (("notes", notes_dir), ("artifacts", artifacts_dir)):
        if not src.is_dir():
            continue
        dest = evidence_dir / label
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        _append_log(log_file, "INFO", f"Evidence collected: {src} -> {dest}")

    print(f"[INFO] Evidence collected to: {evidence_dir}")


# ── Status ────────────────────────────────────────────────────────────────

def _show_status(body_root: Path, findings: list[Finding], selected: tuple[str, ...]) -> int:
    layer3 = body_root / "layer3-engagement"
    notes_dir = layer3 / "NOTES"
    disclosure_dir = layer3 / "disclosure"

    print("\n=== Pre-Disclosure Checklist ===\n")

    findings_file = notes_dir / "FINDINGS.md"
    if findings:
        print(f"[x] FINDINGS.md exists ({len(findings)} findings)")
    elif findings_file.is_file():
        print("[  ] FINDINGS.md exists (0 findings - nothing to disclose)")
    else:
        print("[  ] FINDINGS.md missing")

    for label, path in (
        ("SESSION.md", notes_dir / "SESSION.md"),
        ("scope.md defined", layer3 / "SCOPE.md"),
        ("REPORT.md generated", layer3 / "REPORT.md"),
    ):
        mark = "[x]" if path.is_file() else "[  ]"
        print(f"{mark} {label}")

    print("\n=== Disclosure Documents ===\n")
    for name in ("disclosure-package.md", "vendor-submission.md", "cna-submission.md",
                  "timeline.md", ".disclosure-profile.env"):
        mark = "[x]" if (disclosure_dir / name).is_file() else "[  ]"
        print(f"{mark} {name}")

    print(f"\nReport Types: {','.join(selected)}")

    if findings:
        print("\n=== Severity Summary ===\n")
        print(_severity_summary(findings))

    return 0


# ── CLI ───────────────────────────────────────────────────────────────────

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="disclose.py",
        description="Create disclosure-ready markdown packages from engagement artifacts.",
    )
    parser.add_argument("--package", action="store_true", help="Generate disclosure-package.md only.")
    parser.add_argument("--vendor", action="store_true", help="Generate vendor-submission.md only.")
    parser.add_argument("--cna", action="store_true", help="Generate cna-submission.md only.")
    parser.add_argument("--status", action="store_true", help="Show disclosure status and exit.")
    parser.add_argument("--timeline", action="store_true", help="Generate disclosure timeline document.")
    parser.add_argument("--evidence", action="store_true", help="Collect and hash evidence files.")
    parser.add_argument("--types", help="Comma-separated subset of: generic,vendor,cna.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing outputs.")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Fail if required intake fields are missing.")
    return parser.parse_args(argv)


def _selected_types(args: argparse.Namespace) -> tuple[str, ...]:
    explicit = ""
    if args.package:
        explicit = "generic"
    if args.vendor:
        explicit = "vendor"
    if args.cna:
        explicit = "cna"
    if explicit:
        return (explicit,)
    return _parse_types(args.types)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _detect_body_root(Path(__file__).resolve())
    layer3 = body_root / "layer3-engagement"
    disclosure_dir = layer3 / "disclosure"
    findings_path = layer3 / "NOTES" / "FINDINGS.md"
    scope_path = layer3 / "SCOPE.md"
    meta_file = body_root / ".bra" / "engagement_meta.json"
    artifacts_dir = body_root / ".bra" / "artifacts"
    log_file = body_root / ".bra" / "logs" / "disclose.log"
    script_dir = Path(__file__).resolve().parent

    selected = _selected_types(args)
    profile = _load_profile(body_root / PROFILE_REL)

    # Apply scope name as research target default
    scope_target = _scope_name(scope_path)
    if scope_target and scope_target != "_TBD_":
        profile.setdefault("RESEARCH_TARGET", scope_target)

    findings = _extract_findings(findings_path)

    if args.status:
        return _show_status(body_root, findings, selected)

    if args.evidence:
        _collect_evidence(body_root, disclosure_dir, log_file)
        return 0

    # Check findings exist
    if not findings:
        if not findings_path.is_file():
            print("No FINDINGS.md found in layer3-engagement/NOTES/", file=sys.stderr)
            print("Complete engagement phases 1-5 before disclosure", file=sys.stderr)
        else:
            print("No findings detected in FINDINGS.md", file=sys.stderr)
        return 2

    print(f"[INFO] Found {len(findings)} finding(s) in FINDINGS.md")

    # Validate required fields
    missing = _validate_required_fields(profile, selected, args.non_interactive)
    if missing and args.non_interactive:
        return 2

    written: list[Path] = []

    if "generic" in selected:
        pkg_path = disclosure_dir / "disclosure-package.md"
        if _generate_package(body_root, findings, profile, scope_path, meta_file,
                             artifacts_dir, pkg_path, force=args.force):
            written.append(pkg_path)
            _append_log(log_file, "INFO", f"Created: {pkg_path}")

    if "vendor" in selected:
        vnd_path = disclosure_dir / "vendor-submission.md"
        if _generate_vendor(body_root, findings, profile, scope_path, meta_file,
                            vnd_path, force=args.force):
            written.append(vnd_path)
            _append_log(log_file, "INFO", f"Created: {vnd_path}")

    if "cna" in selected:
        cna_path = disclosure_dir / "cna-submission.md"
        if _generate_cna(findings, profile, scope_path, meta_file,
                         cna_path, force=args.force):
            written.append(cna_path)
            _append_log(log_file, "INFO", f"Created: {cna_path}")

    if args.timeline or not (args.package or args.vendor or args.cna):
        tl_path = disclosure_dir / "timeline.md"
        if _generate_timeline(tl_path, force=args.force):
            written.append(tl_path)
            _append_log(log_file, "INFO", f"Created: {tl_path}")

    if written:
        for path in written:
            print(f"[INFO] wrote {path}")
        print(f"\n[INFO] Output directory: {disclosure_dir}")
        print("\nNext steps:")
        print("  1. Review and customize generated documents")
        print("  2. Fill in _TBD_ placeholders")
        print("  3. Verify CNA redactions are appropriate")
        print("  4. Update timeline.md with actual dates")
        print("  5. Run: disclose.py --evidence (collect evidence package)")
    else:
        print("[INFO] no files were rewritten (use --force to overwrite existing documents)")

    # Auto-invoke lessons-learned after full generation
    if not (args.package or args.vendor or args.cna or args.timeline):
        ll_script = script_dir / "lessons-learned.py"
        if ll_script.is_file():
            try:
                subprocess.run(
                    [sys.executable, str(ll_script), "--auto"],
                    cwd=str(body_root), capture_output=True, text=True, check=False,
                )
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
