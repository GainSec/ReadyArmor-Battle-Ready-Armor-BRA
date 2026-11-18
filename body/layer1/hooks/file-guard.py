#!/usr/bin/env python3
"""Native file guard for file/path governance checks.

Policies enforced (in order):
  - layer1/*: NEVER writable (immutable governance layer)
  - Engagement containment: only .bra/ and layer3-engagement/ writable
    (exception: FRAMEWORK-DEV-APPROVAL token)
  - layer2-templates/*: blocked unless LAYER2-WRITE-APPROVAL token with path match
  - layer3-engagement/NOTES/*: append-only (Write content must be >= existing size)
  - Reporting outputs: append-only (ROE:16)
  - layer3-engagement/ allowlist: known files and subdirs only
  - SCOPE.md locked after SCOPE-CONFIRMED
  - .bra/ schema: artifacts/ is agent-writable; .bra/.claude/ is write-only

Stdout contract:
  - {"decision": "allow", "reason": "", "policy": "ALLOW", "meta": {}}
  - {"decision": "block", "reason": "...", "policy": "...", "meta": {}}

Exit codes represent transport/runtime behavior. Policy decisions are returned
via stdout JSON.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PolicyDecision = tuple[str, str]


# ============== CONSTANTS ==============

ALLOWED_LAYER3_SUBDIRS = {"NOTES", "disclosure", "pitches", "ingest"}

ALLOWED_LAYER3_ROOT_FILES = {
    "SCOPE.md", "ROE.md", "PLAN.md", "REPORT.md", "REVIEW.md", "RETRO.md",
    "README-PROJECTOVERVIEW.md", "BACKUPS.md", "TOOLSUITES.md", "SKILLSUITES.md",
    "CNA-SUBMISSION.md", "DISCLOSURE-PACKAGE.md", "VENDOR-SUBMISSION.md",
    "IMPROVEMENTS.md", "OVERRIDES.md", "STATS.md", "LESSONS-LEARNED.md",
    "SCRIPTS-AUDIT-REPORT.md", "README.md",
}

APPEND_ONLY_ROOT_FILES = {
    "layer3-engagement/REPORT.md",
    "layer3-engagement/CNA-SUBMISSION.md",
    "layer3-engagement/DISCLOSURE-PACKAGE.md",
    "layer3-engagement/VENDOR-SUBMISSION.md",
    "layer3-engagement/IMPROVEMENTS.md",
    "layer3-engagement/OVERRIDES.md",
}

BRA_KNOWN_DIRS = [
    "logs/", "approvals/", "one-time-approvals/", "config/",
    "phase_state/", "specs/", "ui/", "snapshots/", "tmp/",
    "improvements/", "locks/", "dry-run/",
    ".claude/", ".config/", ".cache/", ".local/", ".ner-cache/",
]

BRA_KNOWN_FILES = [
    "pipeline_state.json", "hunt_state.json", "improvement_state.json",
    "engagement_meta.json", "approved_targets.json",
    "PRECHECK_REPORT.md", "phase_context.md", "last_capture.json",
    "service_state.json", "web-config.json", "pending_findings.json",
    "overrides.json", "anon_map.json", "STOP", "paths-remote.md", "TOOL_APPROVAL_DISABLED",
]


# ============== UTILITIES ==============

def _detect_body_root() -> Path:
    script_path = Path(__file__).resolve()
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return Path.cwd().resolve()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(body_root: Path, message: str) -> None:
    try:
        log_file = body_root / ".bra" / "logs" / "file-guard.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"[{_utc_now()}] [PY-guard] {message}\n")
    except Exception:
        pass


def _normalize_target(file_path: str, body_root: Path) -> Path:
    target = Path(file_path)
    if not target.is_absolute():
        target = body_root / target
    try:
        return target.resolve(strict=False)
    except Exception:
        return Path(os.path.abspath(os.path.normpath(str(target))))


def _relative_policy_path(target: Path, body_root: Path) -> str:
    try:
        return target.relative_to(body_root).as_posix()
    except ValueError:
        return target.as_posix()


def _deny(reason: str, policy: str = "POLICY_BLOCKED") -> int:
    print(reason, file=sys.stderr)
    json.dump(
        {
            "decision": "block",
            "reason": reason,
            "policy": policy,
            "meta": {},
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


def _allow(policy: str = "ALLOW", reason: str = "") -> int:
    json.dump(
        {
            "decision": "allow",
            "reason": reason,
            "policy": policy,
            "meta": {},
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


def _extract_payload(stdin_text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_read_candidates(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    if tool_name == "Read":
        file_path = tool_input.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            candidates.append(file_path)
    elif tool_name in {"Grep", "Glob"}:
        path = tool_input.get("path")
        if isinstance(path, str) and path.strip():
            candidates.append(path)
        if tool_name == "Glob":
            pattern = tool_input.get("pattern")
            if isinstance(pattern, str) and pattern.strip():
                candidates.append(pattern)
    return candidates


_FINDING_FILENAME_PATTERNS = [
    re.compile(r"finding", re.IGNORECASE),
    re.compile(r"vulnerability", re.IGNORECASE),
    re.compile(r"\bvuln\b", re.IGNORECASE),
]

_FINDING_CONTENT_SIGNALS = [
    ("cvss", re.compile(r"CVSS:3\.\d/", re.IGNORECASE)),
    ("cwe", re.compile(r"CWE-\d+", re.IGNORECASE)),
    ("finding_header", re.compile(r"^##\s+(Finding|Vulnerability)", re.IGNORECASE | re.MULTILINE)),
    ("remediation", re.compile(r"^##\s+Remediation", re.IGNORECASE | re.MULTILINE)),
    ("severity_label", re.compile(r"Severity[:\s]*(Critical|High|Medium|Low)", re.IGNORECASE)),
]

_ARTIFACTS_BLOCK_REASON = (
    "BLOCKED: This content appears to be a finding record. "
    "Finding records belong in NOTES/FINDINGS.md using the findings-schema.md format, "
    "not in .bra/artifacts/. Emit a [FINDING] marker to start the proper documentation process."
)


def _find_notes_dir(file_path: Path) -> Path | None:
    try:
        for parent in file_path.resolve().parents:
            if parent.name == "NOTES" and (parent / "INTEL.md").exists():
                return parent
            notes = parent / "NOTES"
            if notes.exists() and (notes / "INTEL.md").exists():
                return notes
    except Exception:
        pass
    return None


def _findings_crosscheck(file_path: Path) -> str | None:
    if file_path.name == "FINDINGS.md" or "/reqs/" in file_path.as_posix():
        return None

    notes_dir = _find_notes_dir(file_path)
    if notes_dir is None:
        return None

    intel_path = notes_dir / "INTEL.md"
    findings_path = notes_dir / "FINDINGS.md"
    if not intel_path.exists():
        return None

    def _normalize_title(title: str) -> str:
        return " ".join((title or "").strip().lower().split())

    intel_content = intel_path.read_text(encoding="utf-8", errors="ignore")
    intel_ids: set[str] = set()
    intel_titles: set[str] = set()

    key_issues_idx = intel_content.find("## Key Issues Overview")
    if key_issues_idx != -1:
        intel_ids = set(re.findall(r"\|\s*(\d{3})\s*\|", intel_content[key_issues_idx:]))

    if not intel_ids:
        vuln_match = re.search(
            r"##\s*(?:Vulns|Vulnerabilities)\s*\n+(\|.+)\n\|[-|\s]+\n((?:\|.+\n?)+)",
            intel_content,
            re.IGNORECASE,
        )
        if vuln_match:
            for row in vuln_match.group(2).strip().splitlines():
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                if not cells:
                    continue
                title = _normalize_title(cells[0])
                if title:
                    intel_titles.add(title)

    if not intel_ids and not intel_titles:
        return None

    findings_ids: set[str] = set()
    findings_titles: set[str] = set()
    if findings_path.exists():
        findings_content = findings_path.read_text(encoding="utf-8", errors="ignore")
        findings_ids = set(re.findall(r"## \[FINDING-(\d{3})\]", findings_content))
        for match in re.finditer(r"## \[FINDING-(\d{3})\]\s*(.*)", findings_content):
            title = _normalize_title(match.group(2))
            if title:
                findings_titles.add(title)

    undocumented_ids = intel_ids - findings_ids
    if undocumented_ids:
        return (
            f"BLOCKED: {len(undocumented_ids)} finding(s) in INTEL.md lack "
            f"complete records in FINDINGS.md: "
            f"{', '.join(f'FINDING-{uid}' for uid in sorted(undocumented_ids))}. "
            "Document all findings before other work can proceed."
        )

    undocumented_titles = intel_titles - findings_titles
    if undocumented_titles:
        return (
            f"BLOCKED: {len(undocumented_titles)} finding(s) in INTEL.md "
            f"(Vulnerabilities table) lack complete records in FINDINGS.md. "
            "Document all findings before other work can proceed."
        )
    return None


def _check_artifacts_content(file_path: Path, content: str | None) -> str | None:
    parts = file_path.parts
    try:
        bra_idx = parts.index(".bra")
    except ValueError:
        return None
    if len(parts) <= bra_idx + 1 or parts[bra_idx + 1] != "artifacts":
        return None

    filename = file_path.name
    if re.match(r"^\d{3}-output\.md$", filename):
        return None

    for pattern in _FINDING_FILENAME_PATTERNS:
        if pattern.search(filename):
            return _ARTIFACTS_BLOCK_REASON

    if not content:
        return None

    matched_signals = {
        signal_name for signal_name, pattern in _FINDING_CONTENT_SIGNALS if pattern.search(content)
    }
    if len(matched_signals) >= 2:
        return _ARTIFACTS_BLOCK_REASON
    return None


# ============== FRAMEWORK-DEV-APPROVAL ==============

def _framework_dev_allows(rel_path: str, body_root: Path) -> bool:
    """Check if FRAMEWORK-DEV-APPROVAL token allows this path."""
    token_file = body_root / ".bra" / "approvals" / "FRAMEWORK-DEV-APPROVAL"
    if not token_file.is_file():
        return False
    try:
        for line in token_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if rel_path.startswith(line):
                return True
    except Exception:
        pass
    return False


# ============== LAYER2 WRITE APPROVAL ==============

def _layer2_write_allows(rel_path: str, body_root: Path) -> bool:
    """Check if LAYER2-WRITE-APPROVAL token allows this specific path."""
    token_file = body_root / ".bra" / "approvals" / "LAYER2-WRITE-APPROVAL"
    if not token_file.is_file():
        return False
    try:
        for line in token_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("*"):
                if rel_path.startswith(line[:-1]):
                    return True
            elif rel_path == line:
                return True
    except Exception:
        pass
    return False


# ============== APPEND-ONLY ENFORCEMENT ==============

def _check_append_only(
    tool_name: str, rel_path: str, file_path: Path, content: str | None, body_root: Path,
    context: str = "",
) -> str | None:
    """Return deny reason if append-only violation, else None."""
    if tool_name != "Write":
        # Edit tool: allow (can't easily measure size change pre-apply)
        _log(body_root, f"ALLOWED {rel_path} edit (append-only check deferred)")
        return None

    if not file_path.is_file():
        return None  # New file creation is fine

    try:
        existing_size = file_path.stat().st_size
    except Exception:
        return None

    if content is None:
        _log(body_root, f"WARN could not parse content for append-only check: {rel_path}")
        return None

    new_size = len(content.encode("utf-8"))
    if new_size < existing_size:
        _log(body_root, f"BLOCKED truncation: {rel_path} ({existing_size} -> {new_size})")
        ctx = f" ({context})" if context else ""
        return (
            f"BLOCKED: {rel_path} is append-only{ctx}. "
            f"File: {rel_path}. "
            f"Current: {existing_size} bytes, New: {new_size} bytes. "
            "Content can only grow, not shrink."
        )
    return None


# ============== MAIN POLICY CHECK ==============

def _check_policy(
    tool_name: str, rel_path: str, file_path: Path, content: str | None, body_root: Path,
) -> PolicyDecision | None:
    """Return (policy, reason) for deny, or None to allow."""

    framework_dev = _framework_dev_allows(rel_path, body_root)

    if tool_name in {"Write", "Edit"} and rel_path.startswith("layer3-engagement/"):
        crosscheck_reason = _findings_crosscheck(file_path)
        if crosscheck_reason:
            _log(body_root, f"BLOCKED undocumented findings: {rel_path}")
            return ("UNDOCUMENTED_FINDINGS_BLOCKED", crosscheck_reason)

    # --- layer1/ immutability (no token override) ---
    if rel_path == "layer1" or rel_path.startswith("layer1/"):
        _log(body_root, f"BLOCKED layer1 immutable: {rel_path}")
        return ("LAYER1_IMMUTABLE", (
            f"BLOCKED: layer1/ is immutable during engagement. "
            f"Cannot write to: {rel_path}. "
            "Governance assets (rules, scripts, hooks, lib) cannot be modified."
        ))

    # --- layer2-templates/ immutability ---
    if rel_path.startswith("layer2-templates/") and not framework_dev:
        if not _layer2_write_allows(rel_path, body_root):
            _log(body_root, f"BLOCKED immutable template: {rel_path}")
            return ("LAYER2_WRITE_TOKEN_REQUIRED", (
                f"BLOCKED: layer2-templates/ is immutable. "
                f"Path not in LAYER2-WRITE-APPROVAL token: {rel_path}. "
                "Use growth.sh or self-improvement.sh for framework updates."
            ))
        _log(body_root, f"ALLOWED layer2 write (token match): {rel_path}")

    # --- Engagement containment (skip if framework-dev allows) ---
    if not framework_dev:
        if not (
            rel_path == ".bra"
            or rel_path.startswith(".bra/")
            or rel_path.startswith("layer3-engagement/")
        ):
            name = Path(rel_path).name or "output.txt"
            _log(body_root, f"BLOCKED containment: {rel_path}")
            return ("FILE_PATH_CONTAINMENT_BLOCKED", (
                f"BLOCKED: File operation outside allowed directories. "
                f"Attempted: {rel_path}. "
                "During engagements, files must be in .bra/ or layer3-engagement/. "
                f"Suggested: .bra/artifacts/{name} or layer3-engagement/ingest/{name}."
            ))

    # --- layer3-engagement/NOTES/ append-only ---
    if rel_path.startswith("layer3-engagement/NOTES/"):
        reason = _check_append_only(tool_name, rel_path, file_path, content, body_root, "layer3-engagement/NOTES/ files are APPEND-ONLY")
        if reason:
            return ("APPEND_ONLY_VIOLATION", reason)

        # Invoke notes_guard.py to trigger self-improvement learning chain
        notes_guard = body_root / "layer1" / "scripts" / "notes_guard.py"
        if notes_guard.is_file():
            op = "append" if file_path.is_file() else "write"
            try:
                subprocess.run(
                    [sys.executable, str(notes_guard), op, str(file_path)],
                    capture_output=True, timeout=30,
                )
            except (subprocess.TimeoutExpired, OSError):
                pass

        _log(body_root, f"ALLOWED NOTES operation: {tool_name} {rel_path}")
        return None  # allow

    # --- Reporting outputs append-only (ROE:16) ---
    if rel_path in APPEND_ONLY_ROOT_FILES:
        reason = _check_append_only(tool_name, rel_path, file_path, content, body_root, "ROE:16 — reporting outputs")
        if reason:
            return ("APPEND_ONLY_VIOLATION", reason)
        _log(body_root, f"ALLOWED reporting output: {tool_name} {rel_path}")
        return None  # allow

    # --- layer3-engagement/ allowlist ---
    if rel_path.startswith("layer3-engagement/"):
        l3_rel = rel_path[len("layer3-engagement/"):]
        if not l3_rel:
            return None

        if l3_rel == "artifacts" or l3_rel.startswith("artifacts/"):
            _log(body_root, f"BLOCKED layer3-engagement/artifacts redirect: {rel_path}")
            return ("LAYER3_ARTIFACTS_BLOCKED", (
                f"BLOCKED: {rel_path} is not an allowed runtime artifact location. "
                "Use .bra/artifacts/ for governed runtime artifacts or "
                ".bra/artifacts/raw/ for captured evidence."
            ))

        first = l3_rel.split("/", 1)[0]
        if first in ALLOWED_LAYER3_SUBDIRS:
            return None

        if "/" not in l3_rel and l3_rel in ALLOWED_LAYER3_ROOT_FILES:
            # SCOPE.md locked after scope intake
            if l3_rel == "SCOPE.md" and (body_root / ".bra" / "approvals" / "SCOPE-CONFIRMED").is_file():
                _log(body_root, f"BLOCKED SCOPE.md locked (SCOPE-CONFIRMED): {rel_path}")
                return ("SCOPE_LOCKED_AFTER_CONFIRMATION", (
                    "BLOCKED: SCOPE.md is locked after scope intake (SCOPE-CONFIRMED). "
                    "Target scope changes must go through the approval modal. "
                    "Governance scripts manage SCOPE.md after intake."
                ))
            return None

        _log(body_root, f"BLOCKED not in layer3-engagement allowlist: {rel_path}")
        if "/" in l3_rel:
            subdir = l3_rel.split("/", 1)[0]
            return ("LAYER3_ALLOWLIST_BLOCKED", (
                f"BLOCKED: {rel_path} is not in the layer3-engagement/ allowlist. "
                f"Directory '{subdir}' is not a recognized engagement directory. "
                "Use .bra/artifacts/ for runtime data or NOTES/ for evidence."
            ))
        return ("LAYER3_ALLOWLIST_BLOCKED", (
            f"BLOCKED: {rel_path} is not in the layer3-engagement/ allowlist. "
            "Known root files: SCOPE.md, PLAN.md, REPORT.md, etc. "
            "Known subdirectories: NOTES/, disclosure/, pitches/, ingest/. "
            "Finding records belong in NOTES/FINDINGS.md, not in separate files."
        ))

    # --- .bra/ schema enforcement ---
    if rel_path == ".bra" or rel_path.startswith(".bra/"):
        bra_rel = rel_path[len(".bra/"):] if rel_path.startswith(".bra/") else ""

        # Agent-writable: artifacts/*
        if bra_rel == "artifacts" or bra_rel.startswith("artifacts/"):
            artifacts_reason = _check_artifacts_content(file_path, content)
            if artifacts_reason:
                _log(body_root, f"BLOCKED finding-like artifact content: {rel_path}")
                return ("ARTIFACT_FINDING_CONTENT_BLOCKED", artifacts_reason)
            return None

        # Write-only SDK scratch state: .bra/.claude/*
        if bra_rel == ".claude" or bra_rel.startswith(".claude/"):
            if tool_name == "Write":
                _log(body_root, f"ALLOWED .bra/.claude write-only path: {rel_path}")
                return None
            _log(body_root, f"BLOCKED .bra/.claude non-write access: {rel_path}")
            return ("BRA_CLAUDE_STATE_BLOCKED", (
                "BLOCKED: Agent access to .bra/.claude/ is restricted to Write only. "
                "Project-local .bra/.claude/ is SDK scratch state. "
                "Use .bra/artifacts/raw/ for retrievable captured evidence instead."
            ))

        # Known directories (blocked for agent)
        for known_dir in BRA_KNOWN_DIRS:
            if bra_rel.startswith(known_dir):
                _log(body_root, f"BLOCKED .bra/ schema ({known_dir.rstrip('/')}): {rel_path}")
                return ("BRA_SCHEMA_BLOCKED", (
                    f"BLOCKED: Agent Write/Edit not allowed to .bra/{known_dir.rstrip('/')}/. "
                    "This path is managed by governance scripts. "
                    "Only .bra/artifacts/ is agent-writable."
                ))

        # Known files (blocked for agent)
        for known_file in BRA_KNOWN_FILES:
            if bra_rel == known_file:
                _log(body_root, f"BLOCKED .bra/ schema ({known_file}): {rel_path}")
                return ("BRA_SCHEMA_BLOCKED", (
                    f"BLOCKED: Agent Write/Edit not allowed to .bra/{known_file}. "
                    "This file is managed by governance scripts. "
                    "Only .bra/artifacts/ is agent-writable."
                ))

        # Unknown path — not in schema, block
        _log(body_root, f"BLOCKED .bra/ unknown path: {rel_path}")
        return ("BRA_SCHEMA_BLOCKED", (
            f"BLOCKED: .bra/{bra_rel} is not in the .bra/ schema. "
            "Only declared paths are writable. Use .bra/artifacts/ for agent work products."
        ))

    return None


# ============== MAIN ==============

def main() -> int:
    body_root = _detect_body_root()
    payload = _extract_payload(sys.stdin.read())

    tool_name = ""
    if isinstance(payload.get("tool_name"), str):
        tool_name = payload["tool_name"]

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return _deny(
            "BLOCKED: Invalid file guard request - tool_input must be an object.",
            "INVALID_FILE_GUARD_REQUEST",
        )

    file_path = tool_input.get("file_path")
    if not isinstance(file_path, str) or not file_path.strip():
        file_path = ""

    # Block agent reads of protected .bra state files
    if tool_name in {"Read", "Grep", "Glob"}:
        bra_dir = body_root / ".bra"
        candidates = _extract_read_candidates(tool_name, tool_input)
        if not candidates:
            return _deny(
                f"BLOCKED: Invalid file guard request - tool {tool_name} is missing required path input.",
                "INVALID_FILE_GUARD_REQUEST",
            )
        for candidate in candidates:
            candidate_path = Path(candidate)
            candidate_posix = candidate_path.as_posix()
            if "/.bra/.claude/" in candidate_posix or candidate_posix.endswith("/.bra/.claude"):
                _log(body_root, f"BLOCKED read of .bra/.claude/: {candidate}")
                return _deny(
                    "BLOCKED: Agent read access to .bra/.claude/ is not permitted. "
                    "SDK session state may contain unmasked tool output. "
                    "Use .bra/artifacts/raw/ for captured evidence instead.",
                    "BRA_CLAUDE_STATE_READ_BLOCKED",
                )
            if candidate_posix.endswith("/.bra/anon_map.json") or (
                tool_name == "Glob"
                and "anon_map.json" in candidate_posix
                and any(
                    "/.bra/" in Path(base).as_posix() or Path(base).as_posix().endswith("/.bra")
                    for base in _extract_read_candidates("Grep", tool_input)
                )
            ):
                _log(body_root, f"BLOCKED read of .bra/anon_map.json: {candidate}")
                return _deny(
                    "BLOCKED: Agent access to .bra/anon_map.json is not permitted. "
                    "Anonymization mappings are operator-only governance state.",
                    "BRA_ANON_MAP_READ_BLOCKED",
                )
            try:
                resolved = _normalize_target(candidate, body_root)
                rel_path = _relative_policy_path(resolved, body_root)
                claude_dir = (bra_dir / ".claude").resolve(strict=False)
                if str(resolved).startswith(str(claude_dir)):
                    _log(body_root, f"BLOCKED read of .bra/.claude/: {rel_path}")
                    return _deny(
                        "BLOCKED: Agent read access to .bra/.claude/ is not permitted. "
                        "SDK session state may contain unmasked tool output. "
                        "Use .bra/artifacts/raw/ for captured evidence instead.",
                        "BRA_CLAUDE_STATE_READ_BLOCKED",
                    )
                anon_map = (bra_dir / "anon_map.json").resolve(strict=False)
                if resolved == anon_map:
                    _log(body_root, f"BLOCKED read of .bra/anon_map.json: {rel_path}")
                    return _deny(
                        "BLOCKED: Agent access to .bra/anon_map.json is not permitted. "
                        "Anonymization mappings are operator-only governance state.",
                        "BRA_ANON_MAP_READ_BLOCKED",
                    )
            except Exception:
                pass
        return _allow()

    if not file_path:
        return _deny(
            f"BLOCKED: Invalid file guard request - tool {tool_name or 'unknown'} is missing required field file_path.",
            "INVALID_FILE_GUARD_REQUEST",
        )

    target = _normalize_target(file_path, body_root)
    rel_path = _relative_policy_path(target, body_root)

    _log(body_root, f"Tool: {tool_name}, Path: {rel_path}")

    # For Write tool, capture content for append-only checks
    content: str | None = None
    if tool_name == "Write":
        raw = tool_input.get("content")
        if isinstance(raw, str):
            content = raw

    deny_result = _check_policy(tool_name, rel_path, target, content, body_root)
    if deny_result:
        policy, deny_reason = deny_result
        return _deny(deny_reason, policy)
    return _allow()


if __name__ == "__main__":
    raise SystemExit(main())
