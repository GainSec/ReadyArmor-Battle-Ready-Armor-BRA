#!/usr/bin/env python3
"""Engagement scope readiness validation helpers."""

from __future__ import annotations

import re
import sys
from pathlib import Path

SCOPE_VALID = False
SCOPE_STATUS = "UNKNOWN"
SCOPE_ERRORS: list[str] = []
SCOPE_WARNINGS: list[str] = []


def _detect_body_root() -> Path:
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if (parent / "layer1").is_dir() and (parent / "layer3-engagement").is_dir():
            return parent
    return cwd


def _scope_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "SCOPE.md"


def _roe_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "ROE.md"


def _plan_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "PLAN.md"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def check_ethics_confirmation(body_root: Path | None = None) -> bool:
    """Return whether ethics/authorization confirmation is present."""
    text = _read(_scope_file(body_root))
    if not text:
        return False
    patterns = (
        r"authorization.*yes",
        r"authorized.*yes",
        r"ethics.*confirmed",
        r"solemnly.*swear.*yes",
        r"confirmation.*yes",
        r"\*\*Authorization:\*\*\s*(?!_TBD_|Not specified|None).+",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def check_target_defined(body_root: Path | None = None) -> bool:
    """Return whether at least one realistic target appears in scope."""
    text = _read(_scope_file(body_root))
    if not text:
        return False

    if re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", text):
        return True
    if re.search(r"https?://", text, re.IGNORECASE):
        return True

    domains = re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b", text)
    if any(not domain.lower().endswith((".md", ".sh", ".txt", ".json", ".yaml", ".yml")) for domain in domains):
        return True

    if re.search(r"^##\s+(Primary\s+)?Target", text, re.MULTILINE):
        target_line = re.search(r"\*\*Name:\*\*\s*(.+)", text)
        if target_line and "_TBD_" not in target_line.group(1):
            return True

    if re.search(r"^##\s+Target|^##\s+In-Scope", text, re.MULTILINE) and not re.search(
        r"_TBD_|Populate from|Not specified",
        text,
        re.IGNORECASE,
    ):
        target_section = re.search(
            r"^##\s+(?:Primary\s+)?Target.*?(?=^##\s|\Z)|^##\s+In-Scope.*?(?=^##\s|\Z)",
            text,
            re.IGNORECASE | re.MULTILINE | re.DOTALL,
        )
        if target_section and re.search(r"^[ \t]*[-*].*[A-Za-z0-9]", target_section.group(0), re.MULTILINE):
            return True

    return False


def check_out_of_scope(body_root: Path | None = None) -> bool:
    """Return whether scope contains out-of-scope/exclusions section."""
    text = _read(_scope_file(body_root))
    if not text:
        return False

    section_match = re.search(r"^##\s*(Out[- ]of[- ]Scope|Exclusions).*?(?=\n##\s|\Z)", text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    if not section_match:
        return False
    section = section_match.group(0)
    return bool(re.search(r"(^\s*[-*]\s+.+)|\bNone\b", section, re.MULTILINE))


def check_active_testing_set(body_root: Path | None = None) -> bool:
    """Return whether ACTIVE-TESTING-APPROVAL is explicitly declared."""
    text = _read(_scope_file(body_root)) + "\n" + _read(_roe_file(body_root))
    return bool(re.search(r"ACTIVE-TESTING-APPROVAL\s*[:|]\s*(YES|NO|ASK|APPROVED|DENIED|PROMPT)", text, re.IGNORECASE))


def check_offensive_testing_set(body_root: Path | None = None) -> bool:
    """Legacy alias for active-testing check."""
    return check_active_testing_set(body_root)


def get_active_testing_value(body_root: Path | None = None) -> str:
    """Return configured ACTIVE-TESTING-APPROVAL value."""
    text = _read(_scope_file(body_root)) + "\n" + _read(_roe_file(body_root))
    match = re.search(r"ACTIVE-TESTING-APPROVAL\s*[:|]\s*(YES|NO|ASK|APPROVED|DENIED|PROMPT)", text, re.IGNORECASE)
    return match.group(1).upper() if match else "NOT SET"


def get_offensive_testing_value(body_root: Path | None = None) -> str:
    """Legacy alias for active-testing value."""
    return get_active_testing_value(body_root)


def check_time_window(body_root: Path | None = None) -> bool:
    """Return whether scope includes start/end timing info."""
    text = _read(_scope_file(body_root))
    if not text:
        return False
    if len(re.findall(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text)) >= 2:
        return True

    section_match = re.search(r"^##\s*(Time\s+Window|Timeline|Schedule).*?(?=\n##\s|\Z)", text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    if not section_match:
        return False
    section = section_match.group(0)
    return bool(re.search(r"(Start|End|Begin|Finish)", section, re.IGNORECASE) and "_TBD_" not in section)


def check_not_skeleton(body_root: Path | None = None) -> bool:
    """Return ``True`` when scope file looks populated, not a placeholder."""
    scope = _scope_file(body_root)
    if not scope.is_file():
        return False
    text = _read(scope)
    if re.search(r"_TBD_|Populate from scope-intake|Populate during scope intake", text, re.IGNORECASE):
        return False
    return len(text.splitlines()) >= 10


def check_roe_token_table(body_root: Path | None = None) -> bool:
    """Return whether ROE contains token-status table/section."""
    text = _read(_roe_file(body_root))
    if not text:
        return False
    if re.search(r"^\|.*Token.*\|.*Status.*\|", text, re.IGNORECASE | re.MULTILINE):
        return True
    if re.search(r"^##\s*(Active\s+)?Tokens?", text, re.IGNORECASE | re.MULTILINE) and "_TBD_" not in text:
        return True
    return False


def check_roe_populated(body_root: Path | None = None) -> bool:
    """Return whether ROE exists and is not template skeleton."""
    roe = _roe_file(body_root)
    if not roe.is_file():
        return False
    text = _read(roe)
    if re.search(r"_TBD_|Populate from scope-intake|Populate during scope", text, re.IGNORECASE):
        return False
    return len(text.splitlines()) >= 10


def check_plan_phases(body_root: Path | None = None) -> bool:
    """Return whether PLAN.md defines phases."""
    text = _read(_plan_file(body_root))
    if not text:
        return False
    return bool(re.search(r"##\s*Phase|##\s*Intel|##\s*Static|##\s*Dynamic|##\s*Report|1\.\s*Intel", text, re.IGNORECASE))


def check_plan_targets(body_root: Path | None = None) -> bool:
    """Return whether PLAN.md includes target section/content."""
    text = _read(_plan_file(body_root))
    if not text:
        return False
    if not re.search(r"##\s*(In-Scope\s+)?Targets?|Target:|In-Scope:", text, re.IGNORECASE):
        return False
    return not bool(re.search(r"_TBD_|Populate", text, re.IGNORECASE))


def check_plan_populated(body_root: Path | None = None) -> bool:
    """Return whether PLAN.md is populated and non-template."""
    plan = _plan_file(body_root)
    if not plan.is_file():
        return False
    text = _read(plan)
    if re.search(r"Populate during planning|_TBD_", text, re.IGNORECASE):
        return False
    return len(text.splitlines()) >= 15


def get_scope_status(body_root: Path | None = None) -> str:
    """Return high-level scope readiness state."""
    scope = _scope_file(body_root)
    if not scope.is_file():
        return "MISSING"
    if not check_not_skeleton(body_root):
        return "SKELETON"

    checks = [
        check_ethics_confirmation(body_root),
        check_target_defined(body_root),
        check_out_of_scope(body_root),
        check_offensive_testing_set(body_root),
        check_time_window(body_root),
    ]
    if all(checks):
        return "COMPLETE"
    if any(checks):
        return "PARTIAL"
    return "SKELETON"


def validate_scope(body_root: Path | None = None, report: bool = False) -> bool:
    """Validate required scope fields and populate module-level status variables."""
    global SCOPE_VALID, SCOPE_STATUS, SCOPE_ERRORS, SCOPE_WARNINGS

    SCOPE_VALID = False
    SCOPE_STATUS = "UNKNOWN"
    SCOPE_ERRORS = []
    SCOPE_WARNINGS = []

    scope = _scope_file(body_root)
    root = _detect_body_root() if body_root is None else body_root
    if not scope.is_file():
        SCOPE_STATUS = "MISSING"
        SCOPE_ERRORS.append(f"SCOPE.md file does not exist at {scope}")
        root_scope = root / "layer1" / "rules" / "scope.md"
        if root_scope.is_file():
            SCOPE_WARNINGS.append("Root scope.md exists - consider running /scope-intake to instantiate")
        if report:
            print_validation_report()
        return False

    if not check_not_skeleton(body_root):
        SCOPE_STATUS = "SKELETON"
        SCOPE_ERRORS.append("SCOPE.md is still a skeleton/template - run /scope-intake to populate")
        if report:
            print_validation_report()
        return False

    required_checks: list[tuple[str, bool]] = [
        ("Missing: Ethics confirmation (authorization statement)", check_ethics_confirmation(body_root)),
        ("Missing: Target definition (at least one IP, domain, URL, or app name)", check_target_defined(body_root)),
        ("Missing: Out-of-scope section", check_out_of_scope(body_root)),
        ("Missing: ACTIVE-TESTING-APPROVAL setting (YES/NO/ASK)", check_active_testing_set(body_root)),
        ("Missing: Time window (start and end dates)", check_time_window(body_root)),
    ]

    for message, passed in required_checks:
        if not passed:
            SCOPE_ERRORS.append(message)

    if not _roe_file(body_root).is_file():
        SCOPE_WARNINGS.append("ROE.md does not exist")
    elif not check_roe_populated(body_root):
        SCOPE_WARNINGS.append("ROE.md is still a skeleton")
    elif not check_roe_token_table(body_root):
        SCOPE_WARNINGS.append("ROE.md missing token table")

    if not _plan_file(body_root).is_file():
        SCOPE_WARNINGS.append("PLAN.md does not exist")
    elif not check_plan_populated(body_root):
        SCOPE_WARNINGS.append("PLAN.md is still a skeleton")
    elif not check_plan_phases(body_root):
        SCOPE_WARNINGS.append("PLAN.md missing phase definitions")
    elif not check_plan_targets(body_root):
        SCOPE_WARNINGS.append("PLAN.md missing target information")

    SCOPE_VALID = len(SCOPE_ERRORS) == 0
    SCOPE_STATUS = get_scope_status(body_root)

    if report:
        print_validation_report()
    return SCOPE_VALID


def print_validation_report(body_root: Path | None = None) -> str:
    """Build and print current validation report matching V15 boxed format."""
    lines: list[str] = []
    lines.append("")
    lines.append("═══════════════════════════════════════════════════════════════")
    lines.append("                    SCOPE VALIDATION REPORT")
    lines.append("═══════════════════════════════════════════════════════════════")
    lines.append("")
    lines.append(f"Status: {SCOPE_STATUS}")
    lines.append("")

    # Required Fields checklist
    lines.append("Required Fields:")
    lines.append("────────────────")

    ethics = check_ethics_confirmation(body_root)
    lines.append(f"  [✓] Ethics confirmation" if ethics else "  [✗] Ethics confirmation")

    target = check_target_defined(body_root)
    lines.append(f"  [✓] Target defined" if target else "  [✗] Target defined")

    oos = check_out_of_scope(body_root)
    lines.append(f"  [✓] Out-of-scope section" if oos else "  [✗] Out-of-scope section")

    active = check_active_testing_set(body_root)
    if active:
        lines.append(f"  [✓] ACTIVE-TESTING-APPROVAL: {get_active_testing_value(body_root)}")
    else:
        lines.append("  [✗] ACTIVE-TESTING-APPROVAL")

    tw = check_time_window(body_root)
    lines.append(f"  [✓] Time window" if tw else "  [✗] Time window")

    lines.append("")

    # Related Documents
    lines.append("Related Documents:")
    lines.append("──────────────────")

    roe = _roe_file(body_root)
    if roe.is_file():
        if check_roe_populated(body_root):
            if check_roe_token_table(body_root):
                lines.append("  [✓] ROE.md (populated with token table)")
            else:
                lines.append("  [~] ROE.md (populated, missing token table)")
        else:
            lines.append("  [~] ROE.md (skeleton)")
    else:
        lines.append("  [ ] ROE.md (not created)")

    plan = _plan_file(body_root)
    if plan.is_file():
        if check_plan_populated(body_root):
            if check_plan_phases(body_root):
                lines.append("  [✓] PLAN.md (populated with phases)")
            else:
                lines.append("  [~] PLAN.md (populated, missing phases)")
        else:
            lines.append("  [~] PLAN.md (skeleton)")
    else:
        lines.append("  [ ] PLAN.md (not created)")

    lines.append("")

    # Errors
    if SCOPE_ERRORS:
        lines.append("Errors:")
        lines.append("───────")
        for error in SCOPE_ERRORS:
            lines.append(f"  ✗ {error}")
        lines.append("")

    # Warnings
    if SCOPE_WARNINGS:
        lines.append("Warnings:")
        lines.append("─────────")
        for warning in SCOPE_WARNINGS:
            lines.append(f"  ⚠ {warning}")
        lines.append("")

    # Result
    if SCOPE_VALID:
        lines.append("Result: ✓ SCOPE VALID — Ready for engagement")
    else:
        lines.append("Result: ✗ SCOPE INCOMPLETE — Run /scope-intake to complete")

    lines.append("")
    lines.append("═══════════════════════════════════════════════════════════════")

    report = "\n".join(lines)
    print(report)
    return report


def scope_is_ready(body_root: Path | None = None) -> bool:
    """Return whether scope passes required checks."""
    scope = _scope_file(body_root)
    return scope.is_file() and check_not_skeleton(body_root) and check_ethics_confirmation(body_root) and check_target_defined(body_root)


def require_scope(body_root: Path | None = None) -> bool:
    """Print shell-style error block and return readiness."""
    if scope_is_ready(body_root):
        return True
    error_block = "\n".join([
        "",
        "═══════════════════════════════════════════════════════════════",
        "  ERROR: Scope not defined",
        "═══════════════════════════════════════════════════════════════",
        "",
        "  The engagement scope has not been properly defined.",
        "",
        "  To define scope, run:",
        "    /scope-intake",
        "",
        "  Or validate existing scope:",
        "    /scope-intake --validate-only",
        "",
        "  The pipeline cannot proceed without a valid scope.",
        "",
        "═══════════════════════════════════════════════════════════════",
    ])
    print(error_block)
    return False


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    report = "--report" in args
    is_valid = validate_scope(report=report)
    if not report:
        print(get_scope_status())
    return 0 if is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
