#!/usr/bin/env python3
"""offensive_gate.py - Native offensive testing approval gate."""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / ".bra" / "logs"
LOG_FILE = LOG_DIR / "offensive_gate.log"
PITCHES_DIR = PROJECT_ROOT / "layer3-engagement" / "pitches"
APPROVAL_FILE = PROJECT_ROOT / ".bra" / "approvals" / "ACTIVE-TESTING-APPROVAL"
SCOPE_FILE = PROJECT_ROOT / "layer3-engagement" / "SCOPE.md"
ROE_FILE = PROJECT_ROOT / "layer3-engagement" / "ROE.md"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)


def log(level: str, message: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        return


def show_help() -> None:
    print("""\
offensive_gate.py — Offensive Testing Approval Gate

USAGE:
    offensive_gate.py --check                    Check if offensive testing allowed
    offensive_gate.py --request TYPE TARGET      Request approval for activity
    offensive_gate.py --set                      Set approval token
    offensive_gate.py --unset                    Remove approval token
    offensive_gate.py --scope-status             Show scope intake setting
    offensive_gate.py --list-patterns            List offensive activity patterns
    offensive_gate.py --help                     Show this help

OPTIONS:
    --check
        Check if ACTIVE-TESTING-APPROVAL token is set.
        Exit 0 if set (proceed), Exit 1 if not (blocked).

    --request TYPE TARGET [--description DESC]
        Request approval for an offensive activity.
        TYPE: fuzzing, exploitation, firmware-modification, active-scanning
        TARGET: Target identifier (URL, device, service)
        If scope is PROMPT and token not set, generates pitch document.

    --set
        Set the ACTIVE-TESTING-APPROVAL token.
        Creates .bra/approvals/ACTIVE-TESTING-APPROVAL

    --unset
        Remove the ACTIVE-TESTING-APPROVAL token.

    --scope-status
        Show the scope intake setting for offensive testing:
        APPROVED - Pre-authorized for engagement
        DENIED   - Not permitted for engagement
        PROMPT   - Require per-activity approval

    --list-patterns
        List all patterns that trigger offensive activity detection.

EXIT CODES:
    0 - Approved: Offensive testing is permitted
    1 - Blocked: Offensive testing not permitted (token not set or DENIED)
    2 - Pitch Generated: Approval pitch created, awaiting decision

EXAMPLES:
    # Check before offensive activity
    if ./layer1/scripts/offensive_gate.py --check; then
        echo "Proceeding with offensive testing..."
    else
        ./layer1/scripts/offensive_gate.py --request "fuzzing" "api.target.com"
    fi

    # Request approval for fuzzing
    ./layer1/scripts/offensive_gate.py --request "fuzzing" "api.example.com" \\
        --description "HTTP parameter fuzzing for injection vulnerabilities"

    # Set token after manual approval
    ./layer1/scripts/offensive_gate.py --set

TOKEN SOURCES (checked in order):
    1. Environment variable: ACTIVE_TESTING_APPROVAL=1
    2. Approval file: .bra/approvals/ACTIVE-TESTING-APPROVAL
    3. ROE.md token table: "ACTIVE-TESTING-APPROVAL | Set"

SCOPE INTAKE WORKFLOW:
    During scope intake, offensive testing authorization is captured:

    | Option   | Behavior                                      |
    |----------|-----------------------------------------------|
    | APPROVED | Token set automatically; no pitch needed      |
    | DENIED   | Token cannot be set; offensive testing blocked|
    | PROMPT   | Generate pitch for each activity (default)    |

RELATED:
    - tokens.md: Token catalog and policy
    - roe.md: Rules of engagement
    - scope-intake.md: Scope intake template
    - layer2-templates/offensive-testing-pitch.md: Pitch template
""")


def get_active_scope_setting() -> str:
    if not SCOPE_FILE.is_file():
        return "PROMPT"
    try:
        text = SCOPE_FILE.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "PROMPT"

    match = re.search(r"ACTIVE[-_ ]TESTING[-_ ]APPROVAL\s*:\s*([A-Za-z_-]+)", text, flags=re.IGNORECASE)
    if not match:
        return "PROMPT"

    value = match.group(1).strip().upper()
    if value in {"APPROVED", "ALLOW", "ALLOWED", "GRANTED", "YES", "TRUE", "1", "SET"}:
        return "APPROVED"
    if value in {"DENIED", "DENY", "NO", "FALSE", "0", "BLOCKED"}:
        return "DENIED"
    return "PROMPT"


def check_active_approval() -> bool:
    if os.environ.get("ACTIVE_TESTING_APPROVAL") == "1":
        return True
    if APPROVAL_FILE.is_file():
        return True
    if ROE_FILE.is_file():
        try:
            content = ROE_FILE.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""
        if re.search(r"ACTIVE-TESTING-APPROVAL.*\bSET\b", content, flags=re.IGNORECASE):
            return True
    return False


def set_active_approval() -> None:
    APPROVAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    APPROVAL_FILE.touch(exist_ok=True)


def unset_active_approval() -> None:
    try:
        APPROVAL_FILE.unlink()
    except FileNotFoundError:
        return


def get_engagement_name() -> str:
    if not SCOPE_FILE.is_file():
        return "Unknown Engagement"
    try:
        text = SCOPE_FILE.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "Unknown Engagement"

    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip() or "Unknown Engagement"
        if "Engagement Name" in line:
            _, _, rhs = line.partition(":")
            name = rhs.strip()
            if name:
                return name
    return "Unknown Engagement"


def _check_killswitch() -> bool:
    """Check kill switch. Returns True if active."""
    lib_dir = str(PROJECT_ROOT / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    try:
        import killswitch
        return killswitch.is_killswitch_active(PROJECT_ROOT)
    except (ImportError, Exception):
        return False


def _list_offensive_patterns() -> int:
    """List patterns that trigger offensive activity detection."""
    lib_dir = str(PROJECT_ROOT / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    try:
        import active_check
        if hasattr(active_check, "list_network_patterns"):
            active_check.list_network_patterns()
            return 0
    except ImportError:
        pass

    # Fallback: list known patterns inline
    patterns = [
        ("Network scanning", "nmap, masscan, zmap"),
        ("Vulnerability scanning", "nikto, nuclei, sqlmap, wfuzz"),
        ("Fuzzing", "boofuzz, afl, honggfuzz, radamsa"),
        ("Exploitation", "metasploit, exploit-db, searchsploit"),
        ("Active probing", "curl POST/PUT, wget --post-data"),
        ("Brute force", "hydra, medusa, hashcat"),
    ]
    print("Offensive Activity Patterns")
    print("===========================\n")
    print("| Category | Tool Examples |")
    print("|----------|---------------|")
    for cat, tools in patterns:
        print(f"| {cat} | {tools} |")
    return 0


def generate_pitch(activity_type: str, target: str, description: str) -> Path:
    PITCHES_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    date_slug = now.strftime("%Y%m%d-%H%M%S")
    pitch_file = PITCHES_DIR / f"offensive-testing-pitch-{date_slug}.md"

    if not description:
        description = "No description provided"

    content = "\n".join([
        "# Offensive Testing Approval Request",
        "",
        f"**Generated:** {timestamp}",
        f"**Engagement:** {get_engagement_name()}",
        "**Status:** PENDING APPROVAL",
        "",
        "---",
        "",
        "## Activity Requested",
        "",
        f"**Type:** {activity_type}",
        f"**Description:** {description}",
        f"**Target:** {target}",
        "",
        "### Activity Categories",
        "",
        "| Category | Examples |",
        "|----------|----------|",
        "| Fuzzing | Protocol fuzzing, API fuzzing, input mutation |",
        "| Exploitation | Vulnerability exploitation, PoC execution |",
        "| Firmware Modification | Flash operations, bootloader modification, image injection |",
        "| Active Scanning | Port scanning, service enumeration, vulnerability scanning |",
        "",
        "---",
        "",
        "## Risk Assessment",
        "",
        "| Factor | Assessment | Details |",
        "|--------|------------|---------|",
        "| Target Impact | TBD | Operator to assess |",
        "| Reversibility | TBD | Operator to assess |",
        "| Detection Risk | TBD | Operator to assess |",
        "| Data Loss Risk | TBD | Operator to assess |",
        "",
        "---",
        "",
        "## Justification",
        "",
        description,
        "",
        "### Required Justification Elements",
        "",
        "- [ ] Why is this activity necessary for the engagement objectives?",
        "- [ ] What security findings does this activity aim to discover?",
        "- [ ] Have non-offensive alternatives been considered and ruled out?",
        "- [ ] What is the expected outcome if successful?",
        "",
        "---",
        "",
        "## Scope Verification",
        "",
        "- [ ] Activity is within authorized scope (SCOPE.md)",
        "- [ ] Target is in-scope (PLAN.md)",
        "- [ ] Time window is valid (ROE.md)",
        "- [ ] Required tools are approved (TOOLSUITES.md)",
        "- [ ] No conflicting exclusions exist",
        "",
        "---",
        "",
        "## Approval",
        "",
        "| Decision | Approver | Date | Notes |",
        "|----------|----------|------|-------|",
        "| PENDING | | | |",
        "",
        "### To Approve",
        "",
        "```bash",
        "# Option 1: Create approval marker",
        "touch .bra/approvals/ACTIVE-TESTING-APPROVAL",
        "",
        "# Option 2: Set environment variable",
        "export ACTIVE_TESTING_APPROVAL=1",
        "",
        "# Option 3: Run the gate script",
        "./layer1/scripts/offensive_gate.py --set",
        "```",
        "",
        "### To Deny",
        "",
        'Edit this file and change status to "DENIED" with reason.',
        "",
        "---",
        "",
        "## Notes",
        "",
        f"Activity requested at {timestamp}.",
        "Pitch generated by offensive_gate.py.",
        "",
    ])
    pitch_file.write_text(content, encoding="utf-8")
    return pitch_file


def do_check() -> int:
    scope_setting = get_active_scope_setting()
    if scope_setting == "DENIED":
        log("BLOCKED", "Offensive testing DENIED by scope intake")
        print("")
        print("Scope intake setting: DENIED")
        print("Offensive testing is not permitted for this engagement.")
        return 1
    if scope_setting == "APPROVED":
        if not check_active_approval():
            log("INFO", "Scope is APPROVED, setting token...")
            set_active_approval()
        log("APPROVED", "Offensive testing permitted (scope: APPROVED)")
        return 0

    # PROMPT mode
    if check_active_approval():
        log("APPROVED", "Offensive testing permitted (token set)")
        return 0
    log("BLOCKED", "Offensive testing not approved (token not set)")
    print("")
    print("Scope intake setting: PROMPT")
    print("ACTIVE-TESTING-APPROVAL token not set.")
    print("")
    print("To request approval:")
    print("  ./layer1/scripts/offensive_gate.py --request <type> <target>")
    print("")
    print("To set token directly:")
    print("  ./layer1/scripts/offensive_gate.py --set")
    print("  # or")
    print("  touch .bra/approvals/ACTIVE-TESTING-APPROVAL")
    return 1


def do_request(activity_type: str, target: str, description: str) -> int:
    scope_setting = get_active_scope_setting()
    if scope_setting == "DENIED":
        log("BLOCKED", "Cannot request approval: offensive testing DENIED by scope")
        return 1
    if scope_setting == "APPROVED":
        if not check_active_approval():
            set_active_approval()
        log("APPROVED", "Offensive testing pre-approved by scope")
        return 0
    if check_active_approval():
        log("APPROVED", "Offensive testing already approved (token set)")
        return 0

    pitch_file = generate_pitch(activity_type, target, description)
    log("PENDING", f"Approval pitch generated: {pitch_file}")
    print("")
    print("═══════════════════════════════════════════════════════════════")
    print("OFFENSIVE TESTING APPROVAL REQUIRED")
    print("═══════════════════════════════════════════════════════════════")
    print("")
    print(f"Activity Type: {activity_type}")
    print(f"Target: {target}")
    print(f"Description: {description or 'No description provided'}")
    print("")
    print(f"Pitch document: {pitch_file}")
    print("")
    print("───────────────────────────────────────────────────────────────")
    print("")
    print("To approve this request:")
    print("")
    print("  1. Review the pitch document")
    print("  2. Run: ./layer1/scripts/offensive_gate.py --set")
    print("     or:  touch .bra/approvals/ACTIVE-TESTING-APPROVAL")
    print("")
    print("To deny: Edit the pitch document and set status to DENIED")
    print("")
    print("═══════════════════════════════════════════════════════════════")
    return 2


def do_set() -> int:
    if get_active_scope_setting() == "DENIED":
        print("[ERROR] Cannot set token: offensive testing DENIED by scope intake")
        log("ERROR", "Cannot set token: offensive testing DENIED by scope intake")
        return 1
    set_active_approval()
    print("[APPROVED] ACTIVE-TESTING-APPROVAL token set")
    log("APPROVED", "ACTIVE-TESTING-APPROVAL token set")
    return 0


def do_unset() -> int:
    unset_active_approval()
    print("[INFO] ACTIVE-TESTING-APPROVAL token removed")
    log("INFO", "ACTIVE-TESTING-APPROVAL token removed")
    return 0


def do_scope_status() -> int:
    setting = get_active_scope_setting()
    print("Offensive Testing Scope Status")
    print("===============================")
    print("")
    print(f"Scope intake setting: {setting}")
    print("")

    if setting == "APPROVED":
        print("Offensive testing is PRE-APPROVED for this engagement.")
        print("Token will be set automatically when offensive activities are requested.")
    elif setting == "DENIED":
        print("Offensive testing is DENIED for this engagement.")
        print("No offensive testing activities are permitted.")
    elif setting == "PROMPT":
        print("Offensive testing requires APPROVAL per activity.")
        print("A pitch document will be generated for each request.")

    print("")
    print("Token status:")
    if check_active_approval():
        print("  ACTIVE-TESTING-APPROVAL: SET")
    else:
        print("  ACTIVE-TESTING-APPROVAL: NOT SET")
    return 0


def list_patterns() -> int:
    return _list_offensive_patterns()


def parse_args(args: list[str]) -> tuple[int | None, str, str, str, str]:
    action = ""
    activity_type = ""
    target = ""
    description = ""

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in {"--help", "-h"}:
            show_help()
            return 0, "", "", "", ""
        if arg == "--check":
            action = "check"
            idx += 1
            continue
        if arg == "--request":
            action = "request"
            if idx + 2 >= len(args):
                log("ERROR", "Usage: --request TYPE TARGET [--description DESC]")
                return 1, "", "", "", ""
            activity_type = args[idx + 1]
            target = args[idx + 2]
            idx += 3
            continue
        if arg == "--description":
            if idx + 1 < len(args):
                description = args[idx + 1]
                idx += 2
                continue
            idx += 1
            continue
        if arg == "--set":
            action = "set"
            idx += 1
            continue
        if arg == "--unset":
            action = "unset"
            idx += 1
            continue
        if arg == "--scope-status":
            action = "scope-status"
            idx += 1
            continue
        if arg == "--list-patterns":
            action = "list-patterns"
            idx += 1
            continue
        log("ERROR", f"Unknown option: {arg}")
        return 1, "", "", "", ""

    if not action:
        show_help()
        return 0, "", "", "", ""
    return None, action, activity_type, target, description


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    init_logging()

    # Kill switch check before any operations
    if _check_killswitch():
        print("Kill switch is ACTIVE. All operations halted.", file=sys.stderr)
        return 99

    parsed_exit, action, activity_type, target, description = parse_args(args)
    if parsed_exit is not None:
        return parsed_exit

    if action == "check":
        return do_check()
    if action == "request":
        return do_request(activity_type, target, description)
    if action == "set":
        return do_set()
    if action == "unset":
        return do_unset()
    if action == "scope-status":
        return do_scope_status()
    if action == "list-patterns":
        return list_patterns()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
