#!/usr/bin/env python3
"""Native scope intake wizard/CLI for engagement setup.

Collects engagement scope details, validates CIDR notation, creates
approval tokens, and writes SCOPE.md with proper section structure.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path


TARGET_TYPES = (
    "android",
    "ios",
    "iot",
    "firmware",
    "thick-client",
    "dotnet",
    "bluetooth",
    "homekit",
    "auto-detect",
)

METHODOLOGY_MAP = {
    "android": "android-mobile-security",
    "ios": "ios-mobile-security",
    "iot": "iot-embedded-security",
    "firmware": "firmware-analysis",
    "thick-client": "thick-client-security",
    "dotnet": "dotnet-assessment",
    "bluetooth": "bluetooth-radio-security",
    "homekit": "hap-homekit-fuzzing",
    "selinux": "selinux-android-exploitation",
    "field": "field-intel",
}


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ============== INTERACTIVE HELPERS ==============

def _ask(prompt: str, default: str = "") -> str:
    """Collect input with optional default shown in brackets."""
    if default:
        result = input(f"  {prompt} [{default}]: ").strip()
        return result or default
    result = input(f"  {prompt}: ").strip()
    return result


def _ask_yn(prompt: str, default: str = "y") -> bool:
    """Yes/No question with default."""
    while True:
        result = input(f"  {prompt} (y/n) [{default}]: ").strip().lower()
        result = result or default
        if result in {"y", "yes"}:
            return True
        if result in {"n", "no"}:
            return False
        print("  Please answer y or n")


def _ask_multiline(prompt: str) -> str:
    """Multi-line input, returns bullet-prefixed lines. Blank line to finish."""
    print(f"  {prompt} (enter blank line to finish):")
    lines: list[str] = []
    while True:
        line = input("  > ").strip()
        if not line:
            break
        lines.append(f"- {line}")
    return "\n".join(lines)


def _print_header(title: str) -> None:
    print()
    print("═══════════════════════════════════════════════════════════════")
    print(f"  {title}")
    print("═══════════════════════════════════════════════════════════════")
    print()


def _print_question(title: str) -> None:
    print()
    print(f"  {title}")


def _print_info(text: str) -> None:
    print(f"    {text}")


# ============== CIDR VALIDATION ==============

def _check_cidr_host_bits(targets_text: str) -> list[tuple[str, str, str]]:
    """Return list of (original, network, host) for CIDRs with host bits set."""
    warnings: list[tuple[str, str, str]] = []
    for match in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", targets_text):
        cidr = match.group(1)
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                host = cidr.split("/")[0]
                warnings.append((cidr, str(net), host))
            except ValueError:
                pass
    return warnings


# ============== TOKEN CREATION ==============

def _create_token(body_root: Path, name: str, value: str = "true") -> Path:
    """Create an approval token file."""
    token_dir = body_root / ".bra" / "approvals"
    token_dir.mkdir(parents=True, exist_ok=True)
    token_file = token_dir / name
    token_file.write_text(f"{name}={value}\n", encoding="utf-8")
    return token_file


# ============== SCOPE DOCUMENT ==============

def _build_scope_doc(
    *,
    target_name: str,
    target_type: str,
    methodology: str,
    version: str,
    local_targets: str,
    network_targets: str,
    in_scope: str,
    out_scope: str,
    start_date: str,
    end_date: str,
    active_testing: str,
    slowpath_findings: str,
    notes: str,
) -> str:
    """Build SCOPE.md content matching V15 structure exactly."""
    now = _utc_now()

    return f"""\
# Engagement Scope

> **Generated:** {now}
> **Status:** ACTIVE

---

## Ethics & Authorization

**Authorization: Yes** - Operator solemnly confirmed authorization at {now}

I solemnly swear that I am authorized to perform any actions that may occur from this point forward: **Yes**

---

## Target Definition

**Name:** {target_name}
**Target Type:** {target_type}
**Methodology:** {methodology}
**Version:** {version}

### Local Targets (Static Analysis)

{local_targets}

### Network Targets (Active Testing)

{network_targets}

---

## In-Scope

{in_scope}

---

## Out-of-Scope

{out_scope}

---

## Time Window

- **Start:** {start_date}
- **End:** {end_date}

---

## Active Testing

ACTIVE-TESTING-APPROVAL: {active_testing}

| Setting | Meaning |
|---------|---------|
| YES | Network-based testing allowed |
| NO | Static analysis only |
| ASK | Prompt before network testing |

---

## Findings Pipeline

SLOWPATH-FINDINGS: {slowpath_findings}

| Setting | Meaning |
|---------|---------|
| YES | Script-first findings materialization with subagent narrative |
| NO | Default findings flow |

---

## Notes

{notes}

---

*Generated by scope-intake.py*
"""


def _safe_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", delete=False
    ) as tmp:
        tmp.write(content)
        temp_path = Path(tmp.name)
    temp_path.replace(path)


# ============== MAIN ==============

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect and write engagement scope details.")
    parser.add_argument("--output", default="layer3-engagement/SCOPE.md", help="Output path relative to body root")
    parser.add_argument("--non-interactive", action="store_true", help="Use argument/default values without prompts")
    parser.add_argument("--authorized", choices=("yes", "no"), default="yes", help="Authorization confirmation")
    parser.add_argument("--target-name", default="", help="Target name")
    parser.add_argument("--version", default="unknown", help="Target version/build")
    parser.add_argument("--local-target", action="append", default=[], help="Repeat for multiple local targets")
    parser.add_argument("--network-target", action="append", default=[], help="Repeat for multiple network targets")
    parser.add_argument("--in-scope", action="append", default=[], dest="in_scope", help="Repeat for multiple in-scope items")
    parser.add_argument("--out-of-scope", action="append", default=[], dest="out_of_scope", help="Repeat for multiple out-of-scope items")
    parser.add_argument("--start-date", default=str(date.today()), help="Engagement start date")
    parser.add_argument("--end-date", default="ongoing", help="Engagement end date")
    parser.add_argument("--active-testing", choices=("YES", "NO", "ASK"), default="ASK")
    parser.add_argument("--slowpath-findings", choices=("YES", "NO"), default="NO")
    parser.add_argument("--target-type", choices=TARGET_TYPES, default="auto-detect")
    parser.add_argument("--notes", default="None")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))

    # Defaults from args
    authorized = args.authorized == "yes"
    target_name = args.target_name
    version = args.version
    local_targets_text = "\n".join(f"- {t}" for t in args.local_target) if args.local_target else ""
    network_targets_text = "\n".join(f"- {t}" for t in args.network_target) if args.network_target else ""
    in_scope_text = "\n".join(f"- {t}" for t in args.in_scope) if args.in_scope else ""
    out_scope_text = "\n".join(f"- {t}" for t in args.out_of_scope) if args.out_of_scope else ""
    start_date = args.start_date
    end_date = args.end_date
    active_testing = args.active_testing
    slowpath_findings = args.slowpath_findings
    target_type = args.target_type
    notes = args.notes

    interactive = (not args.non_interactive) and sys.stdin.isatty()
    if interactive:
        _print_header("B.R.A. SCOPE INTAKE")
        print("  This wizard will collect engagement scope information.")
        print("  Press Enter to accept defaults shown in [brackets].")
        print()

        # 1. Authorization
        _print_question("1. AUTHORIZATION")
        print()
        print("  ┌─────────────────────────────────────────────────────────────┐")
        print("  │  Do you solemnly swear that you are authorized to perform  │")
        print("  │  any actions that may occur from this point forward?       │")
        print("  └─────────────────────────────────────────────────────────────┘")
        print()

        authorized = _ask_yn("I am authorized", "y")
        if not authorized:
            print()
            print("  Authorization not confirmed. Cannot proceed.")
            return 1
        print("  ✓ Authorization confirmed")

        # 2. Target Details
        _print_question("2. TARGET DETAILS")
        _print_info("Target type will be auto-detected during intelligence.")
        print()
        target_name = _ask("Target name", target_name)
        version = _ask("Version/Build (if known)", version or "unknown")

        # 3. Local Targets
        _print_question("3. LOCAL TARGETS (Static Analysis)")
        _print_info("Files, directories, firmware, binaries for static analysis")
        local_targets_text = _ask_multiline("Local paths")

        # 4. Network Targets
        _print_question("4. NETWORK TARGETS (Active Testing)")
        _print_info("IPs, URLs, domains, CIDRs, or IP:port combinations")
        network_targets_text = _ask_multiline("Network endpoints")

        # Check for CIDRs with host bits set
        if network_targets_text:
            cidr_warnings = _check_cidr_host_bits(network_targets_text)
            if cidr_warnings:
                print()
                print("  ⚠ CIDR notation check:")
                for orig, network, host in cidr_warnings:
                    print(f"    {orig} has host bits set.")
                    print(f"    Did you mean {network} (network) or {host} (specific host)?")
                print()
                cidr_ok = _ask_yn("Continue with values as entered?", "y")
                if not cidr_ok:
                    _print_info("Please re-enter network targets:")
                    network_targets_text = _ask_multiline("Network endpoints")

        # 5. In-Scope
        _print_question("5. IN-SCOPE")
        _print_info("What is allowed to be tested? (default: Everything)")
        in_scope_text = _ask_multiline("In-scope items")
        if not in_scope_text:
            in_scope_text = "- Everything"

        # 6. Out-of-Scope
        _print_question("6. OUT-OF-SCOPE")
        _print_info("What must NOT be tested? (default: Nothing)")
        out_scope_text = _ask_multiline("Out-of-scope items")
        if not out_scope_text:
            out_scope_text = "- Nothing"

        # 7. Time Window
        _print_question("7. TIME WINDOW")
        start_date = _ask("Start date", start_date or str(date.today()))
        end_date = _ask("End date", end_date or "ongoing")

        # 8. Active Testing
        _print_question("8. ACTIVE TESTING")
        _print_info("Active testing includes port scanning, fuzzing live targets,")
        _print_info("network exploitation, or any traffic to external hosts.")
        print()
        print("  Options:")
        print("    1. YES - Network-based testing allowed")
        print("    2. NO  - Static analysis only, no network activity")
        print("    3. ASK - Prompt before any network testing (default)")
        print()
        active_choice = input("  Select [3]: ").strip() or "3"
        if active_choice == "1":
            active_testing = "YES"
        elif active_choice == "2":
            active_testing = "NO"
        else:
            active_testing = "ASK"

        # 9. Findings Pipeline
        _print_question("9. FINDINGS PIPELINE")
        _print_info("Enable script-first findings slowpath to keep subagent focused on narrative sections.")
        print()
        print("  Options:")
        print("    1. YES - Enable SLOWPATH-FINDINGS token")
        print("    2. NO  - Keep default findings flow (default)")
        print()
        slowpath_choice = input("  Select [2]: ").strip() or "2"
        slowpath_findings = "YES" if slowpath_choice == "1" else "NO"

        # 10. Notes
        _print_question("10. ADDITIONAL NOTES")
        notes = _ask("Any other notes or constraints?", notes or "None")

        # 11. Target Type
        _print_question("11. TARGET TYPE")
        print("  What type of target is this?")
        print()
        type_labels = {
            "android": "Android APK/AAB",
            "ios": "iOS IPA",
            "iot": "IoT/embedded device",
            "firmware": "Firmware image",
            "thick-client": "Windows desktop app",
            "dotnet": ".NET assembly",
            "bluetooth": "Bluetooth/BLE device",
            "homekit": "HomeKit/HAP device",
            "auto-detect": "Unknown, discover during intel (default)",
        }
        for idx, tt in enumerate(TARGET_TYPES, 1):
            label = type_labels.get(tt, tt)
            print(f"    {idx:2d}. {tt:<14s} - {label}")
        print()
        type_choice = input(f"  Select [{len(TARGET_TYPES)}]: ").strip() or str(len(TARGET_TYPES))
        if type_choice.isdigit():
            idx_val = int(type_choice)
            if 1 <= idx_val <= len(TARGET_TYPES):
                target_type = TARGET_TYPES[idx_val - 1]
            else:
                target_type = "auto-detect"
        elif type_choice in TARGET_TYPES:
            target_type = type_choice
        else:
            target_type = "auto-detect"
        if target_type == "auto-detect":
            target_type = "pending-intel"

    else:
        # Non-interactive mode
        if not authorized:
            print("Authorization not confirmed. Cannot proceed.", file=sys.stderr)
            return 1
        if target_type == "auto-detect":
            target_type = "pending-intel"

    # Resolve methodology
    methodology_name = METHODOLOGY_MAP.get(target_type, "auto-detect")
    methodology = methodology_name
    if target_type not in ("auto-detect", "pending-intel"):
        meth_file = body_root / "layer2-templates" / "methodologies" / f"{methodology_name}.md"
        if meth_file.is_file():
            print(f"  ✓ Methodology: {methodology_name}.md")
        else:
            print(f"  ⚠ Methodology file not found: {methodology_name}.md")
            _print_info("Falling back to auto-detect mode")
            target_type = "pending-intel"
            methodology = "auto-detect"

    # Handle empty fields
    if not local_targets_text.strip():
        local_targets_text = "- None specified"
    if not network_targets_text.strip():
        network_targets_text = "- None specified"
    if not in_scope_text.strip():
        in_scope_text = "- Everything"
    if not out_scope_text.strip():
        out_scope_text = "- Nothing"

    # Generate SCOPE.md
    if interactive:
        _print_header("GENERATING SCOPE")

    output_path = Path(args.output).expanduser()
    if not output_path.is_absolute():
        output_path = body_root / output_path

    content = _build_scope_doc(
        target_name=target_name,
        target_type=target_type,
        methodology=methodology,
        version=version,
        local_targets=local_targets_text,
        network_targets=network_targets_text,
        in_scope=in_scope_text,
        out_scope=out_scope_text,
        start_date=start_date,
        end_date=end_date,
        active_testing=active_testing,
        slowpath_findings=slowpath_findings,
        notes=notes,
    )
    _safe_write_text(output_path, content)

    # Create tokens
    if active_testing == "YES":
        _create_token(body_root, "ACTIVE-TESTING-APPROVAL")
        print("  ✓ ACTIVE-TESTING-APPROVAL token set")
    if slowpath_findings == "YES":
        _create_token(body_root, "SLOWPATH-FINDINGS")
        print("  ✓ SLOWPATH-FINDINGS token set")

    # Create SCOPE-CONFIRMED token
    _create_token(body_root, "SCOPE-CONFIRMED")

    print(f"  ✓ Scope saved to: {args.output}")
    print()
    print("  Scope intake complete.")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
