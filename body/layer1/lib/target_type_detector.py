#!/usr/bin/env python3
"""Target-type detection and methodology mapping utilities."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_TARGET_TYPE_MAP: dict[str, str] = {
    "android": "android-mobile-security.md",
    "iot": "iot-embedded-security.md",
    "embedded": "iot-embedded-security.md",
    "bluetooth": "bluetooth-radio-security.md",
    "ble": "bluetooth-radio-security.md",
    "thick-client": "thick-client-security.md",
    "thick_client": "thick-client-security.md",
    "desktop": "thick-client-security.md",
    "dotnet": "dotnet-assessment.md",
    ".net": "dotnet-assessment.md",
    "selinux": "selinux-android-exploitation.md",
    "sepolicy": "selinux-android-exploitation.md",
    "homekit": "hap-homekit-fuzzing.md",
    "hap": "hap-homekit-fuzzing.md",
    "field": "field-intel.md",
    "field-intel": "field-intel.md",
}


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


def _ttd_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "ci.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [TARGET-TYPE] {message}\n")
    except OSError:
        pass


def _scope_file(body_root: Path | None = None) -> Path | None:
    root = _detect_body_root() if body_root is None else body_root
    candidates = [root / "layer3-engagement" / "SCOPE.md", root / "layer1" / "rules" / "scope.md"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_scope_content(body_root: Path | None = None) -> str:
    scope = _scope_file(body_root)
    if scope is None:
        return ""
    try:
        return scope.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def detect_target_type(body_root: Path | None = None) -> str:
    """Detect target type from scope markers and content heuristics."""
    text = _load_scope_content(body_root)
    if not text:
        _ttd_log("No scope file found", body_root)
        return "unknown"

    explicit_match = re.search(r"(?:^|\*\*)Target\s*Type:\*?\*?\s*([A-Za-z0-9_-]+)", text, re.IGNORECASE | re.MULTILINE)
    explicit_type = explicit_match.group(1).strip().lower() if explicit_match else ""

    if explicit_type in {"pending-intel", "auto-detect"}:
        _ttd_log(f"Target type pending intel: {explicit_type}", body_root)
        return explicit_type
    if explicit_type and explicit_type not in {"app", "other"}:
        _ttd_log(f"Explicit target type: {explicit_type}", body_root)
        return explicit_type

    checks: list[tuple[str, str]] = [
        ("android", r"\.apk|\.aab|\badb\b|package\s+android|com\.[a-z0-9_]+\.[a-z0-9_]+"),
        ("ios", r"\.ipa|\bidevice\b|\bxcode\b|\.app\s*bundle"),
        ("bluetooth", r"\bbluetooth\b|\bBLE\b|\bhci[0-9]+\b|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
        ("homekit", r"\bhomekit\b|\bHAP\b|home\s+automation|pairing\s+setup"),
        ("iot", r"\bMQTT\b|\bONVIF\b|\bcamera\b|\bIoT\b|\bembedded\b|\bRTSP\b|smart\s+device|firmware\s+version"),
        ("selinux", r"\bSELinux\b|\bseinfo\b|\bsesearch\b|policy\.conf|\.te\b"),
        ("dotnet", r"\.NET|\bCIL\b|\bMSIL\b|\bAssembly\b|\.dll.*managed|\bdnSpy\b|\bILSpy\b"),
        ("thick-client", r"\.exe\b|\.dll\b|\bHKEY_\b|\bPE\s+file\b|thick\s+client"),
        ("firmware", r"\.bin\b|\.img\b|\.rom\b|\bfirmware\b|\bbinwalk\b|\bsquashfs\b|\bu-boot\b"),
        ("network", r"([0-9]{1,3}\.){3}[0-9]{1,3}|https?://|Network\s+Targets"),
    ]

    for target_type, pattern in checks:
        if re.search(pattern, text, re.IGNORECASE):
            _ttd_log(f"Auto-detected: {target_type}", body_root)
            return target_type

    _ttd_log("No target type detected", body_root)
    return "unknown"


def get_methodology_for_type(target_type: str, body_root: Path | None = None) -> str:
    """Return mapped methodology file path for target type, else empty string."""
    root = _detect_body_root() if body_root is None else body_root
    filename = _TARGET_TYPE_MAP.get(target_type.lower().strip())
    if not filename:
        return ""
    return str(root / "layer2-templates" / "methodologies" / filename)


def has_methodology(target_type: str, body_root: Path | None = None) -> bool:
    """Return whether methodology file exists for given target type."""
    path = get_methodology_for_type(target_type, body_root)
    return bool(path and Path(path).is_file())


def list_methodologies(body_root: Path | None = None) -> list[dict[str, str]]:
    """Print and return per-target methodology availability records."""
    root = _detect_body_root() if body_root is None else body_root

    print("")
    print("Available Methodologies")
    print("========================")
    print("")

    _display_entries: list[tuple[str, str]] = [
        ("android", "android-mobile-security.md"),
        ("iot", "iot-embedded-security.md"),
        ("bluetooth", "bluetooth-radio-security.md"),
        ("thick-client", "thick-client-security.md"),
        ("dotnet", "dotnet-assessment.md"),
        ("selinux", "selinux-android-exploitation.md"),
        ("homekit", "hap-homekit-fuzzing.md"),
        ("field", "field-intel.md"),
    ]

    output: list[dict[str, str]] = []
    for target_type, meth_name in _display_entries:
        meth_path = root / "layer2-templates" / "methodologies" / meth_name
        if meth_path.is_file():
            phase_count = sum(1 for line in meth_path.read_text(encoding="utf-8", errors="ignore").splitlines() if re.match(r"^## Phase [0-9]+:", line))
            phase_str = str(phase_count) if phase_count else "?"
            print(f"  [OK] {target_type} \u2192 {meth_name} ({phase_str} phases)")
        else:
            print(f"  [  ] {target_type} \u2192 {meth_name} (not found)")
        output.append({"file": meth_name, "exists": "yes" if meth_path.is_file() else "no"})

    print("")
    print("Set target type in SCOPE.md: 'Target Type: <type>'")
    print("")

    return output


def list_target_types() -> list[str]:
    """Return user-selectable canonical target-type labels with descriptions."""
    return [
        "1. android      - Android mobile apps (APK/AAB)",
        "2. ios          - iOS mobile apps (IPA)",
        "3. iot          - IoT/embedded devices, cameras",
        "4. bluetooth    - Bluetooth/BLE devices",
        "5. thick-client - Desktop apps (Windows exe/dll)",
        "6. dotnet       - .NET assemblies",
        "7. firmware     - Binary firmware images",
        "8. selinux      - SELinux policy analysis",
        "9. homekit      - HomeKit/HAP devices",
        "10. network     - Network-only (IPs, domains)",
        "11. field       - Field intelligence",
    ]


def selection_to_type(selection: str) -> str:
    """Map numeric or textual selection to canonical type string."""
    value = selection.strip().lower()
    mapping = {
        "1": "android",
        "2": "ios",
        "3": "iot",
        "4": "bluetooth",
        "5": "thick-client",
        "6": "dotnet",
        "7": "firmware",
        "8": "selinux",
        "9": "homekit",
        "10": "network",
        "11": "field",
    }
    if value in mapping:
        return mapping[value]
    # Accept aliases that the shell version supports in its case block
    aliases = {
        "thick_client": "thick-client",
        "hap": "homekit",
    }
    if value in aliases:
        return aliases[value]
    return value if value in {v for v in mapping.values()} else ""


def require_methodology(body_root: Path | None = None) -> str:
    """Return methodology path for detected type or raise ``FileNotFoundError``."""
    target_type = detect_target_type(body_root)
    if target_type == "unknown":
        print("")
        print("No target type detected in scope.")
        print("")
        print("Set target type by adding to SCOPE.md:")
        print("  Target Type: android")
        print("")
        print("Or select from available types:")
        for line in list_target_types():
            print(line)
        raise FileNotFoundError("No target type detected in scope")

    method = get_methodology_for_type(target_type, body_root)
    if not method:
        print("")
        print(f"No methodology available for target type: {target_type}")
        print("")
        list_methodologies(body_root)
        raise FileNotFoundError(f"No methodology mapping for type '{target_type}'")
    if not Path(method).is_file():
        print("")
        print(f"Methodology file not found: {method}")
        print("")
        raise FileNotFoundError(f"Methodology file not found: {method}")
    return method


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        print("target_type_detector.py --detect | --map <type> | --list")
        return 0

    if args[0] == "--detect":
        print(detect_target_type())
        return 0

    if args[0] == "--map" and len(args) >= 2:
        print(get_methodology_for_type(args[1]))
        return 0

    if args[0] == "--list":
        for line in list_target_types():
            print(line)
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
