#!/usr/bin/env python3
"""Tool availability and methodology tool-resolution helpers."""

from __future__ import annotations

import platform
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LIB_DIR = str(Path(__file__).resolve().parent)
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

try:
    from methodology_loader import extract_primary_tools  # type: ignore
except Exception:  # pragma: no cover - optional import for standalone usage
    extract_primary_tools = None  # type: ignore[assignment]

try:
    from methodology_loader import get_tools_reference  # type: ignore
except Exception:  # pragma: no cover - optional import for standalone usage
    get_tools_reference = None  # type: ignore[assignment]


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


def _tr_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "ci.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [TOOL-RESOLVER] {message}\n")
    except OSError:
        pass


def _toolset_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer2-templates" / "toolset.md"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def check_tool(tool_name: str) -> bool:
    """Return whether a tool exists in PATH (with aliases)."""
    aliases = {"nc": "netcat", "python": "python3"}
    normalized = aliases.get(tool_name, tool_name)

    if shutil.which(normalized):
        return True

    fallback_aliases: dict[str, list[str]] = {
        "netcat": ["nc"],
        "python3": ["python"],
        "ida": ["ida64", "idat"],
        "ghidra": ["ghidraRun", "/Applications/Ghidra.app/Contents/MacOS/ghidra"],
    }
    for candidate in fallback_aliases.get(normalized, []):
        if candidate.startswith("/"):
            if Path(candidate).exists():
                return True
        elif shutil.which(candidate):
            return True

    return False


def get_tool_path(tool_name: str) -> str:
    """Return discovered executable path for tool or empty string."""
    direct = shutil.which(tool_name)
    if direct:
        return direct

    fallbacks = {
        "netcat": ["nc"],
        "python": ["python3"],
        "python3": ["python"],
    }
    for candidate in fallbacks.get(tool_name, []):
        path = shutil.which(candidate)
        if path:
            return path
    return ""


def _parse_toolset_entries(body_root: Path | None = None) -> dict[str, dict[str, str]]:
    toolset = _toolset_file(body_root)
    if not toolset.is_file():
        return {}

    entries: dict[str, dict[str, str]] = {}
    current_category = "unknown"
    for line in _read_text(toolset).splitlines():
        header_match = re.match(r"^###\s+(.*)$", line)
        if header_match:
            current_category = header_match.group(1).strip()
            continue

        row = [segment.strip() for segment in line.split("|")]
        if len(row) < 4 or not line.strip().startswith("|"):
            continue

        tool_cell = row[1].strip("` ")
        if not tool_cell or tool_cell.lower() == "tool":
            continue

        entries[tool_cell.lower()] = {
            "tool": tool_cell,
            "category": current_category,
            "purpose": row[2] if len(row) > 2 else "",
            "raw": line,
        }
    return entries


def is_tool_cataloged(tool_name: str, body_root: Path | None = None) -> bool:
    """Return whether tool is present in `toolset.md`."""
    return tool_name.lower() in _parse_toolset_entries(body_root)


def get_tool_category(tool_name: str, body_root: Path | None = None) -> str:
    """Return catalog category for tool, else `unknown`."""
    entry = _parse_toolset_entries(body_root).get(tool_name.lower())
    return entry.get("category", "unknown") if entry else "unknown"


def get_tool_purpose(tool_name: str, body_root: Path | None = None) -> str:
    """Return catalog purpose for tool, else empty string."""
    entry = _parse_toolset_entries(body_root).get(tool_name.lower())
    return entry.get("purpose", "") if entry else ""


def get_token_required(tool_name: str, body_root: Path | None = None) -> str:
    """Return token requirement inferred from toolset row."""
    entry = _parse_toolset_entries(body_root).get(tool_name.lower())
    if not entry:
        return ""
    raw = entry.get("raw", "")
    if "DESTRUCTIVE-APPROVAL" in raw:
        return "DESTRUCTIVE-APPROVAL"
    if "ACTIVE-TESTING-APPROVAL" in raw:
        return "ACTIVE-TESTING-APPROVAL"
    return ""


_COMMAND_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def _extract_code_block_tools(text: str) -> set[str]:
    found: set[str] = set()
    in_code_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if not in_code_block or not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0].strip("`")
        if _COMMAND_TOKEN_RE.fullmatch(token):
            found.add(token)
    return found


def _extract_tools_reference_tools(methodology_file: str | Path) -> set[str]:
    if get_tools_reference is None:
        return set()

    try:
        block = get_tools_reference(methodology_file)
    except Exception:
        return set()

    if not block:
        return set()

    found: set[str] = set()
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip().strip("`") for cell in stripped.split("|") if cell.strip()]
        if len(cells) < 2:
            continue
        if cells[0].lower() == "category" and cells[1].lower() == "tools":
            continue
        for candidate in re.split(r",\s*", cells[1]):
            token = candidate.strip().split()[0].strip("`")
            if _COMMAND_TOKEN_RE.fullmatch(token):
                found.add(token)
    return found


def _normalize_tool_names(tools: set[str]) -> list[str]:
    normalized: dict[str, str] = {}
    for tool in tools:
        key = tool.lower()
        if key not in normalized:
            normalized[key] = tool
    return [normalized[key] for key in sorted(normalized)]


def extract_methodology_tools(methodology_file: str | Path) -> list[str]:
    """Extract potential tools from command blocks and the Tools Reference table."""
    text = _read_text(Path(methodology_file))
    if not text:
        return []

    found = _extract_code_block_tools(text)
    found.update(_extract_tools_reference_tools(methodology_file))

    return _normalize_tool_names(found)


def resolve_tools_for_methodology(methodology_file: str | Path, *, verbose: bool = False, body_root: Path | None = None) -> dict[str, Any]:
    """Resolve availability and token requirements for methodology tools."""
    available: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    token_required: list[dict[str, str]] = []

    for tool in extract_methodology_tools(methodology_file):
        if check_tool(tool):
            available.append({"tool": tool, "path": get_tool_path(tool)})
        else:
            missing.append({"tool": tool, "purpose": get_tool_purpose(tool, body_root)})

        token = get_token_required(tool, body_root)
        if token:
            token_required.append({"tool": tool, "token": token})

    # Print markdown report matching V15 output
    print("## Tool Resolution")
    print("")
    print(f"### Available ({len(available)})")
    for item in available:
        if verbose:
            print(f"- {item['tool']} \u2192 {item.get('path', '')}")
        else:
            print(f"- {item['tool']}")
    print("")

    if missing:
        print(f"### Missing ({len(missing)})")
        for item in missing:
            suffix = f" ({item['purpose']})" if item.get("purpose") else ""
            print(f"- {item['tool']}{suffix}")
        print("")

    if token_required:
        print("### Token Required")
        for item in token_required:
            print(f"- {item['tool']} requires {item['token']}")
        print("")

    return {"available": available, "missing": missing, "token_required": token_required}


def check_tools_for_phase(methodology_file: str | Path, phase_pattern: str) -> dict[str, list[str]]:
    """Check availability for tools used in a specific methodology phase."""
    if extract_primary_tools is None:
        tools = extract_methodology_tools(methodology_file)
    else:
        try:
            tools = extract_primary_tools(methodology_file, phase_pattern)
        except Exception:
            tools = extract_methodology_tools(methodology_file)

    available = sorted(tool for tool in tools if check_tool(tool))
    missing = sorted(tool for tool in tools if not check_tool(tool))

    print("Phase Tools:")
    print(f"  Available: {' '.join(available) if available else 'none'}")
    print(f"  Missing: {' '.join(missing) if missing else 'none'}")

    return {"available": available, "missing": missing}


def get_install_command(tool_name: str) -> str:
    """Return installation hint for current platform."""
    system = platform.system()
    if system == "Darwin":
        if tool_name in {"nmap", "masscan", "ffuf", "gobuster", "nikto", "binwalk", "apktool", "jadx"}:
            return f"brew install {tool_name}"
        if tool_name in {"frida", "objection"}:
            return f"pip3 install {'frida-tools' if tool_name == 'frida' else tool_name}"
        return f"# Check brew or pip for {tool_name}"

    if system == "Linux":
        if tool_name in {"nmap", "masscan", "nikto", "binwalk"}:
            return f"sudo apt install {tool_name}"
        if tool_name in {"ffuf", "gobuster"}:
            return f"go install github.com/ffuf/ffuf@latest  # adjust for {tool_name}"
        if tool_name == "frida":
            return "pip3 install frida-tools"
        return f"# Check apt/dnf/pacman for {tool_name}"

    return f"# Manual install required for {tool_name}"


def show_install_suggestions(methodology_file: str | Path) -> list[str]:
    """Print and return install hints for missing methodology tools."""
    suggestions: list[str] = []
    for tool in extract_methodology_tools(methodology_file):
        if not check_tool(tool):
            suggestions.append(f"{tool}: {get_install_command(tool)}")

    if not suggestions:
        print("All methodology tools available!")
    else:
        print("")
        print("Missing Tools - Install Suggestions:")
        print("")
        for tool in extract_methodology_tools(methodology_file):
            if not check_tool(tool):
                cmd = get_install_command(tool)
                print(f"  {tool}:")
                print(f"    {cmd}")
        print("")

    return suggestions


def show_tool_status(methodology_file: str | Path, *, body_root: Path | None = None) -> str:
    """Return multi-line tool status report for methodology."""
    resolved = resolve_tools_for_methodology(methodology_file, body_root=body_root)
    lines = ["Tool Availability", "================="]

    lines.append("")
    lines.append(f"Available ({len(resolved['available'])})")
    for item in resolved["available"]:
        path = item.get("path") or "(in PATH)"
        lines.append(f"  [OK] {item['tool']} ({path})")

    lines.append("")
    lines.append(f"Missing ({len(resolved['missing'])})")
    for item in resolved["missing"]:
        suffix = f" - {item['purpose']}" if item.get("purpose") else ""
        lines.append(f"  [MISSING] {item['tool']}{suffix}")

    if resolved["token_required"]:
        lines.append("")
        lines.append("Token Required")
        for item in resolved["token_required"]:
            lines.append(f"  {item['tool']}: {item['token']}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        print("tool_resolver.py --check <tool> | --status <methodology.md>")
        return 0

    if args[0] == "--check" and len(args) >= 2:
        return 0 if check_tool(args[1]) else 1

    if args[0] == "--status" and len(args) >= 2:
        print(show_tool_status(args[1]))
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
