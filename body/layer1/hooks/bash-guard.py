#!/usr/bin/env python3
"""Native Python bash governance guard.

Reads hook JSON from stdin and exits with:
- 0 allow
- 2 governance block
- 99 kill switch
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ============== LOCAL-ONLY COMMANDS (skip scope check) ==============

LOCAL_ONLY_COMMANDS = {
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "head", "tail", "less", "more",
    "cut", "sort", "uniq", "wc", "tr", "strings", "xxd", "hexdump", "od", "jq", "yq", "echo",
    "printf", "file", "stat", "sha256sum", "sha1sum", "md5sum", "diff", "comm", "tee", "base64",
    "rev", "nl", "expand", "unexpand", "fold", "fmt", "column", "paste", "join", "csplit",
    "split", "shuf", "readlink", "realpath", "basename", "dirname", "test", "true", "false",
    "ls", "pwd",
}

# ============== ACTIVE TESTING PATTERNS (CHECK 2) ==============

NETWORK_ACTIVITY_PATTERNS = [
    # Port scanning
    r"\bnmap\b", r"\bmasscan\b", r"\bzmap\b", r"\brustscan\b", r"\bunicornscan\b",
    # Web fuzzing against remote targets
    r"wfuzz\s+-u\s+http", r"ffuf\s+-u\s+http", r"gobuster\s+(dir|dns|vhost)",
    r"\bferoxbuster\b", r"\bdirsearch\b", r"\bnikto\b",
    # Network exploitation
    r"\bmetasploit\b", r"\bmsfconsole\b", r"\bmsfvenom\b", r"\bsqlmap\b",
    r"\bcommix\b", r"\bbeef-xss\b", r"\bbettercap\b",
    # Active network attacks
    r"\bhping3?\b", r"\bettercap\b", r"\barpspoof\b", r"\bresponder\b", r"\bmitm\b",
    # Reverse/bind shells
    r"reverse\s+shell", r"bind\s+shell", r"nc\s+-[elp]",
    # Protocol fuzzing
    r"\bsulley\b", r"\bpeach\b", r"\bspike\b", r"\bboofuzz\b",
]

STATIC_ANALYSIS_PATTERNS = [
    # Disassemblers / RE tools
    r"\bghidra\b", r"\bradare2\b", r"\br2\b", r"\bida\b", r"\bhopper\b", r"\bcutter\b",
    r"\bobjdump\b", r"strings\s", r"\breadelf\b", r"\bnm\s",
    # Static code analysis
    r"\bsemgrep\b", r"\bcodeql\b", r"\bbandit\b", r"\bflawfinder\b", r"\bbrakeman\b",
    r"\beslint\b", r"\bpylint\b", r"\bshellcheck\b",
    # Binary analysis (offline)
    r"\bbinwalk\b", r"file\s", r"\bhexdump\b", r"\bxxd\b", r"\bobjcopy\b",
    # Local fuzzing (not network)
    r"\bafl-fuzz\b", r"\blibfuzzer\b", r"\bhonggfuzz\b", r"\bzzuf\b", r"\bradamsa\b",
]

LOCALHOST_PATTERNS = [
    r"127\.0\.0\.1", r"localhost", r"0\.0\.0\.0", r"::1",
]

# ============== LIMITED SCOPE OPERATION PATTERNS (CHECK 2.5) ==============

LIMITED_BLOCK_PATTERNS = [
    r"\bnmap\b", r"\bmasscan\b", r"\brustscan\b", r"\bffuf\b", r"\bwfuzz\b",
    r"\bgobuster\b", r"\bferoxbuster\b", r"\bdirsearch\b", r"\bsqlmap\b", r"\bmsfconsole\b",
    r"\bmetasploit\b", r"\bnuclei\b", r"\bnikto\b", r"\bhydra\b", r"\bmedusa\b",
    r"\bburp\b", r"curl.*-X\s*POST", r"curl.*-X\s*PUT", r"curl.*-X\s*DELETE", r"curl.*-d\s", r"curl.*--data",
]

LIMITED_ALLOW_PATTERNS = [
    r"curl\s+-o", r"curl.*--output", r"curl\s+-O", r"wget\s", r"^ping\s", r"^ping6\s",
    r"^dig\s", r"^nslookup\s", r"^host\s", r"^whois\s", r"curl\s+-G", r"curl.*--get",
    r"curl\s+https?://", r"openssl\s+s_client", r"sslscan\s", r"theHarvester", r"amass.*-passive",
    r"^(cat|head|tail|less|more|file|ls|echo)\b",
]

# ============== DANGER CHECK PATTERNS (CHECK 3) ==============

DESTRUCTIVE_PATTERNS = [
    # Filesystem destruction (handles chained commands)
    (re.compile(r"(^|;|&&|\|\||&)\s*rm\s+-[rf]"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*rm\s+--recursive"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*rm\s+--force"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\brmdir\s+-p\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bfind\b.*-delete"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bfind\b.*-exec\s+rm"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bxargs\b.*\brm\b"), "DESTRUCTIVE-APPROVAL"),
    # Disk operations
    (re.compile(r"(^|;|&&|\|\||&)\s*dd\s+if="), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*dd\s+of=/dev/"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*mkfs"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*fdisk\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*parted\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*shred\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*wipefs\b"), "DESTRUCTIVE-APPROVAL"),
    # Dangerous redirects
    (re.compile(r">\s*/dev/sd"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r">\s*/dev/nvme"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r">\s*/dev/hd"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bcat\s+/dev/zero\s*>"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bcat\s+/dev/urandom\s*>"), "DESTRUCTIVE-APPROVAL"),
    # Fork bombs
    (re.compile(r":\(\)\s*\{.*:\|:.*\}"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"while\s+(true|1|:)\s*(;|do)"), "DESTRUCTIVE-APPROVAL"),
    # Dangerous permissions
    (re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*[0-7]*\s+-R"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bchmod\s+-R\s+[0-7]*7[0-7]*[0-7]*"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bchmod\s+(777|o\+w)"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bchown\s+-R\s+root"), "DESTRUCTIVE-APPROVAL"),
    # Network attacks
    (re.compile(r"(^|;|&&|\|\||&)\s*nmap\s+-s[SUAFX]"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*masscan\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*hping3?\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*ettercap\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*arpspoof\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*bettercap\b"), "DESTRUCTIVE-APPROVAL"),
    # Privilege escalation
    (re.compile(r"\bsudo\s+su\s+"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bsudo\s+(bash|sh|zsh|fish)\b"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bsudo\s+.*\s+-c\s"), "DESTRUCTIVE-APPROVAL"),
    # Remote code execution
    (re.compile(r"(curl|wget).*\|\s*(sh|bash|zsh|perl|ruby)(\s|$)"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(curl|wget).*\|\s*python([0-9.]*)?(\s*$|\s+-c(\s|$)|\s+-(\s|$))"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(curl|wget).*-o\s+\S+\s*&&\s*chmod\s+\+x"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bbash\s+-c\s+.*\$\((curl|wget)"), "DESTRUCTIVE-APPROVAL"),
    # Data exfiltration
    (re.compile(r"\bnc\s+-[elp]"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bnc\s+.*<"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bcurl\s+.*(-d|--data)\s+@"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bscp\s+.*:/"), "DESTRUCTIVE-APPROVAL"),
    # Git destructive
    (re.compile(r"\bgit\s+push\s+.*(-f|--force)"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bgit\s+reset\s+--hard"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bgit\s+clean\s+-[fd]"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bgit\s+checkout\s+\."), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bgit\s+restore\s+\."), "DESTRUCTIVE-APPROVAL"),
    # Git push (separate token)
    (re.compile(r"\bgit\s+push\b"), "PUSH-APPROVAL"),
    # Container escape
    (re.compile(r"\bdocker\s+run\s+.*--privileged"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"\bdocker\s+run\s+.*-v\s+/:/host"), "DESTRUCTIVE-APPROVAL"),
    (re.compile(r"(^|;|&&|\|\||&)\s*nsenter\b"), "DESTRUCTIVE-APPROVAL"),
    # Credential patterns
    (re.compile(r"(password|passwd|secret|api.?key|token)\s*=\s*['\"][^'\"]+['\"]"), "DESTRUCTIVE-APPROVAL"),
]

# System-wide install patterns (require SYSTEM-INSTALL-APPROVAL)
SYSTEM_INSTALL_PATTERNS = [
    re.compile(r"\bsudo\s+(apt|apt-get)\s+(install|remove|purge)"),
    re.compile(r"\bsudo\s+(yum|dnf)\s+(install|remove|erase)"),
    re.compile(r"\bsudo\s+pacman\s+-S"),
    re.compile(r"\bsudo\s+pip3?\s+install"),
    re.compile(r"\bsudo\s+npm\s+install\s+-g"),
    re.compile(r"\bsudo\s+gem\s+install"),
]

# ============== AGGRESSIVE SCAN PATTERNS (CHECK 5) ==============

AGGRESSIVE_SCAN_PATTERNS = [
    (re.compile(r"\bnmap\s+.*-sS\b"), "SYN-SCAN"),
    (re.compile(r"\bnmap\s+.*-sU\b"), "UDP-SCAN"),
    (re.compile(r"\bnmap\s+.*-sV\b"), "VERSION-SCAN"),
    (re.compile(r"\bnmap\s+.*-sC\b"), "SCRIPT-SCAN"),
    (re.compile(r"\bnmap\s+.*-A\b"), "AGGRESSIVE-SCAN"),
    (re.compile(r"\bnmap\s+.*-O\b"), "OS-DETECT"),
    (re.compile(r"\bmasscan\b"), "MASSCAN"),
    (re.compile(r"\bnc\s+-[ez]\b"), "NETCAT-EXEC"),
]

# ============== OUTPUT CONTAINMENT (CHECK 4) ==============

BLOCKED_WRITE_PATH_PATTERNS = [
    "/tmp/", "/private/tmp/", "/var/", "/etc/", "/Users/", "/home/", "/root/", "../",
]

PACKAGE_REGISTRY_HOSTS = {
    "github.com", "gitlab.com", "pypi.org", "npmjs.com", "rubygems.org", "crates.io", "brew.sh",
}

# TLD validation: recognized TLDs for target extraction (prevents filenames like firmware.bin)
VALID_TLDS = {
    # Country codes
    "com", "net", "org", "io", "dev", "app", "co", "us", "uk", "ca", "au", "de", "fr", "jp",
    "cn", "kr", "ru", "br", "in", "mx", "za", "nz", "se", "no", "fi", "nl", "be", "at", "ch",
    "es", "it", "pt", "pl", "cz", "hu", "ro", "bg", "hr", "si", "sk", "lt", "lv", "ee", "ie",
    "dk", "is", "lu", "mt", "cy", "gr", "tr", "il", "ae", "sa", "qa", "kw", "bh", "om", "eg",
    "ng", "ke", "gh", "tz", "ug", "rw", "ma", "tn", "dz", "ly", "et",
    # Institutional
    "edu", "gov", "mil", "int",
    # Generic
    "info", "biz", "name", "pro", "tel", "mobi", "asia", "cat", "coop", "museum", "aero",
    "jobs", "travel",
    # New gTLDs (common subset)
    "xyz", "top", "site", "online", "store", "tech", "space", "fun", "icu", "club", "vip",
    "work", "ltd", "buzz", "guru", "ninja", "life", "live", "world", "today", "zone", "link",
    "click", "host", "press", "news", "blog", "cloud", "digital", "network", "systems",
    "solutions", "services", "agency", "group", "global", "team", "email", "center", "support",
    "media", "marketing", "design", "studio", "consulting", "management", "company",
    # Private/reserved relevant to pentesting
    "local", "lan", "internal", "intranet", "localdomain", "home", "corp", "private", "test",
    "example", "invalid", "localhost",
    # Darknet
    "onion", "i2p",
}


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
        log_file = body_root / ".bra" / "logs" / "bash-guard.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"[{_utc_now()}] [PY-guard] {message}\n")
    except Exception:
        pass


def _read_input() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


# ============== CHECK 1: KILL SWITCH ==============

def _is_killswitch_active(body_root: Path) -> bool:
    # Source 1: Environment variable
    if os.environ.get("BRA_STOP") == "1":
        return True

    # Source 2: .bra/STOP file
    if (body_root / ".bra" / "STOP").exists():
        return True

    # Source 3: CLAUDE.md Kill Switch section (line-by-line state machine like .sh)
    claude = body_root / "CLAUDE.md"
    if claude.exists():
        try:
            text = claude.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        in_ks_section = False
        in_code_block = False
        for line in text.splitlines():
            if re.match(r"^##\s*Kill\s*Switch", line, re.IGNORECASE):
                in_ks_section = True
                continue
            if in_ks_section and line.startswith("## "):
                break
            if in_ks_section:
                if line.strip().startswith("```"):
                    in_code_block = not in_code_block
                    continue
                if in_code_block and re.match(r"^\s*STOP\s*$", line):
                    return True

    return False


# ============== TOKEN HELPERS ==============

def _has_token(body_root: Path, token: str) -> bool:
    env_name = token.replace("-", "_")
    if os.environ.get(env_name) == "1":
        return True
    return (body_root / ".bra" / "approvals" / token).is_file()


# ============== CHECK 2: ACTIVE TESTING ==============

def _is_localhost_target(command: str) -> bool:
    return any(re.search(pat, command) for pat in LOCALHOST_PATTERNS)


def _is_static_activity(command: str) -> bool:
    return any(re.search(pat, command) for pat in STATIC_ANALYSIS_PATTERNS)


def _is_network_activity(command: str) -> bool:
    if _is_localhost_target(command):
        return False
    return any(re.search(pat, command) for pat in NETWORK_ACTIVITY_PATTERNS)


def _get_active_scope_setting(body_root: Path) -> str:
    """Read active testing setting from SCOPE.md or ROE.md. Returns YES/NO/ASK."""
    setting = ""

    scope_file = body_root / "layer3-engagement" / "SCOPE.md"
    if scope_file.exists():
        try:
            for line in scope_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "ACTIVE-TESTING-APPROVAL:" in line:
                    setting = line.split(":", 1)[1].strip().split()[0] if ":" in line else ""
                    break
        except Exception:
            pass

    if not setting:
        roe_file = body_root / "layer3-engagement" / "ROE.md"
        if roe_file.exists():
            try:
                text = roe_file.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"ACTIVE-TESTING-APPROVAL.*(YES|APPROVED)", text):
                    setting = "YES"
                elif re.search(r"ACTIVE-TESTING-APPROVAL.*(NO|DENIED)", text):
                    setting = "NO"
                elif re.search(r"ACTIVE-TESTING-APPROVAL.*ASK", text):
                    setting = "ASK"
            except Exception:
                pass

    upper = setting.upper()
    if upper in {"YES", "APPROVED"}:
        return "YES"
    if upper in {"NO", "DENIED"}:
        return "NO"
    return "ASK"


def _check_active_approval(body_root: Path) -> bool:
    """Return True if ACTIVE-TESTING-APPROVAL token is present."""
    if os.environ.get("ACTIVE_TESTING_APPROVAL") == "1":
        return True
    if (body_root / ".bra" / "approvals" / "ACTIVE-TESTING-APPROVAL").is_file():
        return True
    # Check ROE.md marker
    for roe_path in [
        body_root / "layer3-engagement" / "ROE.md",
        body_root / "layer1" / "rules" / "roe.md",
    ]:
        if roe_path.exists():
            try:
                text = roe_path.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"ACTIVE-TESTING-APPROVAL\s*:\s*(Set|GRANTED)", text):
                    return True
            except Exception:
                pass
    return False


def _check_active_testing(command: str, body_root: Path) -> tuple[bool, str]:
    """CHECK 2: Active testing gate. Returns (allowed, reason)."""
    if not command:
        return True, ""

    # Static analysis always allowed
    if _is_static_activity(command):
        _log(body_root, f"ALLOWED static analysis: {command}")
        return True, ""

    if not _is_network_activity(command):
        return True, ""

    setting = _get_active_scope_setting(body_root)

    if setting == "YES":
        _log(body_root, f"ALLOWED network activity (YES setting): {command}")
        return True, ""

    if setting == "NO":
        matched = next((p for p in NETWORK_ACTIVITY_PATTERNS if re.search(p, command)), "")
        _log(body_root, f"BLOCKED network activity (NO setting): {command}")
        return False, (
            "BLOCKED: Network-based testing is disabled (Active Testing: NO)\n"
            f"Pattern matched: {matched}\n"
            f"Command: {command}\n\n"
            "Static analysis tools are still allowed.\n"
            "To enable network testing, update scope to Active Testing: YES or ASK"
        )

    # ASK
    if _check_active_approval(body_root):
        _log(body_root, f"ALLOWED network activity (ASK + token): {command}")
        return True, ""

    matched = next((p for p in NETWORK_ACTIVITY_PATTERNS if re.search(p, command)), "")
    _log(body_root, f"BLOCKED network activity (ASK, no token): {command}")
    return False, (
        "BLOCKED: Network-based testing requires approval (Active Testing: ASK)\n"
        f"Pattern matched: {matched}\n"
        f"Command: {command}\n\n"
        "To approve, provide token via:\n"
        "  1. Environment: ACTIVE_TESTING_APPROVAL=1\n"
        "  2. File: touch .bra/approvals/ACTIVE-TESTING-APPROVAL"
    )


# ============== CHECK 2.5: TARGET SCOPE ==============

def _looks_like_simple_local_command(command: str) -> bool:
    if any(op in command for op in ("|", ";", "&&", "||", "$(", "`", "<(", ">(", "/dev/tcp/", "/dev/udp/")):
        return False
    first = command.strip().split()[0] if command.strip() else ""
    first = Path(first).name
    return first in LOCAL_ONLY_COMMANDS


def _extract_target(command: str) -> str:
    if not command.strip():
        return ""

    # CIDR first (most specific)
    cidr_match = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", command)
    if cidr_match:
        return cidr_match.group(0)

    # Bare IP (discard localhost, fall through to domain extraction)
    ip_match = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", command)
    if ip_match:
        ip = ip_match.group(0)
        if not ip.startswith("127.0.0.") and ip not in {"0.0.0.0", "::1"}:
            return ip

    # URL domain extraction
    url_match = re.search(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", command)
    if url_match:
        host = url_match.group(1).lower()
        if host not in PACKAGE_REGISTRY_HOSTS and _has_valid_tld(host):
            return host

    # Standalone domain extraction
    domain_match = re.search(r"(?:^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[a-zA-Z0-9.-]*)", command)
    if domain_match:
        host = domain_match.group(1).lower()
        if host not in PACKAGE_REGISTRY_HOSTS and _has_valid_tld(host):
            return host

    return ""


def _has_valid_tld(hostname: str) -> bool:
    """Check if hostname has a recognized TLD (prevents filenames like firmware.bin)."""
    # IPs don't need TLD validation
    if re.match(r"^[0-9]+\.", hostname):
        return True
    tld = hostname.rsplit(".", 1)[-1].split(":")[0].split("/")[0].lower()
    return tld in VALID_TLDS


def _target_in_file(target: str, text: str) -> bool:
    escaped = re.escape(target)
    return re.search(rf"(^|[^a-zA-Z0-9._/-]){escaped}([^a-zA-Z0-9._/-]|$)", text) is not None


def _ip_in_cidr(ip_or_cidr: str, cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if "/" in ip_or_cidr:
            target = ipaddress.ip_network(ip_or_cidr, strict=False)
            return target.subnet_of(network)
        return ipaddress.ip_address(ip_or_cidr) in network
    except Exception:
        return False


def _scope_data(body_root: Path) -> tuple[list[str], list[dict[str, Any]], str]:
    approved_path = body_root / ".bra" / "approved_targets.json"
    scope_md = body_root / "layer3-engagement" / "SCOPE.md"

    original: list[str] = []
    discovered: list[dict[str, Any]] = []
    scope_text = ""

    if approved_path.exists():
        try:
            payload = json.loads(approved_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                o = payload.get("original", [])
                d = payload.get("discovered", [])
                if isinstance(o, list):
                    original = [str(x) for x in o if isinstance(x, str)]
                if isinstance(d, list):
                    discovered = [x for x in d if isinstance(x, dict)]
        except Exception:
            pass

    if scope_md.exists():
        try:
            scope_text = scope_md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            scope_text = ""

    return original, discovered, scope_text


def _is_target_approved(target: str, original: list[str], discovered: list[dict[str, Any]], scope_text: str) -> bool:
    if not target:
        return True

    if target in original:
        return True

    for item in discovered:
        if str(item.get("target", "")) == target:
            return True

    if scope_text and _target_in_file(target, scope_text):
        return True

    if target and scope_text:
        cidrs = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", scope_text)
        for cidr in cidrs:
            if _ip_in_cidr(target, cidr):
                return True

    for item in discovered:
        t = str(item.get("target", ""))
        if "/" in t and _ip_in_cidr(target, t):
            return True

    return False


def _scope_level(target: str, original: list[str], discovered: list[dict[str, Any]], scope_text: str) -> str:
    if not target:
        return "FULL"

    if target in original:
        return "FULL"

    if scope_text and _target_in_file(target, scope_text):
        return "FULL"

    if scope_text:
        cidrs = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", scope_text)
        for cidr in cidrs:
            if _ip_in_cidr(target, cidr):
                return "FULL"

    for item in discovered:
        if str(item.get("target", "")) == target:
            return str(item.get("level", "FULL")).upper() or "FULL"

    for item in discovered:
        cidr = str(item.get("target", ""))
        if "/" in cidr and _ip_in_cidr(target, cidr):
            return str(item.get("level", "FULL")).upper() or "FULL"

    return "FULL"


def _is_operation_allowed(command: str, level: str) -> bool:
    upper = level.upper()
    if upper == "FULL":
        return True
    if upper == "NONE":
        return False
    if upper == "CUSTOM":
        return True

    for pat in LIMITED_BLOCK_PATTERNS:
        if re.search(pat, command, re.IGNORECASE):
            return False

    for pat in LIMITED_ALLOW_PATTERNS:
        if re.search(pat, command, re.IGNORECASE):
            return True

    return False


# ============== CHECK 3: DANGER CHECK ==============

def _is_venv_install(command: str) -> bool:
    """Check if command is a virtual-env/project-local install (always allowed)."""
    if re.search(r"\bpip3?\s+install\b", command) and "--user" not in command and "sudo" not in command:
        if os.environ.get("VIRTUAL_ENV"):
            return True
    if re.search(r"\bnpm\s+install\b", command) and "-g" not in command and "--global" not in command:
        return True
    return False


def _is_user_install(command: str) -> str:
    """Return matched pattern if user-space install, else empty string."""
    patterns = [
        (r"\bbrew\s+install\b", "brew install"),
        (r"\bpip3?\s+install\s+--user\b", "pip install --user"),
        (r"\bnpm\s+install\s+-g\b", "npm install -g (no sudo)"),
    ]
    for pat, label in patterns:
        if re.search(pat, command) and "sudo" not in command:
            return label
    return ""


def _is_system_install(command: str) -> bool:
    """Check if command is a system-wide install."""
    return any(pat.search(command) for pat in SYSTEM_INSTALL_PATTERNS)


def _check_destructive_tokens(command: str, body_root: Path) -> tuple[bool, str]:
    # CHECK 3a: venv install — always allow
    if _is_venv_install(command):
        _log(body_root, f"ALLOWED venv/project-local install: {command}")
        return True, ""

    # CHECK 3b: user-space install — allow with warning
    user_pat = _is_user_install(command)
    if user_pat:
        _log(body_root, f"WARN user-space install ({user_pat}): {command}")
        return True, ""

    # CHECK 3c: system-wide install — requires SYSTEM-INSTALL-APPROVAL
    if _is_system_install(command):
        if _has_token(body_root, "SYSTEM-INSTALL-APPROVAL"):
            _log(body_root, f"APPROVED system install: {command}")
            return True, ""
        return False, (
            "BLOCKED: System-wide installation requires SYSTEM-INSTALL-APPROVAL.\n"
            f"Command: {command}\n"
            "To approve:\n"
            "  1. Environment: SYSTEM_INSTALL_APPROVAL=1\n"
            "  2. File: touch .bra/approvals/SYSTEM-INSTALL-APPROVAL"
        )

    # CHECK 3d: destructive patterns
    for pattern, token in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            if _has_token(body_root, token):
                _log(body_root, f"APPROVED dangerous ({token}): {command}")
                return True, ""
            return False, (
                f"BLOCKED: Operation requires {token}.\n"
                f"Command: {command}\n"
                f"Set env {token.replace('-', '_')}=1 or create .bra/approvals/{token}"
            )
    return True, ""


# ============== CHECK 3.5: HOST CLAUDE PATH ==============

def _references_host_claude_dir(command: str, allowed: str, host_home: str) -> bool:
    if allowed and allowed in command:
        return False
    if host_home and f"{host_home}/.claude" in command:
        return True
    if re.search(r"/Users/[^/\s]+/\.claude([/\s]|$)", command):
        return True
    if re.search(r"/home/[^/\s]+/\.claude([/\s]|$)", command):
        return True
    if re.search(r"/root/\.claude([/\s]|$)", command):
        return True
    return False


# ============== CHECK 4: OUTPUT CONTAINMENT ==============

def _is_write_context(command: str) -> bool:
    patterns = [
        r"-o\s", r"--output", r"-O\s", r"(^|\s)[0-9]*>\s*[^&\s]", r"(^|\s)[0-9]*>>\s*[^&\s]",
        r"\|\s*tee", r"^tee\s", r"(^|\s)cp\s", r"^cp\s", r"(^|\s)mv\s", r"^mv\s", r"\bdd\b", r"\bof=",
        r"\brsync\b", r"\bscp\b",
    ]
    return any(re.search(pat, command) for pat in patterns)


def _is_project_claude_path(token: str, bra_claude: str) -> bool:
    candidate = token.strip().strip("\"'")
    if not candidate:
        return False
    if candidate == ".bra/.claude" or candidate.startswith(".bra/.claude/"):
        return True
    if candidate == bra_claude or candidate.startswith(f"{bra_claude}/"):
        return True
    try:
        candidate_path = Path(candidate)
        if candidate_path.is_absolute():
            resolved_candidate = candidate_path.resolve(strict=False)
            resolved_bra = Path(bra_claude).resolve(strict=False)
            if resolved_candidate == resolved_bra or resolved_bra in resolved_candidate.parents:
                return True
    except Exception:
        pass
    return False


def _references_project_claude_dir(command: str, bra_claude: str) -> bool:
    return bra_claude in command or ".bra/.claude" in command


def _references_anon_map(command: str, anon_map_path: str) -> bool:
    return anon_map_path in command or ".bra/anon_map.json" in command


def _is_project_claude_write_target(command: str, bra_claude: str) -> bool:
    direct_patterns = [
        rf"(^|\s)[0-9]*>>?\s*{re.escape(bra_claude)}([/\s]|$)",
        rf"(^|\s)[0-9]*>>?\s*\.bra/\.claude([/\s]|$)",
        r"(^|\s)[0-9]*>>?\s*\S*?\.bra/\.claude([/\s]|$)",
        rf"\btee\b(?:\s+-a)?\s+{re.escape(bra_claude)}([/\s]|$)",
        rf"\btee\b(?:\s+-a)?\s+\.bra/\.claude([/\s]|$)",
        r"\btee\b(?:\s+-a)?\s+\S*?\.bra/\.claude([/\s]|$)",
    ]
    if any(re.search(pattern, command) for pattern in direct_patterns):
        return True

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    if not tokens:
        return False

    for token, next_token in zip(tokens, tokens[1:]):
        if token in {">", ">>", "1>", "1>>"} and _is_project_claude_path(next_token, bra_claude):
            return True
        for prefix in (">>", "1>>", ">", "1>"):
            if token.startswith(prefix) and _is_project_claude_path(token[len(prefix):], bra_claude):
                return True

    cmd = Path(tokens[0]).name
    if cmd == "tee":
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            if _is_project_claude_path(token, bra_claude):
                return True
    if cmd in {"cp", "mv", "install", "rsync"}:
        for token in reversed(tokens[1:]):
            if token.startswith("-"):
                continue
            return _is_project_claude_path(token, bra_claude)

    return False


def _check_output_containment(command: str, allowed_output_dir: str | None = None) -> tuple[bool, str]:
    if not _is_write_context(command):
        return True, ""
    if allowed_output_dir and _is_project_claude_write_target(command, allowed_output_dir):
        return True, ""
    for pattern in BLOCKED_WRITE_PATH_PATTERNS:
        if pattern in command:
            return False, (
                "BLOCKED: Command writes to restricted path\n"
                f"Pattern matched: {pattern}\n"
                f"Command: {command}\n\n"
                "During engagements, output must stay within:\n"
                "  • .bra/artifacts/    - Runtime artifacts\n"
                "  • layer3-engagement/ - Engagement files\n\n"
                "Use relative paths or approved directories."
            )
    return True, ""


# ============== CHECK 5: AGGRESSIVE SCAN ==============

def _detect_scan_type(command: str) -> str:
    """Return scan type label if command is an aggressive scan, else empty string."""
    for pattern, label in AGGRESSIVE_SCAN_PATTERNS:
        if pattern.search(command):
            return label
    return ""


def _check_aggressive_scan(command: str, body_root: Path) -> tuple[bool, str]:
    """CHECK 5: Block aggressive scans without approval."""
    scan_type = _detect_scan_type(command)
    if not scan_type:
        return True, ""

    # Check for scan approval file
    approval_file = body_root / ".bra" / "approvals" / f"SCAN-{scan_type}"
    if approval_file.is_file():
        _log(body_root, f"ALLOWED aggressive scan approved: {scan_type} - {command}")
        return True, ""

    # Also accept general ACTIVE-TESTING-APPROVAL
    if _has_token(body_root, "ACTIVE-TESTING-APPROVAL"):
        _log(body_root, f"ALLOWED aggressive scan (ACTIVE-TESTING token): {scan_type} - {command}")
        return True, ""

    scan_target = _extract_target(command) or "*"
    _log(body_root, f"BLOCKED aggressive scan: {scan_type} - {command}")
    return False, (
        "AGGRESSIVE_SCAN_BLOCKED\n"
        f"SCAN_TYPE={scan_type}\n\n"
        "═══════════════════════════════════════════════════════════════\n"
        "                AGGRESSIVE SCAN REQUIRES APPROVAL\n"
        "═══════════════════════════════════════════════════════════════\n\n"
        f"Scan Type: {scan_type}\n"
        f"Command: {command}\n\n"
        "Aggressive scans can:\n"
        "  - Trigger IDS/IPS alerts and get IP banned\n"
        "  - Cause service disruption or crashes\n"
        "  - Leave obvious forensic traces\n"
        "  - Violate rules of engagement\n\n"
        "Before proceeding, ask the user:\n"
        f"  'This is an aggressive scan ({scan_type}). Should I proceed?'\n\n"
        "If approved, run:\n"
        f"  ./layer1/scripts/approve-scan.py {scan_type} {scan_target} 1h\n\n"
        "───────────────────────────────────────────────────────────────"
    )


# ============== CHECK 7: ANON INTERCEPT ==============

def _load_anon_map(body_root: Path) -> list[dict[str, str]]:
    """Load mappings from .bra/anon_map.json. Returns [] on any error."""
    map_path = body_root / ".bra" / "anon_map.json"
    if not map_path.is_file():
        return []
    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
        mappings = data.get("mappings", [])
        return mappings if isinstance(mappings, list) else []
    except Exception:
        return []


def _anon_unmask(text: str, mappings: list[dict[str, str]]) -> str:
    """Replace anon words with real values in target tokens, not local paths.

    Shell redirects and local artifact names often embed the anon target label
    (for example `twilight_root_full.html`). Replacing those path fragments with
    the real identifier leaks provenance into local filenames. Only unmask:
    - URL-like tokens (`http://anon/...`)
    - standalone command tokens (`nmap anon`, `curl anon:8080`)
    """
    updated = str(text or "")
    if not updated:
        return updated

    url_pattern = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"`|><&;]+")
    boundary_class = r"A-Za-z0-9._/\-"

    for mapping in sorted(mappings, key=lambda item: len(item.get("anon", "")), reverse=True):
        anon = str(mapping.get("anon", "") or "")
        real = str(mapping.get("real", "") or "")
        if not anon or not real:
            continue

        updated = url_pattern.sub(lambda match: match.group(0).replace(anon, real), updated)
        token_pattern = re.compile(
            rf"(?<![{boundary_class}]){re.escape(anon)}(?![{boundary_class}])"
        )
        updated = token_pattern.sub(real, updated)

    return updated


def _anon_mask(text: str, mappings: list[dict[str, str]]) -> str:
    """Replace real values with anon words (longest first)."""
    for mapping in sorted(mappings, key=lambda item: len(item.get("real", "")), reverse=True):
        real = mapping.get("real", "")
        anon = mapping.get("anon", "")
        if real and anon and real in text:
            text = text.replace(real, anon)
    return text


def _command_has_anon_words(command: str, mappings: list[dict[str, str]]) -> bool:
    """Return True if command contains any known anon words."""
    return any(mapping.get("anon", "") and mapping["anon"] in command for mapping in mappings)


def _anon_execute_and_capture(command: str, timeout: int = 300) -> tuple[int, str]:
    """Execute a shell command and capture combined stdout+stderr."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        parts = []
        if result.stdout:
            parts.append(result.stdout)
        if result.stderr:
            parts.append(result.stderr)
        return result.returncode, "\n".join(parts) if parts else ""
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out after {timeout}s"
    except Exception as exc:
        return 1, f"Execution error: {exc}"


def _sanitize_capture_token(value: str, fallback: str) -> str:
    """Sanitize a value for use in artifact filenames."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip().lower()).strip("-._")
    return cleaned[:80] if cleaned else fallback


def _anon_save_artifact(
    masked_output: str,
    body_root: Path,
    label: str,
    capture_id: str = "",
) -> Path | None:
    """Save masked output to .bra/artifacts/raw/. Returns artifact path."""
    if not masked_output:
        return None
    raw_dir = body_root / ".bra" / "artifacts" / "raw"
    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    cap_prefix = _sanitize_capture_token(capture_id, "anon")
    base_name = f"{cap_prefix}_{label}_{timestamp}"
    artifact = raw_dir / f"{base_name}.txt"
    suffix = 1
    while artifact.exists():
        artifact = raw_dir / f"{base_name}_{suffix:02d}.txt"
        suffix += 1
    try:
        artifact.write_text(masked_output, encoding="utf-8")
        return artifact
    except Exception:
        return None


def _anon_write_last_capture(
    body_root: Path,
    command: str,
    artifact_path: Path,
    capture_id: str,
) -> None:
    """Write .bra/last_capture.json so capture_id resolves."""
    try:
        last_capture_path = body_root / ".bra" / "last_capture.json"
        last_capture_path.write_text(
            json.dumps(
                {
                    "command": command,
                    "path": str(artifact_path),
                    "capture_id": capture_id,
                    "anon_intercepted": True,
                }
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def _anon_append_evidence_index(
    body_root: Path,
    command: str,
    artifact_path: Path,
    capture_id: str,
    session_id: str = "",
    tool_use_id: str = "",
) -> None:
    """Append to .bra/logs/evidence_index.jsonl for provenance."""
    try:
        import hashlib

        sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        index_path = body_root / ".bra" / "logs" / "evidence_index.jsonl"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "capture_id": capture_id,
            "session_id": session_id,
            "tool_use_id": tool_use_id,
            "tool_name": "Bash",
            "action": "bash",
            "target": command[:240],
            "command": command,
            "artifact_path": str(artifact_path),
            "artifact_sha256": sha,
            "source_kind": "anon_intercept",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with index_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except Exception:
        pass


def _anon_intercept(
    command: str,
    body_root: Path,
    tool_use_id: str = "",
    session_id: str = "",
) -> tuple[bool, str]:
    """Intercept anon-word commands, execute them, and store masked output."""
    if _has_token(body_root, "ANON-DISABLE"):
        return True, ""

    mappings = _load_anon_map(body_root)
    if not mappings:
        return True, ""

    if not _command_has_anon_words(command, mappings):
        return True, ""

    capture_id = _sanitize_capture_token(tool_use_id, "")
    if not capture_id:
        capture_id = f"anon_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

    real_command = _anon_unmask(command, mappings)
    _log(body_root, f"ANON-INTERCEPT unmask: {command} -> {real_command}")

    exit_code, raw_output = _anon_execute_and_capture(real_command)
    masked_output = _anon_mask(raw_output, mappings)

    command_parts = command.strip().split()
    label = re.sub(r"[^a-zA-Z0-9._-]+", "-", command_parts[0] if command_parts else "cmd").strip("-")[:40]
    artifact_path = _anon_save_artifact(masked_output, body_root, label, capture_id)
    _log(body_root, f"ANON-INTERCEPT captured: exit={exit_code} capture_id={capture_id} artifact={artifact_path}")

    if artifact_path:
        _anon_write_last_capture(body_root, command, artifact_path, capture_id)
        _anon_append_evidence_index(
            body_root,
            command,
            artifact_path,
            capture_id,
            session_id=session_id,
            tool_use_id=tool_use_id,
        )

    lines = masked_output.splitlines()
    preview = "\n".join(lines[:80])
    if len(lines) > 80:
        preview += f"\n... ({len(lines) - 80} more lines)"

    artifact_rel = ""
    if artifact_path:
        try:
            artifact_rel = str(artifact_path.relative_to(body_root))
        except ValueError:
            artifact_rel = str(artifact_path)

    message_parts = [
        f"ANON_INTERCEPT_OK (exit {exit_code})",
        f"capture_id: {capture_id}",
        "",
        "Command executed successfully. Output anonymized.",
    ]
    if artifact_path:
        message_parts.append(f"Full output: {artifact_rel}")
        message_parts.append("")
    if preview:
        message_parts.append(preview)

    return False, "\n".join(message_parts)


# ============== CHECK 6: SERVICE STATE TRACKING ==============

def _record_pre_command_state(target: str, body_root: Path) -> None:
    """Record service state before a network command (best-effort, non-blocking)."""
    try:
        state_file = body_root / ".bra" / "service_state.json"
        state: dict[str, Any] = {}
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
            except Exception:
                state = {}

        state.setdefault("pre_command", {})[target] = {
            "timestamp": _utc_now(),
            "status": "pending",
        }
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


# ============== MAIN ==============

def main(argv: list[str] | None = None) -> int:  # noqa: ARG001
    body_root = _detect_body_root()
    payload = _read_input()
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    tool_use_id = str(payload.get("tool_use_id", "") or "") if isinstance(payload, dict) else ""
    session_id = str(payload.get("session_id", "") or "") if isinstance(payload, dict) else ""
    command = ""
    if isinstance(tool_input, dict):
        command = str(tool_input.get("command", "") or "")

    _log(body_root, f"Command: {command or '<empty>'}")

    # CHECK 1: Kill switch
    if _is_killswitch_active(body_root):
        _log(body_root, "BLOCKED: kill switch active")
        print("BLOCKED: Kill switch is ACTIVE - all operations halted", file=sys.stderr)
        return 99

    if not command:
        return 0

    # CHECK 2: Active testing gate
    ok, reason = _check_active_testing(command, body_root)
    if not ok:
        print(reason, file=sys.stderr)
        return 2

    # CHECK 2.5: Target scope validation (skip simple local-only commands)
    if not _looks_like_simple_local_command(command):
        target = _extract_target(command)
        if target:
            original, discovered, scope_text = _scope_data(body_root)
            if not _is_target_approved(target, original, discovered, scope_text):
                _log(body_root, f"BLOCKED unapproved target: {target} in command: {command}")
                print("SCOPE_CHECK_REQUIRED", file=sys.stderr)
                print(f"TARGET={target}", file=sys.stderr)
                print("", file=sys.stderr)
                print("═══════════════════════════════════════════════════════════════", file=sys.stderr)
                print("                    SCOPE CHECK REQUIRED", file=sys.stderr)
                print("═══════════════════════════════════════════════════════════════", file=sys.stderr)
                print("", file=sys.stderr)
                print(f"Discovered target: {target}", file=sys.stderr)
                print(f"Command: {command}", file=sys.stderr)
                print("", file=sys.stderr)
                print("This target is not in the approved scope.", file=sys.stderr)
                print("Before interacting, BRA must request an operator scope decision:", file=sys.stderr)
                print("", file=sys.stderr)
                print(f"  Is '{target}' in scope?", file=sys.stderr)
                print("  A. Fully in Scope — all testing allowed", file=sys.stderr)
                print("  B. Limited Scope — passive only (download, ping, DNS)", file=sys.stderr)
                print("  C. Not in Scope — do not interact", file=sys.stderr)
                print("  D. Custom — specify what's allowed", file=sys.stderr)
                print("", file=sys.stderr)
                print("Do not run approve-target.py directly. Wait for the operator's scope approval modal.", file=sys.stderr)
                print("After BRA reports the target was added to scope, retry the original command.", file=sys.stderr)
                print("", file=sys.stderr)
                print("───────────────────────────────────────────────────────────────", file=sys.stderr)
                return 2

            level = _scope_level(target, original, discovered, scope_text)
            if not _is_operation_allowed(command, level):
                _log(body_root, f"BLOCKED operation not allowed for scope level: {command} (target: {target}, level: {level})")
                print("OPERATION_NOT_ALLOWED_FOR_SCOPE_LEVEL", file=sys.stderr)
                print(f"TARGET={target}", file=sys.stderr)
                print(f"SCOPE_LEVEL={level}", file=sys.stderr)
                print("", file=sys.stderr)
                print("═══════════════════════════════════════════════════════════════", file=sys.stderr)
                print("                OPERATION NOT ALLOWED", file=sys.stderr)
                print("═══════════════════════════════════════════════════════════════", file=sys.stderr)
                print("", file=sys.stderr)
                print(f"Target: {target}", file=sys.stderr)
                print(f"Scope Level: {level}", file=sys.stderr)
                print(f"Command: {command}", file=sys.stderr)
                print("", file=sys.stderr)
                if level == "LIMITED":
                    print("This target has LIMITED scope - only passive operations allowed:", file=sys.stderr)
                    print("  - Download files (curl -o, wget)", file=sys.stderr)
                    print("  - Ping", file=sys.stderr)
                    print("  - DNS lookups (dig, nslookup, host)", file=sys.stderr)
                    print("  - SSL/TLS inspection (openssl s_client)", file=sys.stderr)
                    print("", file=sys.stderr)
                    print("Blocked operations: port scanning, fuzzing, exploitation", file=sys.stderr)
                elif level == "NONE":
                    print("This target has NONE scope - no interaction allowed.", file=sys.stderr)
                    print("Document findings only.", file=sys.stderr)
                elif level == "CUSTOM":
                    print("This target has CUSTOM scope - check allowed operations.", file=sys.stderr)
                print("", file=sys.stderr)
                print("To change scope level, ask user and run:", file=sys.stderr)
                print(f"  ./layer1/scripts/approve-target.py '{target}' <NEW_LEVEL> '<reason>'", file=sys.stderr)
                print("", file=sys.stderr)
                print("───────────────────────────────────────────────────────────────", file=sys.stderr)
                return 2

    # CHECK 3: Danger check (destructive patterns + install detection)
    ok, reason = _check_destructive_tokens(command, body_root)
    if not ok:
        print(reason, file=sys.stderr)
        return 2

    # CHECK 3.5: Host Claude path block
    allowed_claude = os.environ.get("BRA_ALLOWED_CLAUDE_DIR") or str(body_root / ".bra" / ".claude")
    host_home = os.environ.get("BRA_HOST_HOME") or str(Path.home())
    if _references_host_claude_dir(command, allowed_claude, host_home):
        _log(body_root, f"BLOCKED host Claude path access: {command}")
        print("BLOCKED: Host Claude default directory access is not allowed", file=sys.stderr)
        print(f"Command: {command}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Use project-local state only:", file=sys.stderr)
        print(f"  • {allowed_claude}", file=sys.stderr)
        return 2

    # CHECK 3.6: Project-local .bra/.claude/ is write-only SDK scratch state
    bra_claude = str(body_root / ".bra" / ".claude")
    if _references_project_claude_dir(command, bra_claude) and not _is_project_claude_write_target(command, bra_claude):
        _log(body_root, f"BLOCKED .bra/.claude/ read access: {command}")
        print("BLOCKED: Agent read access to .bra/.claude/ is not permitted.", file=sys.stderr)
        print("Project-local .bra/.claude/ is write-only SDK scratch state.", file=sys.stderr)
        print("SDK session state may contain unmasked tool output.", file=sys.stderr)
        print("Use .bra/artifacts/raw/ for captured evidence instead.", file=sys.stderr)
        return 2

    anon_map_path = str(body_root / ".bra" / "anon_map.json")
    if _references_anon_map(command, anon_map_path):
        _log(body_root, f"BLOCKED .bra/anon_map.json access: {command}")
        print("BLOCKED: Agent access to .bra/anon_map.json is not permitted.", file=sys.stderr)
        print("Anonymization mappings are operator-only governance state.", file=sys.stderr)
        return 2

    # CHECK 4: Output path containment
    ok, reason = _check_output_containment(command, allowed_output_dir=bra_claude)
    if not ok:
        print(reason, file=sys.stderr)
        return 2

    # CHECK 5: Aggressive scan detection
    ok, reason = _check_aggressive_scan(command, body_root)
    if not ok:
        print(reason, file=sys.stderr)
        return 2

    # CHECK 6: Service state tracking (non-blocking, best effort)
    if _is_network_activity(command):
        target = _extract_target(command)
        if target:
            _record_pre_command_state(target, body_root)
            _log(body_root, f"Recording pre-command state for: {target}")

    ok, reason = _anon_intercept(command, body_root, tool_use_id=tool_use_id, session_id=session_id)
    if not ok:
        print(reason, file=sys.stderr)
        return 2

    _log(body_root, "ALLOWED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
