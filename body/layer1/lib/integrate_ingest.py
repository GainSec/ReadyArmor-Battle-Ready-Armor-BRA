#!/usr/bin/env python3
"""
Ingest Integration Script

Parses layer3-engagement/ingest/* content, redacts identifiable information,
and merges tools/methodologies into main files.

Redaction targets:
- Project/folder names from ingest sources
- Specific file paths containing usernames or project names
- Device serial numbers, specific IPs in target context
- Company/product names from assessments
- Specific finding references (finding1_, etc.)

Preserved content:
- Generic tool names (nmap, Ghidra, adb, etc.)
- Methodology descriptions and workflows
- Command patterns with placeholders
- Technique descriptions
"""

import os
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# ============================================================================
# REDACTION CONFIGURATION
# ============================================================================

# Project folder names to redact (extracted from layer3-engagement/ingest/)
# NOTE: Removed overly generic names that cause false positives:
# - "search", "notes", "mine", "comm", "compute", "raven", "quark", "magisk"
PROJECT_NAMES = {
    "ALLINONE", "ALPR-FLock-3", "ALPR-Final", "AOL-Test",
    "AutoPro", "COMPUTESELINUX", "Codex-Research", "Compute-Box-1",
    "ComputeApps", "ComputeBox-Unbricked-1-Root", "Digital-Ally", "EWALK",
    "FOLLOWUP", "Flock-General", "Flock-Sumarize", "FlockSafety-App",
    "HotList", "ImagePlayGroundTester-Public", "LibreSDR-GNURadio-Custom",
    "Modified-2", "NewNew", "Smartwatches", "binwalkv3-extract",
    "cardputor", "cpctl_build", "cpctl_full_build",
    "cpctl_full_www", "cpctl_www", "cveform-template", "droidvnc",
    "extractions", "final-modify", "flockcomputeboxbt", "flockleak",
    "fuzzingplan", "homekit-codex", "kapsch-notes", "latest-flock-add",
    "magiskmanager", "nano-phone",
    "oneplus-12r", "original-flock-lpr", "prior-agents",
    "raptor-orig", "raptor2", "remote-kali", "rms-sharing",
    "sepolicy-inject", "simdump", "ubertooth", "zsh_logs"
}

# Company/product names to redact (only longer/specific names to avoid false positives)
COMPANY_NAMES = {
    "FlockSafety", "Flock Safety", "Digital-Ally", "DigitalAlly",
    "CameraConfig", "ComputeBox", "NanoHTTPD",
    "sysmoUSIM", "sysmoISIM",  # Specific product identifiers
    "FLOCK", "AOL",  # Uppercase project names
}

# Patterns for identifiable content
REDACTION_PATTERNS = [
    # Serial numbers (device-specific)
    (r'\b\d{12,}P\d{8}\b', '[DEVICE_SERIAL]'),
    (r'\b241108P02100632\b', '[DEVICE_SERIAL]'),

    # Specific user paths (Unix)
    (r'/Users/\w+/', '/Users/[USER]/'),
    (r'/home/\w+/', '/home/[USER]/'),

    # Specific IPs in target context (not localhost/examples)
    (r'\b192\.168\.\d+\.\d+\b', '[TARGET_IP]'),
    (r'\b10\.\d+\.\d+\.\d+\b', '[TARGET_IP]'),
    # AWS/Cloud IPs
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b', '[CLOUD_IP]:[PORT]'),
    (r'\b3\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[AWS_IP]'),

    # Finding-specific script names
    (r'finding\d+_\w+\.py', '[FINDING_SCRIPT].py'),
    (r'finding\d+_\w+\.cs', '[FINDING_SCRIPT].cs'),

    # Specific port numbers in exploit context (keep common ones)
    (r'port[:\s]+8700\b', 'port: [JDWP_PORT]'),
    (r'port[:\s]+8900\b', 'port: [TARGET_PORT]'),

    # Project-specific paths
    (r'/ingest_sources/\w+/', '/ingest_sources/[PROJECT]/'),
    (r'layer3-engagement/ingest/\w+/', 'layer3-engagement/ingest/[PROJECT]/'),

    # Project-specific service/process names
    (r'\bflock_\w+', '[vendor]_[service]'),
    (r'\bkapsch_\w+', '[vendor]_[service]'),
]

# Replacement mappings for common project references
PROJECT_REPLACEMENTS = {
    "AOL Desktop": "[TARGET_APPLICATION]",
    "AOL.exe": "[TARGET_BINARY]",
    "AolDesktop": "[TARGET_APPLICATION]",
    "AolDesktop.sln": "[TARGET_SOLUTION]",
    ".AolSave": ".[CUSTOM_EXTENSION]",
    "waol-": "[CUSTOM_PROTO]-",
    "aol://": "[custom]://",
    "FlockSafety": "[TARGET_VENDOR]",
    "Flock Safety": "[TARGET_VENDOR]",
    "CameraConfig": "[TARGET_PROCESS]",
    "ComputeBox": "[TARGET_DEVICE]",
    "raptor.py": "[FRAMEWORK].py",
    "RAPTOR": "[FRAMEWORK]",
}

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Tool:
    """Represents a generic tool entry."""
    name: str
    purpose: str
    category: str
    platform: str = "Cross-platform"
    license: str = ""
    installation: str = ""
    source_project: str = ""  # Will be redacted in output

@dataclass
class Methodology:
    """Represents a methodology/technique."""
    name: str
    description: str
    category: str
    steps: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    source_project: str = ""  # Will be redacted in output

@dataclass
class IngestContent:
    """Aggregated content from ingest sources."""
    tools: List[Tool] = field(default_factory=list)
    methodologies: List[Methodology] = field(default_factory=list)
    skills: List[Dict] = field(default_factory=list)
    raw_sections: Dict[str, str] = field(default_factory=dict)

# ============================================================================
# REDACTION FUNCTIONS
# ============================================================================

def redact_text(text: str) -> str:
    """Apply all redaction patterns to text."""
    result = text

    # Apply regex patterns
    for pattern, replacement in REDACTION_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    # Apply direct replacements
    for original, replacement in PROJECT_REPLACEMENTS.items():
        result = re.sub(re.escape(original), replacement, result, flags=re.IGNORECASE)

    # Redact project folder names
    for project in PROJECT_NAMES:
        # Match as standalone word or in paths
        result = re.sub(
            rf'\b{re.escape(project)}\b',
            '[PROJECT]',
            result,
            flags=re.IGNORECASE
        )

    # Redact company names (be careful not to over-redact)
    for company in COMPANY_NAMES:
        if len(company) > 4:  # Only redact longer names to avoid false positives
            result = re.sub(
                rf'\b{re.escape(company)}\b',
                '[VENDOR]',
                result,
                flags=re.IGNORECASE
            )

    return result

def is_generic_tool(name: str) -> bool:
    """Check if a tool name is generic (not project-specific)."""
    generic_tools = {
        # Static analysis
        "semgrep", "codeql", "ripgrep", "rg", "grep", "strings", "file",
        "readelf", "objdump", "nm", "ldd", "jdeps", "binwalk", "rabin2",

        # Reverse engineering
        "ghidra", "ida", "radare2", "r2", "jadx", "apktool", "dex2jar",
        "ilspy", "dnspy", "hopper",

        # Dynamic analysis
        "gdb", "lldb", "windbg", "strace", "ltrace", "frida", "dtrace",
        "rr", "valgrind",

        # Fuzzing
        "afl", "afl++", "libfuzzer", "honggfuzz", "radamsa", "zzuf",

        # Network
        "wireshark", "tcpdump", "nmap", "masscan", "netcat", "nc",
        "burp", "burpsuite", "mitmproxy", "curl", "wget", "httpx",

        # Web
        "ffuf", "nuclei", "sqlmap", "nikto", "dirb", "gobuster",
        "wfuzz", "feroxbuster", "playwright", "selenium",

        # Mobile
        "adb", "fastboot", "scrcpy", "drozer", "objection",

        # Build/compile
        "gcc", "g++", "clang", "make", "cmake", "msbuild", "csc",
        "python", "python3", "pip", "npm", "cargo", "go",

        # Crypto/hash
        "openssl", "hashcat", "john", "sha256sum", "md5sum",

        # Documentation
        "markdown", "pandoc", "doxygen", "sphinx",

        # Version control
        "git", "svn",

        # Containers
        "docker", "podman", "kubectl",

        # Misc
        "jq", "yq", "xmllint", "textutil", "tar", "zip", "unzip",
    }
    return name.lower().strip() in generic_tools

def is_valid_purpose(purpose: str) -> bool:
    """Check if a purpose string is valid (not garbage/malformed)."""
    # Too short (likely version number or garbage)
    if len(purpose) < 8:
        return False

    # Looks like just a version number or framework version
    if re.match(r'^[\d.]+$', purpose.strip()):
        return False
    if re.match(r'^\.NET\s*[\d.]+$', purpose.strip()):
        return False

    # Contains code blocks or multiline content
    if '```' in purpose or '\n' in purpose:
        return False

    # Looks like a file path only
    if re.match(r'^[`/\\].*[`]?$', purpose.strip()):
        return False

    # Contains shell command fragments
    if any(x in purpose for x in ['cut -d', '--base', '--pagesize', '-o ']):
        return False

    # Starts with markdown header (garbage)
    if purpose.strip().startswith('##'):
        return False

    # Looks like partial/truncated content (contains redacted markers in odd places)
    if '[PROJECT]' in purpose:
        return False

    return True

def extract_generic_tools_from_table(text: str) -> List[Tool]:
    """Extract tool entries from markdown tables."""
    tools = []

    # Pattern for markdown table rows: | tool | purpose | ... |
    table_pattern = r'\|\s*`?([^|`]+)`?\s*\|\s*([^|]+)\s*\|'

    for match in re.finditer(table_pattern, text):
        name = match.group(1).strip()
        purpose = match.group(2).strip()

        # Skip header rows and non-tool entries
        if name.lower() in ('tool', 'name', '---', '----', 'version', 'purpose'):
            continue
        if not name or name.startswith('-'):
            continue

        # Skip if name looks malformed
        if ' ' in name and len(name.split()) > 4:
            continue
        if 'cmdline' in name.lower():
            continue

        # Validate purpose (before redaction)
        if not is_valid_purpose(purpose):
            continue

        # Redact and validate again
        redacted_purpose = redact_text(purpose)
        if not is_valid_purpose(redacted_purpose):
            continue

        # Only include generic tools
        base_name = name.split()[0].lower().replace('`', '')
        if is_generic_tool(base_name):
            # Clean up tool name (remove version numbers like "v14.1.0/14.1.1")
            clean_name = re.sub(r'\s+v?[\d./-]+$', '', name.replace('`', ''))
            tools.append(Tool(
                name=clean_name,
                purpose=redacted_purpose,
                category="Extracted",
            ))

    return tools

# ============================================================================
# PARSING FUNCTIONS
# ============================================================================

def parse_tools_file(filepath: Path) -> List[Tool]:
    """Parse a tools.md file and extract generic tools."""
    tools = []

    try:
        content = filepath.read_text()
    except Exception as e:
        print(f"  Warning: Could not read {filepath}: {e}")
        return tools

    # Extract from tables
    tools.extend(extract_generic_tools_from_table(content))

    # Extract from headers and lists
    current_category = "General"
    for line in content.split('\n'):
        # Track category from headers
        if line.startswith('##'):
            current_category = line.strip('#').strip()
            current_category = redact_text(current_category)

        # Extract from bullet points: - **tool** - description
        bullet_match = re.match(r'[-*]\s+\*\*([^*]+)\*\*\s*[-:]\s*(.+)', line)
        if bullet_match:
            name = bullet_match.group(1).strip()
            purpose = bullet_match.group(2).strip()

            # Validate purpose
            if not is_valid_purpose(purpose):
                continue

            base_name = name.split()[0].lower().replace('`', '')
            if is_generic_tool(base_name):
                # Clean up tool name (remove version numbers)
                clean_name = re.sub(r'\s+v?[\d./-]+$', '', name.replace('`', ''))
                tools.append(Tool(
                    name=clean_name,
                    purpose=redact_text(purpose),
                    category=current_category,
                ))

    return tools

def parse_methodology_file(filepath: Path) -> List[Methodology]:
    """Parse a methodology.md file and extract techniques."""
    methodologies = []

    try:
        content = filepath.read_text()
    except Exception as e:
        print(f"  Warning: Could not read {filepath}: {e}")
        return methodologies

    # Split by H2 headers
    sections = re.split(r'^## ', content, flags=re.MULTILINE)

    for section in sections[1:]:  # Skip content before first H2
        lines = section.split('\n')
        if not lines:
            continue

        name = lines[0].strip()
        body = '\n'.join(lines[1:])

        # Skip sections that are too project-specific
        skip_keywords = ['authorized', 'testing boundaries', 'kill switch',
                         'evidence standards', 'risk scoring']
        if any(kw in name.lower() for kw in skip_keywords):
            continue

        # Redact the content
        redacted_name = redact_text(name)
        redacted_body = redact_text(body)

        # Extract steps from numbered lists
        steps = []
        for match in re.finditer(r'^\d+\.\s+(.+)$', redacted_body, re.MULTILINE):
            steps.append(match.group(1).strip())

        methodologies.append(Methodology(
            name=redacted_name,
            description=redacted_body[:500] + "..." if len(redacted_body) > 500 else redacted_body,
            category="Extracted",
            steps=steps[:10],  # Limit steps
        ))

    return methodologies

def parse_skills_file(filepath: Path) -> List[Dict]:
    """Parse a skills.md file and extract skill patterns."""
    skills = []

    try:
        content = filepath.read_text()
    except Exception as e:
        print(f"  Warning: Could not read {filepath}: {e}")
        return skills

    # Extract skill entries from tables
    table_pattern = r'\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|'

    for match in re.finditer(table_pattern, content):
        skill = match.group(1).strip()
        tool = match.group(2).strip()
        purpose = match.group(3).strip()

        if skill.lower() in ('skill', 'capability', '---'):
            continue

        skills.append({
            'skill': redact_text(skill),
            'tool': redact_text(tool),
            'purpose': redact_text(purpose),
        })

    return skills

# ============================================================================
# INTEGRATION FUNCTIONS
# ============================================================================

def scan_ingest_directory(base_path: Path) -> IngestContent:
    """Scan layer3-engagement/ingest/ and extract all content."""
    content = IngestContent()
    ingest_path = base_path / "docs" / "ingest"

    if not ingest_path.exists():
        print(f"Error: {ingest_path} does not exist")
        return content

    print(f"Scanning {ingest_path}...")

    for project_dir in sorted(ingest_path.iterdir()):
        if not project_dir.is_dir():
            continue
        if project_dir.name.startswith('.'):
            continue

        print(f"  Processing {project_dir.name}...")

        # Parse tools
        tools_file = project_dir / "tools.md"
        if tools_file.exists():
            tools = parse_tools_file(tools_file)
            for tool in tools:
                tool.source_project = project_dir.name
            content.tools.extend(tools)

        # Parse methodology (singular and plural)
        for method_name in ["methodology.md", "methodologies.md"]:
            method_file = project_dir / method_name
            if method_file.exists():
                methods = parse_methodology_file(method_file)
                for method in methods:
                    method.source_project = project_dir.name
                content.methodologies.extend(methods)

        # Parse skills
        skills_file = project_dir / "skills.md"
        if skills_file.exists():
            skills = parse_skills_file(skills_file)
            content.skills.extend(skills)

    return content

def deduplicate_tools(tools: List[Tool]) -> List[Tool]:
    """Remove duplicate tools, keeping most detailed entry."""
    seen = {}

    for tool in tools:
        key = tool.name.lower().split()[0]  # Base tool name

        if key not in seen:
            seen[key] = tool
        else:
            # Keep entry with longer description
            if len(tool.purpose) > len(seen[key].purpose):
                seen[key] = tool

    return list(seen.values())

def categorize_tools(tools: List[Tool]) -> Dict[str, List[Tool]]:
    """Organize tools by category."""
    categories = {
        "Static Analysis": [],
        "Dynamic Analysis": [],
        "Reverse Engineering": [],
        "Fuzzing": [],
        "Network Analysis": [],
        "Web Assessment": [],
        "Mobile Security": [],
        "Binary Analysis": [],
        "Build Tools": [],
        "Cryptography": [],
        "Documentation": [],
        "Utility": [],
    }

    # Category keywords mapping
    category_keywords = {
        "Static Analysis": ["semgrep", "codeql", "lint", "sast", "grep", "ripgrep"],
        "Dynamic Analysis": ["strace", "ltrace", "frida", "dtrace", "debug", "gdb", "lldb"],
        "Reverse Engineering": ["ghidra", "ida", "radare", "jadx", "decompil", "disassembl"],
        "Fuzzing": ["afl", "fuzz", "libfuzzer", "honggfuzz", "radamsa"],
        "Network Analysis": ["wireshark", "tcpdump", "nmap", "netcat", "packet"],
        "Web Assessment": ["burp", "ffuf", "nuclei", "sqlmap", "xss", "web"],
        "Mobile Security": ["adb", "apk", "android", "ios", "frida", "objection"],
        "Binary Analysis": ["binwalk", "strings", "readelf", "objdump", "nm", "file"],
        "Build Tools": ["gcc", "clang", "make", "cmake", "msbuild", "compile"],
        "Cryptography": ["openssl", "hash", "crypto", "ssl", "tls"],
        "Documentation": ["markdown", "pandoc", "doc"],
    }

    for tool in tools:
        categorized = False
        tool_lower = tool.name.lower()
        purpose_lower = tool.purpose.lower()

        for category, keywords in category_keywords.items():
            if any(kw in tool_lower or kw in purpose_lower for kw in keywords):
                categories[category].append(tool)
                categorized = True
                break

        if not categorized:
            categories["Utility"].append(tool)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

def generate_toolset_additions(tools: List[Tool]) -> str:
    """Generate markdown for toolset.md additions."""
    categorized = categorize_tools(tools)

    lines = [
        "",
        "---",
        "",
        "## Integrated Tools (from Prior Engagements)",
        "",
        "> **Note:** Tools extracted from prior engagement documentation.",
        "> Specific project references have been redacted.",
        "",
    ]

    for category, category_tools in sorted(categorized.items()):
        lines.append(f"### {category}")
        lines.append("")
        lines.append("| Tool | Purpose | Platform |")
        lines.append("|------|---------|----------|")

        for tool in sorted(category_tools, key=lambda t: t.name.lower()):
            purpose = tool.purpose[:80] + "..." if len(tool.purpose) > 80 else tool.purpose
            lines.append(f"| `{tool.name}` | {purpose} | {tool.platform} |")

        lines.append("")

    return '\n'.join(lines)

def generate_methodology_additions(methodologies: List[Methodology]) -> str:
    """Generate markdown for methodology documentation."""
    lines = [
        "# Integrated Methodologies",
        "",
        "> **Source:** Extracted from prior engagement documentation.",
        "> Project-specific references have been redacted.",
        "",
        f"> **Generated:** {datetime.now().strftime('%Y-%m-%d')}",
        "",
        "---",
        "",
    ]

    # Group by rough category
    categories = {}
    for method in methodologies:
        # Derive category from name
        name_lower = method.name.lower()
        if any(kw in name_lower for kw in ['static', 'analysis', 'code']):
            cat = "Static Analysis"
        elif any(kw in name_lower for kw in ['dynamic', 'runtime', 'debug']):
            cat = "Dynamic Analysis"
        elif any(kw in name_lower for kw in ['fuzz', 'crash']):
            cat = "Fuzzing"
        elif any(kw in name_lower for kw in ['exploit', 'attack']):
            cat = "Exploitation"
        elif any(kw in name_lower for kw in ['intel', 'enum', 'discover']):
            cat = "Intelligence"
        else:
            cat = "General"

        if cat not in categories:
            categories[cat] = []
        categories[cat].append(method)

    for category, methods in sorted(categories.items()):
        lines.append(f"## {category}")
        lines.append("")

        for method in methods:
            lines.append(f"### {method.name}")
            lines.append("")

            # Add truncated description
            desc = method.description.strip()
            if desc:
                lines.append(desc)
                lines.append("")

            # Add steps if available
            if method.steps:
                lines.append("**Steps:**")
                for i, step in enumerate(method.steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

        lines.append("---")
        lines.append("")

    return '\n'.join(lines)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main integration workflow."""
    base_path = Path(__file__).parent.parent.parent  # layer1/lib -> root

    print("=" * 60)
    print("Ingest Integration Script")
    print("=" * 60)
    print()

    # Scan ingest directory
    content = scan_ingest_directory(base_path)

    print()
    print(f"Found {len(content.tools)} tool entries")
    print(f"Found {len(content.methodologies)} methodology sections")
    print(f"Found {len(content.skills)} skill entries")
    print()

    # Deduplicate
    unique_tools = deduplicate_tools(content.tools)
    print(f"After deduplication: {len(unique_tools)} unique tools")
    print()

    # Generate outputs
    output_dir = base_path / "docs" / "integrated"
    output_dir.mkdir(exist_ok=True)

    # Write tool additions
    tool_additions = generate_toolset_additions(unique_tools)
    tool_file = output_dir / "tools-integrated.md"
    tool_file.write_text(tool_additions)
    print(f"Wrote tool additions to {tool_file}")

    # Write methodology additions
    method_additions = generate_methodology_additions(content.methodologies)
    method_file = output_dir / "methodologies-integrated.md"
    method_file.write_text(method_additions)
    print(f"Wrote methodology additions to {method_file}")

    # Write raw extraction for review
    raw_file = output_dir / "extraction-raw.json"
    raw_data = {
        "tools": [{"name": t.name, "purpose": t.purpose, "category": t.category}
                  for t in unique_tools],
        "methodologies": [{"name": m.name, "category": m.category}
                         for m in content.methodologies],
        "skills": content.skills,
        "stats": {
            "total_tools_found": len(content.tools),
            "unique_tools": len(unique_tools),
            "methodologies": len(content.methodologies),
            "skills": len(content.skills),
        }
    }
    raw_file.write_text(json.dumps(raw_data, indent=2))
    print(f"Wrote raw extraction to {raw_file}")

    print()
    print("=" * 60)
    print("Integration complete!")
    print()
    print("Next steps:")
    print("1. Review layer2-templates/reference/integrated/tools-integrated.md")
    print("2. Review layer2-templates/reference/integrated/methodologies-integrated.md")
    print("3. Manually merge desired content into toolset.md")
    print("4. Delete layer3-engagement/ingest/ when satisfied")
    print("=" * 60)

if __name__ == "__main__":
    main()
