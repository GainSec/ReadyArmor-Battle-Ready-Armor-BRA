"""IntelWriter - Flexible markdown writer for INTEL.md and LEADS.md.

Handles mechanical capture of discoveries:
- Appends to existing tables by matching column headers
- Creates new dated sections when no matching table exists
- Writes suggestions and leads to LEADS.md
- Deduplicates entries
- Captures raw command output

Note: Findings are written directly by the agent to FINDINGS.md
using the format defined in findings-schema.md. IntelWriter only
maintains the summary table in INTEL.md.
"""

import re
import hashlib
import fcntl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class IntelWriter:
    """Section-aware writer for INTEL.md and related files."""

    # Section headers to look for
    SECTIONS = {
        "target": "## Target Profile",
        "service": "## Port Scan Results",
        "endpoint": "## Discovered Endpoints",
        "finding": "## Vulnerabilities",
        "credential": "## Credentials",
    }

    # Templates for on-the-fly section creation (header, columns, separator)
    SECTION_TEMPLATES = {
        "target": ("## Target Profile", "| Property | Value | Source |", "|----------|-------|--------|"),
        "service": ("## Port Scan Results", "| Port | State | Service | Version | Source |", "|------|-------|---------|---------|--------|"),
        "endpoint": ("## Discovered Endpoints", "| Path | Method | Function | Risk | Status | Source |", "|------|--------|----------|------|--------|--------|"),
        "finding": ("## Vulnerabilities", "| ID | Title | Severity | CVSS | Status | Source |", "|----|-------|----------|------|--------|--------|"),
        "credential": ("## Credentials", "| Credential | Description | Detail | Source |", "|------------|-------------|--------|--------|"),
    }

    # Baseline headers for append_entry() — maps category to (section_key, section_title, column_headers)
    BASELINE_HEADERS: dict[str, tuple[str, str, list[str]]] = {
        "SERVICE": ("service", "## Port Scan Results", ["Port", "State", "Service", "Version", "Source"]),
        "ENDPOINT": ("endpoint", "## Discovered Endpoints", ["Path", "Method", "Function", "Risk", "Status", "Source"]),
        "TARGET": ("target", "## Target Profile", ["Property", "Value", "Source"]),
        "FINDING": ("finding", "## Vulnerabilities", ["ID", "Title", "Severity", "CVSS", "Status", "Source"]),
        "CREDENTIAL": ("credential", "## Credentials", ["Credential", "Description", "Detail", "Source"]),
    }

    # Aliases: common dynamic marker categories → baseline category they should merge into.
    # Agents emit varying marker names; this ensures data lands in the right section.
    CATEGORY_ALIASES: dict[str, str] = {
        "PROPERTY": "TARGET",
        "TARGET_PROPERTY": "TARGET",
        "HOST": "TARGET",
        "VERSION": "TARGET",
        "CONFIG": "TARGET",
        "SECRET": "CREDENTIAL",
        "CRED": "CREDENTIAL",
    }

    def __init__(self, notes_dir: Path, bra_dir: Path | None = None):
        """Initialize writer.

        Args:
            notes_dir: Path to NOTES directory containing INTEL.md, FINDINGS.md, LEADS.md
            bra_dir: Path to .bra directory for sidecar access (resolved from config if None)
        """
        self.notes_dir = Path(notes_dir)
        self.intel_path = self.notes_dir / "INTEL.md"
        self.leads_path = self.notes_dir / "LEADS.md"
        self.seen_path = self.notes_dir / ".seen_entries.txt"

        # Copy class-level dicts so dynamic registrations are per-instance
        self.SECTIONS = dict(IntelWriter.SECTIONS)
        self.BASELINE_HEADERS = dict(IntelWriter.BASELINE_HEADERS)
        self.SECTION_TEMPLATES = dict(IntelWriter.SECTION_TEMPLATES)
        self.CATEGORY_ALIASES = dict(IntelWriter.CATEGORY_ALIASES)

        if bra_dir is not None:
            self._bra_dir = Path(bra_dir)
        else:
            try:
                from bra.config.settings import BRA_STATE
                self._bra_dir = BRA_STATE
            except Exception:
                self._bra_dir = None

        # Load seen entries for deduplication
        self._seen: set[str] = set()
        self._load_seen()

        # Track finding and suggestion IDs
        self._next_finding_id = self._detect_next_finding_id()
        self._next_suggestion_id = self._detect_next_lead_id()

    def _load_seen(self) -> None:
        """Load previously seen entries."""
        if self.seen_path.exists():
            self._seen = set(self.seen_path.read_text().strip().split('\n'))

    def _save_seen(self, entry_hash: str) -> None:
        """Save a new seen entry."""
        self._seen.add(entry_hash)
        with open(self.seen_path, 'a') as f:
            f.write(entry_hash + '\n')

    def _read_sidecar(self) -> str:
        """Read and consume last_capture.json sidecar.

        Returns:
            Formatted source string, or empty string if no sidecar
        """
        if not self._bra_dir:
            return ""

        import json
        sidecar = self._bra_dir / "last_capture.json"
        if not sidecar.exists():
            return ""

        try:
            data = json.loads(sidecar.read_text())
            # Sidecar is NOT deleted; it's overwritten by the next tool execution
            # and serves as a shared provenance resource for other code paths.
            path = data.get("path", "")
            if path:
                return path
            # Fallback to command if no artifact path recorded
            return data.get("command", "")
        except Exception:
            return ""

    def _hash_entry(self, *parts: str) -> str:
        """Create hash for deduplication."""
        content = '|'.join(str(p) for p in parts)
        return hashlib.md5(content.encode()).hexdigest()[:16]

    @staticmethod
    def _format_source(
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> str:
        """Build a deterministic source string with optional provenance tokens."""
        parts: list[str] = []
        if source:
            parts.append(source.strip())
        if capture_id and capture_id != "provided_info":
            parts.append(f"capture_id:{capture_id}")
        if source_kind and source_kind != "provided_info":
            parts.append(f"source_kind:{source_kind}")
        return " ; ".join(parts)

    def _detect_next_finding_id(self) -> int:
        """Detect the next finding ID from existing INTEL.md."""
        if not self.intel_path.exists():
            return 1

        content = self.intel_path.read_text()
        # Find all existing IDs like "| 001 |" or "| 012 |"
        matches = re.findall(r'\|\s*(\d{3})\s*\|', content)
        if matches:
            return max(int(m) for m in matches) + 1
        return 1

    def _detect_next_lead_id(self) -> int:
        """Detect the next lead/suggestion ID from existing LEADS.md."""
        if not self.leads_path.exists():
            return 1

        content = self.leads_path.read_text()
        # Find all existing IDs like "| 001 |" or "| 012 |"
        matches = re.findall(r'\|\s*(\d{3})\s*\|', content)
        if matches:
            return max(int(m) for m in matches) + 1
        return 1

    def _find_section_end(self, content: str, section_header: str) -> int:
        """Find the position to insert after a section's table.

        Args:
            content: Full file content
            section_header: Header like "## Target Profile"

        Returns:
            Position to insert new row
        """
        idx = content.find(section_header)
        if idx == -1:
            return -1

        # Find the table after this header
        lines = content[idx:].split('\n')
        pos = idx
        in_table = False
        last_table_line_end = -1

        for line in lines:
            if line.startswith('|'):
                in_table = True
                last_table_line_end = pos + len(line)
            elif in_table and not line.startswith('|'):
                # End of table
                break
            pos += len(line) + 1  # +1 for newline

        return last_table_line_end if last_table_line_end > 0 else -1

    def _insert_table_row(
        self,
        section_key: str,
        row: str,
        dynamic_header: str | None = None,
        dynamic_columns: list[str] | None = None,
    ) -> bool:
        """Insert a row into a section's table.

        If the section doesn't exist, creates it on-the-fly with headers.

        Args:
            section_key: Key from SECTIONS dict OR a dynamic key
            row: Formatted table row including | delimiters
            dynamic_header: Section header for dynamic categories (e.g., "## Firmware")
            dynamic_columns: Column names for dynamic categories

        Returns:
            True if inserted, False if section key is unknown and no dynamic info
        """
        section_header = self.SECTIONS.get(section_key) or dynamic_header
        if not section_header:
            return False

        # Ensure INTEL.md exists
        if not self.intel_path.exists():
            self.intel_path.write_text("# INTEL.md\n\n")

        with open(self.intel_path, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                content = f.read()

                insert_pos = self._find_section_end(content, section_header)
                if insert_pos == -1:
                    # Section doesn't exist — create it on-the-fly
                    template = self.SECTION_TEMPLATES.get(section_key)
                    if template:
                        header, col_header, separator = template
                    elif dynamic_header and dynamic_columns:
                        header = dynamic_header
                        col_header = "| " + " | ".join(dynamic_columns) + " |"
                        separator = "|" + "|".join("------" for _ in dynamic_columns) + "|"
                    else:
                        return False

                    new_section = f"\n{header}\n\n{col_header}\n{separator}\n{row}\n"
                    content = content.rstrip() + "\n" + new_section
                else:
                    # Insert into existing table
                    content = content[:insert_pos] + '\n' + row + content[insert_pos:]

                f.seek(0)
                f.write(content)
                f.truncate()
                return True
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def append_entry(
        self,
        category: str,
        fields: list[str],
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Generic entry writer — dynamic section/table creation.

        Handles both baseline categories (SERVICE, ENDPOINT, etc.) and
        arbitrary new categories (USB_DEVICE, FIRMWARE, etc.).

        Args:
            category: Marker category (e.g., "SERVICE", "USB_DEVICE")
            fields: List of field values from the marker
            source: Optional source attribution
        """
        # Auto-fill source from sidecar if empty
        source_value = self._format_source(source, capture_id, source_kind)
        if not source_value:
            source_value = self._format_source(self._read_sidecar(), capture_id, source_kind)

        # Dedup hashes ALL fields and provenance context
        entry_hash = self._hash_entry(category, *fields, source_value)
        if entry_hash in self._seen:
            return

        # Resolve aliases (e.g., PROPERTY → TARGET, SECRET → CREDENTIAL)
        effective = self.CATEGORY_ALIASES.get(category, category)
        baseline = self.BASELINE_HEADERS.get(effective)

        if baseline:
            section_key, section_title, col_names = baseline
            # Pad or trim fields to match expected column count (minus Source col).
            # Overflow: if more fields than data columns, merge extras into last col.
            data_cols = len(col_names) - 1  # Last column is Source
            padded = list(fields[:data_cols])
            if len(fields) > data_cols:
                overflow = ", ".join(fields[data_cols:])
                padded[-1] = (padded[-1] + ", " + overflow) if padded[-1] else overflow
            while len(padded) < data_cols:
                padded.append("")
            source_col = f" {source_value} " if source_value else " "
            row = "| " + " | ".join(padded) + f" |{source_col}|"
            if self._insert_table_row(section_key, row):
                self._save_seen(entry_hash)
        else:
            # Dynamic category — create section on-the-fly
            section_title = self._category_to_title(category)
            # Generate meaningful column names (never blank)
            if len(fields) == 1:
                col_names = ["Entry"]
            elif len(fields) == 2:
                col_names = ["Property", "Value"]
            else:
                col_names = ["Property", "Value"] + [
                    f"Detail {i}" for i in range(1, len(fields) - 1)
                ]
            if source_value:
                col_names.append("Source")

            # Pad fields to match column count (same as baseline path)
            # so Source always lands in the last column.
            data_cols = len(col_names) - (1 if source_value else 0)
            padded = list(fields[:data_cols])
            while len(padded) < data_cols:
                padded.append("")
            source_col = f" {source_value} " if source_value else ""
            row = "| " + " | ".join(padded) + (f" |{source_col}|" if source_value else " |")

            # Use a dynamic key that won't collide with SECTIONS
            dynamic_key = f"_dyn_{category.lower()}"
            if self._insert_table_row(
                dynamic_key,
                row,
                dynamic_header=section_title,
                dynamic_columns=col_names,
            ):
                # Register as baseline so subsequent entries get proper
                # column padding (source stays in last column).
                self.SECTIONS[dynamic_key] = section_title
                self.BASELINE_HEADERS[category] = (dynamic_key, section_title, col_names)
                self._save_seen(entry_hash)

    @staticmethod
    def _category_to_title(category: str) -> str:
        """Convert a category like USB_DEVICE to a section title like '## Usb Devices'.

        Args:
            category: Upper-case category name

        Returns:
            Markdown section header
        """
        words = category.replace("_", " ").title()
        # Pluralize simple cases with a y->ies rule for natural headings.
        if words.endswith("y") and len(words) > 1 and words[-2].lower() not in "aeiou":
            words = words[:-1] + "ies"
        elif not words.endswith("s"):
            words += "s"
        return f"## {words}"

    def append_target(
        self,
        property: str,
        value: str,
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append to Target Profile section."""
        self.append_entry(
            "TARGET",
            [property, value],
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
        )

    def append_service(
        self,
        port: str,
        state: str,
        service: str,
        version: str,
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append to Port Scan Results section."""
        self.append_entry(
            "SERVICE",
            [port, state, service, version],
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
        )

    def append_endpoint(
        self,
        path: str,
        method: str,
        function: str,
        risk: str = "Unknown",
        status: str = "Untested",
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append to Discovered Endpoints section."""
        self.append_entry(
            "ENDPOINT",
            [path, method, function, risk, status],
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
        )

    def append_finding(
        self,
        severity: str,
        title: str,
        cvss: Optional[str] = None,
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> int:
        """Append finding summary row to INTEL.md table.

        Note: This only adds a summary row to INTEL.md. Full finding
        documentation should be written by the agent directly to
        FINDINGS.md using the findings-schema.md format.
        """
        source_value = self._format_source(source, capture_id, source_kind)
        if not source_value:
            source_value = self._format_source(self._read_sidecar(), capture_id, source_kind)

        entry_hash = self._hash_entry("finding", severity, title, source_value)
        if entry_hash in self._seen:
            return self._next_finding_id - 1

        finding_id = self._next_finding_id
        self._next_finding_id += 1

        sev_formatted = f"**{severity}**" if severity in ("CRITICAL", "HIGH") else severity
        cvss_str = cvss if cvss else "-"

        source_col = f" {source_value} " if source_value else " "
        row = f"| {finding_id:03d} | {title} | {sev_formatted} | {cvss_str} | Confirmed |{source_col}|"
        if self._insert_table_row("finding", row):
            self._save_seen(entry_hash)

        return finding_id

    def _ensure_leads_table(self) -> None:
        """Ensure LEADS.md has the leads table header."""
        if not self.leads_path.exists():
            self.leads_path.write_text(
                "# Leads\n\n> Investigation leads and suggestions.\n\n---\n\n"
                "| ID | Lead | Priority | Rationale | Status |\n"
                "|----|------|----------|-----------|--------|\n"
            )
            return

        content = self.leads_path.read_text()
        if "| ID | Lead |" not in content:
            with open(self.leads_path, 'a') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    f.write(
                        "\n| ID | Lead | Priority | Rationale | Status |\n"
                        "|----|------|----------|-----------|--------|\n"
                    )
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

    def _append_lead_row(
        self,
        description: str,
        priority: str,
        rationale: str,
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append a row to the leads table in LEADS.md."""
        provenance = self._format_source(source, capture_id, source_kind)
        rationale_value = rationale
        if provenance:
            rationale_value = f"{rationale_value} ; {provenance}" if rationale_value else provenance

        entry_hash = self._hash_entry("lead", description, priority, rationale_value)
        if entry_hash in self._seen:
            return

        self._ensure_leads_table()

        lead_id = self._next_suggestion_id
        self._next_suggestion_id += 1
        row = f"| {lead_id:03d} | {description} | {priority} | {rationale_value} | Open |\n"

        with open(self.leads_path, 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(row)
                self._save_seen(entry_hash)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def append_lead(
        self,
        description: str,
        priority: str = "Medium",
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append to LEADS.md."""
        self._append_lead_row(
            description,
            priority,
            "",
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
        )

    def append_suggestion(
        self,
        description: str,
        priority: str = "Medium",
        rationale: str = "",
        source: str = "",
        capture_id: str | None = None,
        source_kind: str | None = None,
    ) -> None:
        """Append to LEADS.md (suggestions are leads)."""
        self._append_lead_row(
            description,
            priority,
            rationale,
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
        )

    @staticmethod
    def _extract_tool_and_target(command: str) -> tuple[str, str]:
        """Extract tool name and target from a command string.

        Args:
            command: Full command string (e.g. "nmap -sV 192.168.18.9")

        Returns:
            Tuple of (tool, target) — target may be empty if not found
        """
        import shlex
        parts = shlex.split(command)
        tool = parts[0].split("/")[-1] if parts else "unknown"

        # Look for IP or hostname in args
        target = ""
        ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+(/\d+)?')
        for part in parts[1:]:
            if ip_pattern.match(part):
                target = part.replace("/", "_")
                break
            # hostname-like (contains dot, not a flag)
            if '.' in part and not part.startswith('-') and not part.startswith('http'):
                target = part
                break
            # URL — extract host
            if part.startswith('http'):
                from urllib.parse import urlparse
                host = urlparse(part).hostname or ""
                if host:
                    target = host
                    break

        return tool, target

    def append_raw_capture(
        self,
        command: str,
        output: str,
        artifacts_dir: Path | None = None,
        logs_dir: Path | None = None,
        bra_dir: Path | None = None,
        capture_id: str | None = None,
    ) -> Path | None:
        """Save raw command output to artifacts/raw/ and write audit log.

        Args:
            command: Command that was executed
            output: Command output
            artifacts_dir: Path to .bra/artifacts/ (resolved from config if None)
            logs_dir: Path to .bra/logs/ (resolved from config if None)
            bra_dir: Path to .bra/ for sidecar (resolved from config if None)
            capture_id: Optional correlation ID propagated across logs/artifacts

        Returns:
            Path to saved raw output file, or None on error
        """
        if artifacts_dir is None:
            from bra.config.settings import ARTIFACTS_DIR
            artifacts_dir = ARTIFACTS_DIR
        if logs_dir is None:
            from bra.config.settings import LOGS_DIR
            logs_dir = LOGS_DIR
        if bra_dir is None:
            from bra.config.settings import BRA_STATE
            bra_dir = BRA_STATE

        raw_dir = Path(artifacts_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Build filename: <tool>_<target>_<YYYYMMDD>_<HHMM>.txt
        tool, target = self._extract_tool_and_target(command)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        parts = []
        if capture_id:
            parts.append(capture_id)
        parts.append(tool)
        if target:
            parts.append(target)
        parts.append(timestamp)
        filename = "_".join(parts) + ".txt"
        output_path = raw_dir / filename

        # Save raw output
        output_path.write_text(output)

        # Append to captures.log
        log_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        capture_token = capture_id or ""
        log_line = f"{log_ts} | {capture_token} | {command} | {output_path}\n"
        captures_log = Path(logs_dir) / "captures.log"
        with open(captures_log, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(log_line)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        # Write sidecar for append_entry handoff
        import json
        sidecar = Path(bra_dir) / "last_capture.json"
        sidecar.write_text(json.dumps({
            "command": command,
            "path": str(output_path),
            "capture_id": capture_id or "",
        }))

        return output_path
