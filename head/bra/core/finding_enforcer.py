"""FindingEnforcer - Mechanical enforcement of finding documentation.

When the runner detects a [FINDING] marker, this module:
1. Queues the finding for documentation
2. Blocks all non-documentation tool calls
3. Validates finding records against findings-schema.md
4. Verifies evidence file existence and hash integrity

ENFORCEMENT LAYERS:
- Layer 1 (this module): Tool-call interception in the runner
- Layer 2 (finding_guard hook): Defense-in-depth bash/Python gate
- Layer 3 (file_hook.py): INTEL↔FINDINGS cross-check
- Layer 4 (FindingsAudit): Post-session integrity verification
"""

import json
import hashlib
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from bra.core.capture_provenance import resolve_capture


@dataclass
class PendingFinding:
    """A finding that requires documentation in FINDINGS.md."""
    id: str
    severity: str
    title: str
    source_marker: str
    queued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "source_marker": self.source_marker,
            "queued_at": self.queued_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PendingFinding":
        return cls(
            id=data["id"],
            severity=data["severity"],
            title=data["title"],
            source_marker=data["source_marker"],
            queued_at=data.get("queued_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ValidationResult:
    """Result of validating a finding record."""
    valid: bool
    missing_fields: list[str]
    errors: list[str]


class FindingEnforcer:
    """Mechanical enforcement of finding documentation."""
    FASTPATH_TOKEN = "FINDINGS-FASTPATH"
    SLOWPATH_TOKEN = "SLOWPATH-FINDINGS"
    SYSTEM_MANAGED_SECTIONS = (
        "Affected Artifact",
        "Reproduction Steps",
        "Proof of Concept",
        "Observed Evidence",
    )

    def __init__(self, notes_dir: Path, bra_state_dir: Path):
        self.notes_dir = Path(notes_dir)
        self.bra_state_dir = Path(bra_state_dir)
        self.pending_file = self.bra_state_dir / "pending_findings.json"
        self.findings_path = self.notes_dir / "FINDINGS.md"
        self.intel_path = self.notes_dir / "INTEL.md"
        self.reqs_dir = self.notes_dir / "reqs"

        self.pending_queue: list[PendingFinding] = []
        self._completed_ids: set[str] = set()

        self._load_queue()
        for pending in self.pending_queue:
            self._seed_finding_skeleton(pending)

    def _load_queue(self) -> None:
        """Load pending findings and completed ID set from JSON file."""
        if self.pending_file.exists():
            try:
                data = json.loads(self.pending_file.read_text())
                if isinstance(data, list):
                    # Legacy format: plain list of pending findings
                    self.pending_queue = [PendingFinding.from_dict(d) for d in data]
                    self._completed_ids = set()
                else:
                    self.pending_queue = [PendingFinding.from_dict(d) for d in data.get("pending", [])]
                    self._completed_ids = set(data.get("completed_ids", []))
            except (json.JSONDecodeError, KeyError):
                self.pending_queue = []
                self._completed_ids = set()

    def _save_queue(self) -> None:
        """Save pending findings and completed ID set to JSON file."""
        self.bra_state_dir.mkdir(parents=True, exist_ok=True)
        self.pending_file.write_text(
            json.dumps(
                {
                    "pending": [pf.to_dict() for pf in self.pending_queue],
                    "completed_ids": sorted(self._completed_ids),
                },
                indent=2,
            )
        )

    @staticmethod
    def _normalize_title(title: str) -> str:
        """Normalize finding titles for stable dedupe/comparison."""
        return " ".join(str(title or "").strip().lower().split())

    @staticmethod
    def _normalize_finding_id(finding_id: str) -> str:
        """Normalize finding IDs to zero-padded 3-digit format when numeric."""
        text = str(finding_id or "").strip()
        return text.zfill(3) if text.isdigit() else text

    _PLACEHOLDER_PATTERN = re.compile(r"\{\{PENDING:[^}]+\}\}")
    _PLACEHOLDER_KEY_PATTERN = re.compile(r"\{\{PENDING:([^}]+)\}\}")
    _LIKELIHOOD_LEVEL_PATTERN = re.compile(
        r"\b(critical|high|medium|med|low|info|informational)\b",
        re.IGNORECASE,
    )

    def _has_placeholder_tokens(self, text: str) -> bool:
        """Check whether text still contains unresolved skeleton placeholders."""
        return bool(self._PLACEHOLDER_PATTERN.search(text or ""))

    def _token_enabled(self, token_name: str) -> bool:
        """Return True when a governance token file exists under approvals/."""
        approvals_dir = self.bra_state_dir / "approvals"
        if not approvals_dir.exists():
            return False
        candidates = (
            token_name,
            token_name.replace("-", "_"),
        )
        return any((approvals_dir / name).exists() for name in candidates)

    def is_slowpath_enabled(self) -> bool:
        """Return True when SLOWPATH-FINDINGS governance token is enabled."""
        return self._token_enabled(self.SLOWPATH_TOKEN)

    def is_fastpath_enabled(self) -> bool:
        """Return True when findings deterministic fastpath governance token is enabled."""
        if self.is_slowpath_enabled():
            # Slowpath explicitly disables fastpath short-circuit behavior.
            return False
        return self._token_enabled(self.FASTPATH_TOKEN)

    def _workspace_root(self) -> Path:
        """Best-effort workspace root used to resolve relative evidence paths."""
        if self.notes_dir.parent.name == "layer3-engagement":
            return self.notes_dir.parent.parent
        return self.notes_dir.parent

    @staticmethod
    def _extract_sha256(text: str) -> str | None:
        """Extract first SHA256 hash from text, normalized to lowercase."""
        match = re.search(r"\b([0-9a-fA-F]{64})\b", text or "")
        if not match:
            return None
        return match.group(1).lower()

    @staticmethod
    def _clean_path_token(path_text: str) -> str:
        """Normalize markdown-wrapped path tokens for filesystem resolution."""
        cleaned = (path_text or "").strip().strip("`").strip("'").strip('"')
        cleaned = cleaned.rstrip(".,);]")
        return cleaned.strip("*")

    def _resolve_record_path(self, path_text: str) -> Path:
        """Resolve a path mentioned in FINDINGS.md to a concrete local path."""
        cleaned = self._clean_path_token(path_text)
        if not cleaned:
            return Path("")

        raw_path = Path(cleaned)
        if raw_path.is_absolute():
            if raw_path.exists():
                return raw_path

            raw_posix = raw_path.as_posix()
            workspace_root = self._workspace_root()
            remap_suffixes = (
                "/body/.bra/",
                "/body/layer3-engagement/",
                "/.bra/",
                "/layer3-engagement/",
            )
            for suffix in remap_suffixes:
                if suffix not in raw_posix:
                    continue
                relative = raw_posix.split(suffix, 1)[1]
                if suffix.startswith("/body/"):
                    prefix = "body/.bra/" if "/.bra/" in suffix else "body/layer3-engagement/"
                else:
                    prefix = ".bra/" if suffix == "/.bra/" else "layer3-engagement/"
                remapped = workspace_root / prefix / relative
                if remapped.exists():
                    return remapped
            return raw_path

        candidates: list[Path] = []
        workspace_root = self._workspace_root()
        candidates.append(workspace_root / cleaned)

        if cleaned.startswith("layer3-engagement/NOTES/"):
            suffix = cleaned.split("layer3-engagement/NOTES/", 1)[1]
            candidates.append(self.notes_dir / suffix)
        if cleaned.startswith("NOTES/"):
            suffix = cleaned.split("NOTES/", 1)[1]
            candidates.append(self.notes_dir / suffix)
        if cleaned.startswith("reqs/"):
            suffix = cleaned.split("reqs/", 1)[1]
            candidates.append(self.reqs_dir / suffix)

        candidates.append(self.notes_dir / cleaned)
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    @staticmethod
    def _sha256_for_file(path: Path) -> str:
        """Calculate SHA256 hash for a file."""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _extract_finding_slice(self, content: str, finding_id: str) -> tuple[int, int, str] | None:
        """Return (start, end, finding_content) for a finding record."""
        pattern = rf"## \[FINDING-{re.escape(finding_id)}\]"
        match = re.search(pattern, content)
        if not match:
            return None

        start = match.start()
        next_finding = re.search(r"\n## \[FINDING-", content[start + 1:])
        if next_finding:
            end = start + 1 + next_finding.start()
        else:
            end = len(content)
        return start, end, content[start:end]

    def _extract_section_content(self, finding_content: str, section_name: str) -> str:
        """Extract markdown section body for a `### <section_name>` heading."""
        section_match = re.search(
            rf"###\s+{re.escape(section_name)}\s*([\s\S]*?)(?:\n###\s+|\Z)",
            finding_content,
            re.IGNORECASE,
        )
        if not section_match:
            return ""
        return section_match.group(1).strip()

    def _extract_artifact_hash(self, finding_content: str) -> str | None:
        """Extract Artifact Hash value from a finding section."""
        for line in finding_content.splitlines():
            if "artifact hash" in line.lower():
                hash_value = self._extract_sha256(line)
                if hash_value:
                    return hash_value
        return None

    def _extract_artifact_hash_value(self, finding_content: str) -> str:
        """Extract raw Artifact Hash field value (hash text, N/A, marker, etc.)."""
        affected_section = self._extract_section_content(finding_content, "Affected Artifact")
        search_space = affected_section or finding_content
        table_match = re.search(
            r"^\|\s*\*\*Artifact Hash(?:\s*\(SHA256\))?\*\*\s*\|\s*([^\n|]*)",
            search_space,
            re.IGNORECASE | re.MULTILINE,
        )
        if table_match:
            return self._clean_path_token(table_match.group(1))
        for line in search_space.splitlines():
            if "artifact hash" not in line.lower():
                continue
            value = line.split(":", 1)[1] if ":" in line else line
            return self._clean_path_token(value)
        return ""

    def _is_na_hash_marker(self, value: str) -> bool:
        """Return True when artifact hash explicitly states N/A."""
        normalized = self._clean_path_token(value).lower().replace(".", "")
        return normalized in self._NA_HASH_MARKERS

    def _extract_artifact_location_local_paths(self, finding_content: str) -> list[str]:
        """Extract local artifact paths referenced in Artifact Location fields."""
        affected_section = self._extract_section_content(finding_content, "Affected Artifact")
        search_space = affected_section or finding_content
        local_paths: list[str] = []

        for match in re.finditer(r"Local:\s*`?([^`\n|;]+)`?", search_space, re.IGNORECASE):
            token = self._clean_path_token(match.group(1))
            if token:
                local_paths.append(token)

        if not local_paths:
            for line in search_space.splitlines():
                if "artifact location" not in line.lower():
                    continue
                segment = line.split(":", 1)[1] if ":" in line else ""
                inline_tick = re.search(r"`([^`\n]+)`", segment)
                if inline_tick:
                    token = self._clean_path_token(inline_tick.group(1))
                else:
                    token = self._clean_path_token(segment)
                if token and "/" in token and "local:" not in token.lower():
                    local_paths.append(token)

        deduped: list[str] = []
        seen: set[str] = set()
        for path in local_paths:
            if path not in seen:
                deduped.append(path)
                seen.add(path)
        return deduped

    def _extract_artifact_location_descriptor(self, finding_content: str) -> str:
        """Extract descriptor text from Artifact Location for fallback hashing."""
        affected_section = self._extract_section_content(finding_content, "Affected Artifact")
        search_space = affected_section or finding_content

        table_match = re.search(
            r"^\|\s*\*\*Artifact Location\*\*\s*\|\s*([^\n|]+?)\s*(?:\||$)",
            search_space,
            re.IGNORECASE | re.MULTILINE,
        )
        if table_match:
            return self._clean_path_token(table_match.group(1))

        for line in search_space.splitlines():
            if "artifact location" not in line.lower():
                continue
            segment = line.split(":", 1)[1] if ":" in line else ""
            inline_tick = re.search(r"`([^`\n]+)`", segment)
            if inline_tick:
                token = self._clean_path_token(inline_tick.group(1))
            else:
                token = self._clean_path_token(segment)
            if token:
                return token
        return ""

    @staticmethod
    def _hash_text(value: str) -> str:
        """Calculate SHA256 for arbitrary text."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _is_bra_scoped_path(self, path_text: str) -> bool:
        """Check whether a referenced artifact path is in BRA project scope."""
        cleaned = self._clean_path_token(path_text).lower()
        if not cleaned:
            return False

        if cleaned.startswith(("layer3-engagement/", "notes/", "reqs/", ".bra/")):
            return True
        if "/layer3-engagement/" in cleaned or "/.bra/" in cleaned:
            return True
        return False

    def _upsert_artifact_hash(self, finding_content: str, sha256_hash: str) -> str:
        """Update or insert Artifact Hash field for a finding section."""
        updated = finding_content

        table_pattern = re.compile(
            r"(^\|\s*\*\*Artifact Hash(?:\s*\(SHA256\))?\*\*\s*\|\s*)([^|\n]*)(\|.*$)",
            re.IGNORECASE | re.MULTILINE,
        )
        if table_pattern.search(updated):
            return table_pattern.sub(rf"\1`{sha256_hash}` \3", updated, count=1)

        # If Affected Artifact uses a metadata table but hash row is missing,
        # insert a canonical hash row immediately after Artifact Location.
        table_location_pattern = re.compile(
            r"(^\|\s*\*\*Artifact Location\*\*\s*\|[^\n]*\n)",
            re.IGNORECASE | re.MULTILINE,
        )
        table_location_match = table_location_pattern.search(updated)
        if table_location_match:
            insert_at = table_location_match.end()
            hash_row = f"| **Artifact Hash (SHA256)** | `{sha256_hash}` |\n"
            return updated[:insert_at] + hash_row + updated[insert_at:]

        line_pattern = re.compile(
            r"(^\*\*Artifact Hash(?:\s*\(SHA256\))?\*\*:\s*)(.*$)",
            re.IGNORECASE | re.MULTILINE,
        )
        if line_pattern.search(updated):
            return line_pattern.sub(rf"\1`{sha256_hash}`", updated, count=1)

        # Inline Artifact Location variant (single line with Original + Local).
        inline_location_pattern = re.compile(
            r"(?im)^(\*\*Artifact Location(?:\s*\(.*\))?\*\*:\s*.*)$"
        )
        inline_location_match = inline_location_pattern.search(updated)
        if inline_location_match:
            insert_at = inline_location_match.end()
            return (
                updated[:insert_at]
                + f"\n**Artifact Hash:** `{sha256_hash}`"
                + updated[insert_at:]
            )

        location_line = re.search(r"(?im)^(?:-\s*)?Local:\s*.*$", updated)
        if location_line:
            insert_at = location_line.end()
            return (
                updated[:insert_at]
                + f"\n**Artifact Hash:** `{sha256_hash}`"
                + updated[insert_at:]
            )

        return updated

    def _autofill_artifact_hash(self, finding_id: str) -> bool:
        """Auto-populate Artifact Hash from local artifact bytes or descriptor text."""
        if not self.findings_path.exists():
            return False

        content = self.findings_path.read_text()
        finding_slice = self._extract_finding_slice(content, finding_id)
        if not finding_slice:
            return False

        start, end, finding_content = finding_slice
        local_paths = self._extract_artifact_location_local_paths(finding_content)
        bra_paths = [path for path in local_paths if self._is_bra_scoped_path(path)]

        sha256_hash = ""
        if bra_paths:
            resolved_paths = [self._resolve_record_path(path_text) for path_text in bra_paths]
            existing_paths = [path for path in resolved_paths if path.exists()]
            if existing_paths:
                sha256_hash = self._sha256_for_file(existing_paths[0])
        else:
            descriptor = self._extract_artifact_location_descriptor(finding_content)
            if descriptor and not self._has_placeholder_tokens(descriptor):
                sha256_hash = self._hash_text(descriptor)

        if not sha256_hash:
            return False

        updated_finding = self._upsert_artifact_hash(finding_content, sha256_hash)
        if updated_finding == finding_content:
            return False

        updated_content = content[:start] + updated_finding + content[end:]
        self.findings_path.write_text(updated_content)
        return True

    def _build_finding_skeleton(self, finding: PendingFinding) -> str:
        """Build canonical full-schema skeleton for a finding record."""
        finding_id = self._normalize_finding_id(finding.id)
        title = " ".join((finding.title or "").strip().split()) or "Untitled Finding"
        severity = str(finding.severity or "INFO").upper()
        poc_path = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-poc.sh"
        evidence_path = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-evidence.txt"
        placeholder = lambda key: f"{{{{PENDING:{key}}}}}"

        # Pre-populate severity-appropriate CVSS defaults so the subagent
        # has a realistic starting point instead of defaulting to 0.0/None.
        default_score, default_vector, default_label, default_likelihood = (
            self._default_cvss_for_severity(severity)
        )

        # Extract known values from source_marker to avoid creating placeholders
        # the subagent must re-derive from data the marker already provides.
        _marker_cvss: str | None = None
        _marker_attack_surface: str | None = None
        if finding.source_marker:
            _cvss_m = re.search(r'\bcvss:\s*([\d.]+)', finding.source_marker, re.IGNORECASE)
            _atk_m = re.search(r'\battack_surface:\s*([^|\n]+)', finding.source_marker, re.IGNORECASE)
            if _cvss_m:
                _marker_cvss = _cvss_m.group(1).strip()
            if _atk_m:
                _marker_attack_surface = _atk_m.group(1).strip()
        cvss_score_val = _marker_cvss or placeholder('CVSS_SCORE')
        attack_surface_val = _marker_attack_surface or placeholder('ATTACK_SURFACE')

        return (
            f"## [FINDING-{finding_id}] {title}\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **ID** | FINDING-{finding_id} |\n"
            f"| **Title** | {title} |\n"
            f"| **Severity** | {severity} |\n"
            f"| **CVSS** | {cvss_score_val} |\n"
            f"| **CWE** | {placeholder('CWE_ID')} |\n"
            f"| **Status** | Open |\n\n"
            f"### Affected Artifact\n\n"
            f"**Artifact:** `{placeholder('ARTIFACT_PATH_OR_URL')}`\n"
            f"**Artifact Location:**\n"
            f"- Original: `{placeholder('ORIGINAL_LOCATION')}`\n"
            f"- Local: `{placeholder('LOCAL_ARTIFACT_PATH')}`\n"
            f"**Artifact Hash:** `N/A`\n\n"
            f"### Description\n\n"
            f"{placeholder('DESCRIPTION')}\n\n"
            f"### Impact\n\n"
            f"{placeholder('IMPACT')}\n\n"
            f"### Attack Vector\n\n"
            f"{placeholder('ATTACK_VECTOR')}\n\n"
            f"### Reproduction Steps\n\n"
            f"**Environment:**\n"
            f"- {placeholder('ENVIRONMENT')}\n\n"
            f"**Steps:**\n"
            f"```bash\n"
            f"{placeholder('REPRO_STEPS')}\n"
            f"```\n\n"
            f"### Proof of Concept\n\n"
            f"- **Description:** {placeholder('POC_DESCRIPTION')}\n"
            f"- **Location:** `{poc_path}`\n"
            f"- **Note:** Not weaponized\n\n"
            f"### Observed Evidence\n\n"
            f"| Evidence | Location | Hash | Timestamp | Tool/Version |\n"
            f"|----------|----------|------|-----------|--------------|\n"
            f"| {placeholder('EVIDENCE_TYPE')} | `{evidence_path}` | `N/A` | {placeholder('EVIDENCE_TIMESTAMP')} | {placeholder('EVIDENCE_TOOL')} |\n\n"
            f"### Severity\n\n"
            f"**CVSS Vector:** `{default_vector}`\n"
            f"**CVSS Score:** {default_score} ({default_label})\n\n"
            f"### Likelihood\n\n"
            f"{default_likelihood}\n\n"
            f"### Remediation\n\n"
            f"{placeholder('REMEDIATION')}\n\n"
            f"### Attack Surface\n\n"
            f"{attack_surface_val}\n\n"
            f"### Tools & Versions\n\n"
            f"- {placeholder('TOOLS_AND_VERSIONS')}\n"
        )

    def _seed_finding_skeleton(self, finding: PendingFinding) -> bool:
        """Append a canonical finding block if one does not already exist."""
        finding_id = self._normalize_finding_id(finding.id)
        if not self.findings_path.exists():
            self.findings_path.parent.mkdir(parents=True, exist_ok=True)
            self.findings_path.write_text("# Findings\n\n---\n")

        content = self.findings_path.read_text()
        if self._extract_finding_slice(content, finding_id):
            return False

        block = self._build_finding_skeleton(finding)
        updated = content.rstrip() + "\n\n" + block + "\n"
        self.findings_path.write_text(updated)
        return True

    def _normalize_likelihood_for_finding(self, finding_id: str) -> bool:
        """Normalize Likelihood section to a single level value."""
        if not self.findings_path.exists():
            return False
        content = self.findings_path.read_text()
        finding_slice = self._extract_finding_slice(content, finding_id)
        if not finding_slice:
            return False
        start, end, finding_content = finding_slice

        def _normalize_level(raw: str) -> str:
            token = (raw or "").strip().lower()
            mapping = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "med": "Medium",
                "low": "Low",
                "info": "Info",
                "informational": "Info",
            }
            return mapping.get(token, "")

        changed = False
        pattern = re.compile(r"(###\s+Likelihood\s*\n)(.*?)(?=\n###\s+|\Z)", re.IGNORECASE | re.DOTALL)

        def repl(match: re.Match[str]) -> str:
            nonlocal changed
            heading = match.group(1)
            body = match.group(2)
            level_match = self._LIKELIHOOD_LEVEL_PATTERN.search(body or "")
            if not level_match:
                return match.group(0)
            normalized_level = _normalize_level(level_match.group(1))
            if not normalized_level:
                return match.group(0)
            canonical = f"{heading}\n{normalized_level}\n"
            if canonical != match.group(0):
                changed = True
            return canonical

        updated_finding = pattern.sub(repl, finding_content, count=1)
        if not changed:
            return False
        self.findings_path.write_text(content[:start] + updated_finding + content[end:])
        return True

    @staticmethod
    def _default_cvss_for_severity(severity: str) -> tuple[str, str, str, str]:
        """Return (score, vector, score_label, likelihood) defaults by severity."""
        sev = str(severity or "INFO").upper()
        mapping = {
            "CRITICAL": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "High"),
            "HIGH": ("8.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "High", "High"),
            "MEDIUM": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", "Medium", "Medium"),
            "LOW": ("3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "Low", "Low"),
            "INFO": ("0.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Informational", "Low"),
        }
        return mapping.get(sev, mapping["INFO"])

    @staticmethod
    def _default_cwe_for_title(title: str) -> str:
        """Best-effort CWE mapping based on title keywords."""
        lower = str(title or "").lower()
        keyword_map = [
            ("unauth", "CWE-306"),
            ("authentication", "CWE-306"),
            ("default password", "CWE-798"),
            ("hardcoded", "CWE-798"),
            ("signing key", "CWE-321"),
            ("firmware upload", "CWE-434"),
            ("upload", "CWE-434"),
            ("clock", "CWE-682"),
            ("epoch", "CWE-682"),
            ("http", "CWE-319"),
        ]
        for keyword, cwe in keyword_map:
            if keyword in lower:
                return cwe
        return "CWE-200"

    @staticmethod
    def _default_attack_surface_for_title(title: str, cwe: str = "") -> str:
        """Best-effort attack surface category from title keywords and CWE."""
        lower = str(title or "").lower()
        keyword_map = [
            ("command injection", "Embedded Device — OS Command Injection"),
            ("shell injection", "Embedded Device — OS Command Injection"),
            ("$(", "Embedded Device — OS Command Injection"),
            ("injection", "Web Service — Injection"),
            ("upload", "Web Service — Unrestricted File Upload"),
            ("ota", "Firmware — Over-the-Air Update"),
            ("firmware", "Firmware — Update Mechanism"),
            ("unauth", "Web Service — Missing Authentication"),
            ("no auth", "Web Service — Missing Authentication"),
            ("authentication", "Web Service — Authentication"),
            ("version", "Web Service — Information Disclosure"),
            ("disclosure", "Web Service — Information Disclosure"),
            ("property dump", "Web Service — Information Disclosure"),
            ("clock", "Embedded Device — Time Synchronization"),
            ("epoch", "Embedded Device — Time Synchronization"),
            ("rtc", "Embedded Device — Time Synchronization"),
            ("cgi", "Web Service — CGI Endpoint"),
            ("debug", "Embedded Device — Debug Interface"),
            ("default password", "Network — Default Credentials"),
            ("hardcoded", "Network — Default Credentials"),
            ("p2p", "Network — Peer-to-Peer Protocol"),
            ("factory reset", "Embedded Device — Factory Reset"),
        ]
        for keyword, surface in keyword_map:
            if keyword in lower:
                return surface
        # Fall back on CWE
        cwe_map = {
            "CWE-306": "Web Service — Missing Authentication",
            "CWE-798": "Network — Default Credentials",
            "CWE-434": "Web Service — Unrestricted File Upload",
            "CWE-682": "Embedded Device — Misconfiguration",
            "CWE-319": "Network — Cleartext Transmission",
            "CWE-200": "Web Service — Information Disclosure",
            "CWE-321": "Cryptography — Key Management",
        }
        return cwe_map.get(cwe, "Web Service — General")

    @staticmethod
    def _extract_source_hint(source_marker: str) -> str:
        """Extract trailing source hint from marker text."""
        marker = str(source_marker or "")
        match = re.search(r"source:\s*([^|\n]+)", marker, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # Fallback: capture first explicit URL in marker text.
        url_match = re.search(r"https?://[^\s|`]+", marker, re.IGNORECASE)
        if url_match:
            return url_match.group(0).rstrip(".,);")
        # Fallback: endpoint-like absolute path.
        path_match = re.search(r"(/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+)", marker)
        if path_match:
            return path_match.group(1)
        # Fallback: host:port tuples often used in finding titles.
        host_port_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}:\d{2,5})\b", marker)
        if host_port_match:
            return f"http://{host_port_match.group(1)}"
        return ""

    @staticmethod
    def _extract_capture_id(source_marker: str) -> str:
        """Extract capture_id token from marker text when present."""
        marker = str(source_marker or "")
        match = re.search(r"capture_id:\s*([A-Za-z0-9._-]+)", marker, re.IGNORECASE)
        return match.group(1) if match else ""

    @staticmethod
    def _is_unresolved_source_hint(source_hint: str) -> bool:
        """Return True when a source hint is blank or placeholder-like."""
        hint = str(source_hint or "").strip().lower()
        if not hint:
            return True
        return hint in {
            "unknown",
            "unknown (pending capture)",
            "unresolved",
            "provided_info",
            "provided info",
        }

    def _resolve_source_hint_from_capture(self, source_hint: str, source_marker: str) -> str:
        """Use capture provenance metadata as primary source hint when marker hint is unresolved."""
        capture_id = self._extract_capture_id(source_marker)
        if not capture_id:
            return source_hint
        record = resolve_capture(capture_id, self.bra_state_dir)
        if not record:
            return source_hint
        if not self._is_unresolved_source_hint(source_hint):
            return source_hint
        for key in ("url", "endpoint", "target"):
            value = str(record.get(key, "")).strip()
            if value:
                return value
        return source_hint

    @staticmethod
    def _summarize_marker_parts(source_marker: str) -> tuple[str, str]:
        """Extract (description_hint, impact_hint) from pipe-delimited marker."""
        parts = [p.strip() for p in str(source_marker or "").split("|")]
        description_hint = parts[0] if parts else ""
        impact_hint = parts[2] if len(parts) > 2 else ""
        if description_hint.startswith("[FINDING]"):
            description_hint = description_hint[len("[FINDING]"):].strip()
        return description_hint, impact_hint

    @staticmethod
    def _ensure_file(path: Path, content: str) -> None:
        """Create a file with content if it does not already exist."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)

    @staticmethod
    def _is_metadata_only_poc(content: str) -> bool:
        """Detect legacy auto-generated PoC text with no executable commands."""
        allowed_prefixes = (
            "finding-",
            "title:",
            "severity:",
            "source:",
            "source marker:",
        )
        lines = [line.strip().lower() for line in str(content or "").splitlines() if line.strip()]
        if not lines:
            return True
        return all(any(line.startswith(prefix) for prefix in allowed_prefixes) for line in lines)

    @staticmethod
    def _is_metadata_only_evidence(content: str) -> bool:
        """Detect legacy auto-generated evidence text with only marker metadata."""
        allowed_prefixes = (
            "finding-",
            "captured:",
            "source marker:",
            "raw artifact",  # "Raw artifact:" and "Raw artifact SHA256:"
        )
        lines = [line.strip().lower() for line in str(content or "").splitlines() if line.strip()]
        if not lines:
            return True
        return all(any(line.startswith(prefix) for prefix in allowed_prefixes) for line in lines)

    def _upsert_generated_file(self, path: Path, content: str, *, stale_check) -> None:
        """Write generated content when missing or stale metadata-only."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            return
        existing = path.read_text()
        if stale_check(existing):
            path.write_text(content)


    def _relative_to_workspace(self, path: Path) -> str:
        """Render a path relative to workspace root when possible."""
        workspace_root = self._workspace_root()
        try:
            return path.resolve().relative_to(workspace_root.resolve()).as_posix()
        except Exception:
            return path.as_posix()

    @staticmethod
    def _extract_host_and_path_hint(source_hint: str, source_marker: str) -> tuple[str, str]:
        """Extract host/path hints from source marker text."""
        text = " ".join(str(part or "") for part in (source_hint, source_marker))
        host = ""
        path_hint = ""

        url_match = re.search(r"https?://([^/\s]+)(/[^\s]*)?", text, re.IGNORECASE)
        if url_match:
            host = (url_match.group(1) or "").strip()
            path_hint = (url_match.group(2) or "").strip() or "/"

        if not path_hint:
            path_match = re.search(r"\s(/cgi-bin/[^\s|`]+)", text)
            if path_match:
                path_hint = path_match.group(1).strip()

        return host, path_hint

    def _find_best_raw_evidence_artifact(self, source_hint: str, source_marker: str) -> Path | None:
        """Select the best matching raw artifact for this finding marker.

        Uses two strategies:
        1. Direct capture_id lookup in evidence_index.jsonl
        2. Score-based fuzzy match against files in artifacts/raw/
        3. Fallback: search captures.log for commands matching the source hint
        """
        capture_id = self._extract_capture_id(source_marker)
        if capture_id:
            record = resolve_capture(capture_id, self.bra_state_dir)
            artifact_path = str(record.get("artifact_path", "")).strip() if record else ""
            if artifact_path:
                candidate = self._resolve_record_path(artifact_path)
                if candidate.exists():
                    return candidate

        raw_dir = self.bra_state_dir / "artifacts" / "raw"
        if not raw_dir.exists():
            return None

        host, path_hint = self._extract_host_and_path_hint(source_hint, source_marker)

        # Strategy 1: score-based fuzzy match (existing logic)
        if host or path_hint:
            best: tuple[int, float, Path] | None = None
            for candidate in raw_dir.glob("*"):
                if not candidate.is_file():
                    continue
                score = 0
                name = candidate.name.lower()
                if name.startswith("curl_"):
                    score += 2
                if host and host.lower() in name:
                    score += 8
                text_sample = candidate.read_text(errors="replace")
                if host and host.lower() in text_sample.lower():
                    score += 4
                if path_hint and path_hint != "/" and path_hint in text_sample:
                    score += 6
                if score <= 0:
                    continue
                mtime = candidate.stat().st_mtime
                if best is None or score > best[0] or (score == best[0] and mtime > best[1]):
                    best = (score, mtime, candidate)
            if best:
                return best[2]

        # Strategy 2: search captures.log for matching commands
        captures_log = self.bra_state_dir / "logs" / "captures.log"
        if captures_log.exists() and source_hint:
            hint_lower = source_hint.lower().strip()
            # Also try extracting bare filename from hint (e.g. "getversion.cgi")
            search_terms = [hint_lower]
            if "." in hint_lower and "/" not in hint_lower:
                search_terms.append(f"/{hint_lower}")  # match /cgi-bin/getversion.cgi
            try:
                for line in reversed(captures_log.read_text(errors="replace").splitlines()):
                    parsed = self._parse_capture_log_line(line)
                    if not parsed:
                        continue
                    command, artifact_path = parsed
                    command_lower = command.lower()
                    if any(term in command_lower for term in search_terms):
                        candidate = Path(artifact_path)
                        if candidate.exists():
                            return candidate
            except Exception:
                pass

        return None

    def _build_poc_script(
        self,
        finding_id: str,
        title: str,
        source_marker: str,
        source_hint: str,
        *,
        strict_command: bool = False,
    ) -> str:
        """Generate an executable shell PoC script."""
        host, path_hint = self._extract_host_and_path_hint(source_hint, source_marker)
        command = ""
        cleaned_hint = str(source_hint or "").strip()
        command_from_capture = self._find_capture_command(source_hint, source_marker)
        if command_from_capture:
            command = command_from_capture

        if not command and cleaned_hint.lower().startswith("curl "):
            command = cleaned_hint
        elif not command and cleaned_hint.lower().startswith(("http://", "https://")):
            command = f"curl -i {shlex.quote(cleaned_hint)}"
        elif not command and path_hint:
            if host:
                command = f"curl -i {shlex.quote('http://' + host + path_hint)}"
            else:
                command = 'curl -i "http://${TARGET_HOST:?Set TARGET_HOST for this finding}"' + shlex.quote(path_hint)
        elif not command and strict_command:
            return ""
        elif not command:
            command = "echo 'Set a reproducible curl command for this finding.'"

        return (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n\n"
            f"# FINDING-{finding_id} PoC\n"
            f"# Title: {title}\n"
            f"# Source marker: {source_marker}\n\n"
            f"{command}\n"
        )

    @staticmethod
    def _parse_capture_log_line(line: str) -> tuple[str, str] | None:
        """Parse captures.log rows in either 3- or 4-column format."""
        parts = line.split(" | ", 3)
        if len(parts) >= 4:
            command = parts[2].strip()
            artifact_path = parts[3].strip()
        elif len(parts) >= 3:
            command = parts[1].strip()
            artifact_path = parts[2].strip()
        else:
            return None
        if not command:
            return None
        return command, artifact_path

    def _find_capture_command(self, source_hint: str, source_marker: str) -> str:
        """Return the latest matching command from captures.log for this finding."""
        capture_id = self._extract_capture_id(source_marker)
        if capture_id:
            record = resolve_capture(capture_id, self.bra_state_dir)
            if record:
                command = str(record.get("command", "")).strip()
                if command:
                    return command
                target = str(record.get("target", "")).strip()
                if target:
                    return target

        captures_log = self.bra_state_dir / "logs" / "captures.log"
        if not captures_log.exists():
            return ""
        terms: list[str] = []
        for value in (str(source_hint or "").strip(), str(source_marker or "").strip()):
            if not value:
                continue
            lower_value = value.lower()
            terms.append(lower_value)
            if "." in lower_value and "/" not in lower_value:
                terms.append(f"/{lower_value}")
        if not terms:
            terms = []

        try:
            lines = captures_log.read_text(errors="replace").splitlines()
            for line in reversed(lines):
                parsed = self._parse_capture_log_line(line)
                if not parsed:
                    continue
                command = parsed[0]
                command_lower = command.lower()
                if terms and any(term in command_lower for term in terms):
                    return command
            # Fallback: keep PoC reproducible with the most recent recorded command
            # even when source markers are descriptive and do not include command terms.
            for line in reversed(lines):
                parsed = self._parse_capture_log_line(line)
                if not parsed:
                    continue
                command = parsed[0]
                if command:
                    return command
        except Exception:
            return ""
        return ""

    def _deterministic_line_span(
        self,
        raw_artifact: Path | None,
        source_hint: str,
        source_marker: str,
    ) -> tuple[int | None, int | None, str, str]:
        """Select deterministic evidence line span and return metadata tuple."""
        if not raw_artifact or not raw_artifact.exists():
            return None, None, "", "unresolved"

        try:
            lines = raw_artifact.read_text(errors="replace").splitlines()
        except Exception:
            return None, None, "", "unresolved"
        if not lines:
            return None, None, "", "unresolved"

        host, path_hint = self._extract_host_and_path_hint(source_hint, source_marker)
        terms: list[str] = []
        if source_hint:
            terms.append(source_hint.lower())
        if host:
            terms.append(host.lower())
        if path_hint:
            terms.append(path_hint.lower())

        for idx, line in enumerate(lines, start=1):
            lowered = line.lower()
            if any(term and term in lowered for term in terms):
                excerpt_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                return idx, idx, excerpt_hash, "exact"

        for idx, line in enumerate(lines, start=1):
            if line.strip():
                excerpt_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                return idx, idx, excerpt_hash, "fallback"

        return None, None, "", "unresolved"

    @staticmethod
    def _upsert_section(finding_content: str, section_name: str, body: str) -> str:
        """Replace or append a markdown section body."""
        pattern = re.compile(
            rf"(###\s+{re.escape(section_name)}\s*\n)(.*?)(?=\n###\s+|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        if pattern.search(finding_content):
            return pattern.sub(lambda m: f"{m.group(1)}\n{body.strip()}\n\n", finding_content, count=1)
        return finding_content.rstrip() + f"\n\n### {section_name}\n\n{body.strip()}\n"

    def materialize_system_sections(self, finding: PendingFinding) -> list[str]:
        """Deterministically populate system-managed finding sections.

        This is the core fastpath path for:
        - Affected Artifact
        - Reproduction Steps
        - Proof of Concept
        - Observed Evidence
        """
        if not self.findings_path.exists():
            return []

        finding_id = self._normalize_finding_id(finding.id)
        content = self.findings_path.read_text()
        finding_slice = self._extract_finding_slice(content, finding_id)
        if not finding_slice:
            return []

        start, end, finding_content = finding_slice
        source_hint = self._extract_source_hint(finding.source_marker)
        source_hint = self._resolve_source_hint_from_capture(source_hint, finding.source_marker)
        source_hint = source_hint or "Unknown (pending capture)"
        capture_id = self._extract_capture_id(finding.source_marker) or "unresolved"
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        command = self._find_capture_command(source_hint, finding.source_marker)
        raw_artifact = self._find_best_raw_evidence_artifact(source_hint, finding.source_marker)
        raw_rel = self._relative_to_workspace(raw_artifact) if raw_artifact else ""
        line_start, line_end, excerpt_sha256, match_type = self._deterministic_line_span(
            raw_artifact,
            source_hint,
            finding.source_marker,
        )

        poc_rel = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-poc.sh"
        evidence_rel = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-evidence.txt"
        poc_abs = self.reqs_dir / f"finding-{finding_id}-poc.sh"
        evidence_abs = self.reqs_dir / f"finding-{finding_id}-evidence.txt"

        poc_content = self._build_poc_script(
            finding_id,
            finding.title,
            finding.source_marker,
            source_hint,
            strict_command=True,
        )
        if poc_content:
            self._upsert_generated_file(poc_abs, poc_content, stale_check=self._is_metadata_only_poc)

        evidence_content, _, _, evidence_tool = self._build_evidence_content(
            finding_id=finding_id,
            source_marker=finding.source_marker,
            captured_at=now_ts,
            raw_artifact=raw_artifact,
        )
        self._upsert_generated_file(evidence_abs, evidence_content, stale_check=self._is_metadata_only_evidence)
        evidence_hash = self._sha256_for_file(evidence_abs) if evidence_abs.exists() else "N/A"
        raw_hash = self._sha256_for_file(raw_artifact) if raw_artifact and raw_artifact.exists() else ""
        artifact_hash = raw_hash or "N/A"

        local_artifact_path = raw_rel or evidence_rel
        line_start_text = str(line_start) if line_start is not None else "unresolved"
        line_end_text = str(line_end) if line_end is not None else "unresolved"
        artifact_ref = raw_rel or "unresolved"
        excerpt_ref = excerpt_sha256 or "unresolved"
        artifact_body = (
            f"**Artifact:** `{source_hint}`\n"
            f"**Artifact Location:**\n"
            f"- Original: `{source_hint}`\n"
            f"- Local: `{local_artifact_path}`\n"
            f"**Artifact Hash:** `{artifact_hash}`\n\n"
            f"**Evidence Ref:**\n"
            f"- capture_id: `{capture_id}`\n"
            f"- artifact_path: `{artifact_ref}`\n"
            f"- line_start: `{line_start_text}` - line_end: `{line_end_text}`\n"
            f"- excerpt_sha256: `{excerpt_ref}`\n"
            f"- match_type: `{match_type}`"
        )

        repro_command = command.strip() if command else f"cat {poc_rel}"
        repro_body = (
            "**Environment:**\n"
            "- Captured during active engagement; use existing command captures.\n\n"
            "**Steps:**\n"
            "```bash\n"
            f"{repro_command}\n"
            "```"
        )

        proof_body = (
            f"- **Description:** Deterministic PoC generated from captured command output.\n"
            f"- **Location:** `{poc_rel}`\n"
            "- **Note:** Not weaponized"
        )

        observed_rows = [
            f"| Captured output | `{evidence_rel}` | `{evidence_hash}` | {now_ts} | {evidence_tool} |"
        ]
        if raw_rel:
            observed_rows.append(
                f"| Raw artifact | `{raw_rel}` | `{raw_hash}` | {now_ts} | captured/raw |"
            )
        evidence_body = (
            "| Evidence | Location | Hash | Timestamp | Tool/Version |\n"
            "|----------|----------|------|-----------|--------------|\n"
            + "\n".join(observed_rows)
        )

        updated_finding = finding_content
        updated_finding = self._upsert_section(updated_finding, "Affected Artifact", artifact_body)
        updated_finding = self._upsert_section(updated_finding, "Reproduction Steps", repro_body)
        updated_finding = self._upsert_section(updated_finding, "Proof of Concept", proof_body)
        updated_finding = self._upsert_section(updated_finding, "Observed Evidence", evidence_body)

        changed: list[str] = []
        if updated_finding != finding_content:
            self.findings_path.write_text(content[:start] + updated_finding + content[end:])
            changed.extend(self.SYSTEM_MANAGED_SECTIONS)
        if poc_content:
            changed.append("PoC file")
        changed.append("Evidence file")
        return changed

    def materialize_finding_from_marker(
        self,
        finding_id: str,
        severity: str,
        title: str,
        source_marker: str,
    ) -> str:
        """Enqueue and materialize one finding from a marker-compatible payload."""
        normalized_id = self._normalize_finding_id(finding_id)
        self.enqueue_finding(normalized_id, severity, title, source_marker)
        pending = next((pf for pf in self.pending_queue if pf.id == normalized_id), None)
        if not pending:
            return normalized_id

        self.materialize_system_sections(pending)
        if not self.is_slowpath_enabled():
            self._autofill_finding_record_defaults(pending)
        return normalized_id

    def _build_evidence_content(
        self,
        finding_id: str,
        source_marker: str,
        captured_at: str,
        raw_artifact: Path | None,
    ) -> tuple[str, str, str, str]:
        """Build evidence text and return (content, location, hash, tool)."""
        if raw_artifact and raw_artifact.exists():
            raw_hash = self._sha256_for_file(raw_artifact)
            raw_rel = self._relative_to_workspace(raw_artifact)
            excerpt_lines: list[str] = []
            for line in raw_artifact.read_text(errors="replace").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("> ") or stripped.startswith("< HTTP/") or stripped.startswith("< Server:"):
                    excerpt_lines.append(stripped)
                if len(excerpt_lines) >= 6:
                    break
            content_lines = [
                f"FINDING-{finding_id} Evidence",
                f"Captured: {captured_at}",
                f"Source marker: {source_marker}",
                f"Raw artifact: {raw_rel}",
                f"Raw artifact SHA256: {raw_hash}",
            ]
            if excerpt_lines:
                content_lines.extend(["", "Excerpt:"] + excerpt_lines)
            return "\n".join(content_lines) + "\n", raw_rel, raw_hash, "curl/raw-artifact"

        fallback_lines = [
            f"FINDING-{finding_id} Evidence",
            f"Captured: {captured_at}",
            f"Source marker: {source_marker}",
        ]
        return "\n".join(fallback_lines) + "\n", "", "", "auto-enforcer/1.0"

    def _autofill_finding_record_defaults(self, finding: PendingFinding) -> bool:
        """Fill unresolved {{PENDING:*}} placeholders and seed required files."""
        if not self.findings_path.exists():
            return False

        finding_id = self._normalize_finding_id(finding.id)
        content = self.findings_path.read_text()
        finding_slice = self._extract_finding_slice(content, finding_id)
        if not finding_slice:
            return False

        start, end, finding_content = finding_slice
        if not self._has_placeholder_tokens(finding_content):
            return False

        source_hint = self._extract_source_hint(finding.source_marker)
        source_hint = self._resolve_source_hint_from_capture(source_hint, finding.source_marker)
        source_hint = source_hint or "Unknown (pending capture)"
        description_hint, impact_hint = self._summarize_marker_parts(finding.source_marker)
        score, vector, score_label, likelihood = self._default_cvss_for_severity(finding.severity)
        cwe_id = self._default_cwe_for_title(finding.title)
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        poc_rel = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-poc.sh"
        evidence_rel = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-evidence.txt"
        poc_abs = self.reqs_dir / f"finding-{finding_id}-poc.sh"
        evidence_abs = self.reqs_dir / f"finding-{finding_id}-evidence.txt"

        raw_artifact = self._find_best_raw_evidence_artifact(source_hint, finding.source_marker)
        poc_content = self._build_poc_script(finding_id, finding.title, finding.source_marker, source_hint)
        evidence_content, evidence_location, raw_evidence_hash, evidence_tool = self._build_evidence_content(
            finding_id=finding_id,
            source_marker=finding.source_marker,
            captured_at=now_ts,
            raw_artifact=raw_artifact,
        )
        self._upsert_generated_file(poc_abs, poc_content, stale_check=self._is_metadata_only_poc)
        self._upsert_generated_file(evidence_abs, evidence_content, stale_check=self._is_metadata_only_evidence)

        evidence_hash = raw_evidence_hash or self._sha256_for_file(evidence_abs)
        evidence_location_value = evidence_location or evidence_rel
        source_hash = self._hash_text(finding.source_marker or finding.title)
        snippet_body = (
            f"// {description_hint or finding.title}\n"
            f"// {impact_hint or 'Potential security impact observed during analysis.'}"
        )
        description_text = description_hint or finding.title
        impact_text = impact_hint or "Impact requires follow-up verification; treat as actionable risk."
        attack_vector_text = "Network-adjacent attacker on reachable interface can trigger this behavior."
        remediation_text = "Add authentication/authorization checks and validate trusted input before action."

        replacements = {
            "CVSS_SCORE": score,
            "CWE_ID": cwe_id,
            "ARTIFACT_PATH_OR_URL": source_hint,
            "ORIGINAL_LOCATION": source_hint,
            "DESCRIPTION": description_text,
            "IMPACT": impact_text,
            "ATTACK_VECTOR": attack_vector_text,
            "SNIPPET_FILE": source_hint if "/" in source_hint else "Unknown (pending capture)",
            "LINE_RANGE": "Unknown (pending capture)",
            "SOURCE_HASH": source_hash,
            "SNIPPET_BODY": snippet_body,
            "ENVIRONMENT": "Captured during active engagement; reproducible in current target context.",
            "REPRO_STEPS": (
                f"# Review PoC artifact\n"
                f"cat {poc_rel}\n"
                f"# Validate evidence artifact\n"
                f"cat {evidence_rel}"
            ),
            "POC_DESCRIPTION": "PoC steps and raw capture saved for operator verification.",
            "EVIDENCE_TYPE": "Raw capture" if raw_artifact else "Captured output",
            "EVIDENCE_LOCATION": evidence_location_value,
            "EVIDENCE_HASH": evidence_hash,
            "EVIDENCE_TIMESTAMP": now_ts,
            "EVIDENCE_TOOL": evidence_tool,
            "CVSS_VECTOR": vector,
            "CVSS_SCORE_SEVERITY": f"{score} ({score_label})",
            "LIKELIHOOD": likelihood,
            # Backward-compatibility for legacy skeletons that still include
            # {{PENDING:LIKELIHOOD_RATIONALE}}.
            "LIKELIHOOD_RATIONALE": "",
            "REMEDIATION": remediation_text,
            "ATTACK_SURFACE": self._default_attack_surface_for_title(finding.title, cwe_id),
            "COVERAGE_EVIDENCE": "Validated against stored artifacts and schema checks.",
            "TOOLS_AND_VERSIONS": "auto-enforcer/1.0, validator schema v1",
        }

        # Fill artifact path: prefer raw artifact, fall back to evidence file
        if raw_artifact:
            try:
                replacements["LOCAL_ARTIFACT_PATH"] = str(raw_artifact.relative_to(self.notes_dir.parent.parent))
            except ValueError:
                replacements["LOCAL_ARTIFACT_PATH"] = str(raw_artifact)
        elif evidence_abs.exists():
            replacements["LOCAL_ARTIFACT_PATH"] = evidence_rel

        updated_finding = self._PLACEHOLDER_KEY_PATTERN.sub(
            lambda match: replacements.get(match.group(1), match.group(0)),
            finding_content,
        )
        updated_finding = re.sub(
            r"(###\s+Likelihood\s*\n\s*\n)([^\n]*?)\s+[—-]\s*$",
            r"\1\2",
            updated_finding,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        if updated_finding != finding_content:
            updated_content = content[:start] + updated_finding + content[end:]
            self.findings_path.write_text(updated_content)
            return True

        return False

    def enqueue_finding(self, finding_id: str, severity: str,
                        title: str, source_marker: str) -> None:
        """Add finding to queue, activate lock."""
        normalized_id = self._normalize_finding_id(finding_id)
        # Never re-enqueue a finding that was already completed this session
        if normalized_id in self._completed_ids:
            return
        norm_title = self._normalize_title(title)
        for existing in self.pending_queue:
            if existing.id == normalized_id or self._normalize_title(existing.title) == norm_title:
                return

        pf = PendingFinding(
            id=normalized_id,
            severity=severity,
            title=title,
            source_marker=source_marker,
        )
        self.pending_queue.append(pf)
        self._save_queue()
        self._seed_finding_skeleton(pf)

    def write_context_file(
        self,
        finding_id: str,
        agent_text: str,
        source_marker: str = "",
        pre_finding_buffer: "list[tuple[str, str]] | None" = None,
    ) -> None:
        """Persist a minimal provenance snapshot at [FINDING] emission time.

        This intentionally avoids storing broad agent/tool context to keep
        findings-subagent prompts bounded and finding-scoped.

        Skips if the file already exists (first capture wins).
        """
        normalized_id = self._normalize_finding_id(finding_id)
        context_file = self.reqs_dir / f"finding-{normalized_id}-context.md"

        # First capture wins — don't overwrite an existing snapshot.
        if context_file.exists():
            return

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        source_hint = self._extract_source_hint(source_marker)
        parts: list[str] = [
            f"# Finding Context: FINDING-{normalized_id}\n",
            f"Captured: {now_ts}",
            f"Source marker: {source_marker}",
            f"Source hint: {source_hint or 'N/A'}",
            "",
            "Note: full main-agent and tool-output context intentionally omitted.",
            "",
            "---",
        ]

        try:
            self.reqs_dir.mkdir(parents=True, exist_ok=True)
            context_file.write_text("\n".join(parts) + "\n")
        except Exception:
            pass  # Non-fatal — prompt generation falls back to key-path references.

    def dequeue_finding(self, finding_id: str) -> None:
        """Remove finding from queue and record as completed."""
        normalized_id = self._normalize_finding_id(finding_id)
        self.pending_queue = [pf for pf in self.pending_queue if pf.id != normalized_id]
        self._completed_ids.add(normalized_id)
        self._save_queue()



    def _is_findings_path(self, file_path: str) -> bool:
        """Check if path points to FINDINGS.md."""
        try:
            p = Path(file_path).resolve()
            return p == self.findings_path.resolve()
        except Exception:
            return "FINDINGS.md" in file_path

    def _is_reqs_path(self, file_path: str) -> bool:
        """Check if path is under NOTES/reqs/."""
        try:
            p = Path(file_path).resolve()
            p.relative_to(self.reqs_dir.resolve())
            return True
        except (ValueError, Exception):
            return "/reqs/" in file_path

    _DEFERRED_HASH_MARKERS = (
        "(Hash generated during report creation)",
        "(computed during report creation)",
    )
    _NA_HASH_MARKERS = ("n/a", "na")

    # Required sections in a finding record (markdown heading-based)
    _REQUIRED_SECTIONS = [
        "Affected Artifact",
        "Description",
        "Impact",
        "Attack Vector",
        "Reproduction Steps",
        "Proof of Concept",
        "Observed Evidence",
        "Severity",
        "Likelihood",
        "Remediation",
        "Attack Surface",
        "Tools & Versions",
    ]
    _REQUIRED_METADATA_FIELDS = ["ID", "Title", "Severity", "CVSS", "CWE", "Status"]

    def _extract_metadata_value(self, finding_content: str, field_name: str) -> str:
        """Extract metadata table/inline value for a required field."""
        table_match = re.search(
            rf"^\|\s*\*\*{re.escape(field_name)}\*\*\s*\|\s*([^\n|]*)",
            finding_content,
            re.IGNORECASE | re.MULTILINE,
        )
        if table_match:
            return table_match.group(1).strip()
        inline_match = re.search(
            rf"\*\*{re.escape(field_name)}\*\*\s*:\s*([^\n]+)",
            finding_content,
            re.IGNORECASE,
        )
        if inline_match:
            return inline_match.group(1).strip()
        return ""

    def validate_finding_record(self, finding_id: str) -> ValidationResult:
        """Parse FINDINGS.md and validate a specific finding record.

        Checks:
        1. Finding record exists (## [FINDING-{id}] header)
        2. All required sections present with non-empty content
        3. Artifact hash is present (SHA256 format)
        4. PoC file referenced in record exists in NOTES/reqs/

        Returns:
            ValidationResult with valid flag, missing fields, and errors
        """
        missing_fields: list[str] = []
        errors: list[str] = []

        if not self.findings_path.exists():
            return ValidationResult(False, [], [f"FINDINGS.md not found at {self.findings_path}"])

        content = self.findings_path.read_text()

        finding_slice = self._extract_finding_slice(content, finding_id)
        if not finding_slice:
            return ValidationResult(False, [], [f"Finding FINDING-{finding_id} not found in FINDINGS.md"])

        _, _, finding_content = finding_slice

        def add_missing(field: str) -> None:
            if field not in missing_fields:
                missing_fields.append(field)

        # Check required sections
        for section in self._REQUIRED_SECTIONS:
            section_pattern = rf"###\s+{re.escape(section)}"
            section_match = re.search(section_pattern, finding_content)
            if not section_match:
                add_missing(section)
            else:
                # Check section has non-empty content after header
                section_start = section_match.end()
                next_section = re.search(r'\n###\s+', finding_content[section_start:])
                if next_section:
                    section_content = finding_content[section_start:section_start + next_section.start()].strip()
                else:
                    section_content = finding_content[section_start:].strip()
                if not section_content:
                    add_missing(section)
                elif self._has_placeholder_tokens(section_content):
                    add_missing(section)

        # Check required metadata fields in table/inline form.
        for field_name in self._REQUIRED_METADATA_FIELDS:
            if not re.search(
                rf"(?:\|\s*\*\*{re.escape(field_name)}\*\*\s*\|)|(?:\*\*{re.escape(field_name)}\*\*\s*:)",
                finding_content,
                re.IGNORECASE,
            ):
                add_missing(field_name)
                continue
            if self._has_placeholder_tokens(self._extract_metadata_value(finding_content, field_name)):
                add_missing(field_name)

        # CWE must be in CWE-XXX format when present.
        if re.search(r"(?:\|\s*\*\*CWE\*\*\s*\|)|(?:\*\*CWE\*\*\s*:)", finding_content, re.IGNORECASE):
            cwe_value = self._extract_metadata_value(finding_content, "CWE")
            if cwe_value and (not self._has_placeholder_tokens(cwe_value)) and not re.search(r"CWE-\d+", cwe_value):
                errors.append("CWE is not in expected format (CWE-XXX)")

        # Artifact Location (dual-path: Original + Local)
        if not re.search(r'Artifact Location', finding_content, re.IGNORECASE):
            missing_fields.append("Artifact Location")

        # Check artifact hash (SHA256 = 64 hex chars)
        has_artifact_hash_field = "artifact hash" in finding_content.lower()
        artifact_hash = self._extract_artifact_hash(finding_content)
        artifact_hash_value = self._extract_artifact_hash_value(finding_content)
        is_na_hash = self._is_na_hash_marker(artifact_hash_value)
        lower_content = finding_content.lower()
        deferred_hash = any(marker.lower() in lower_content for marker in self._DEFERRED_HASH_MARKERS)
        if not has_artifact_hash_field:
            if "Artifact Hash" not in missing_fields:
                add_missing("Artifact Hash")
        else:
            if deferred_hash:
                errors.append("Artifact Hash deferred markers are not allowed; use SHA256 or N/A")
            elif not artifact_hash and not is_na_hash:
                errors.append("Artifact Hash is not a valid SHA256 (expected 64 hex characters)")

        local_artifact_paths = self._extract_artifact_location_local_paths(finding_content)
        bra_artifact_paths = [path for path in local_artifact_paths if self._is_bra_scoped_path(path)]
        if bra_artifact_paths and artifact_hash and not is_na_hash:
            resolved_paths = [self._resolve_record_path(path) for path in bra_artifact_paths]
            existing_paths = [path for path in resolved_paths if path.exists()]
            if not existing_paths:
                errors.append(
                    "BRA artifact file(s) not found: "
                    + ", ".join(str(path) for path in resolved_paths)
                )
            else:
                expected_by_path = {path: self._sha256_for_file(path) for path in existing_paths}
                if artifact_hash.lower() not in expected_by_path.values():
                    expected_summary = ", ".join(
                        f"{path} => {digest}" for path, digest in expected_by_path.items()
                    )
                    errors.append(
                        "Artifact Hash mismatch for local artifact. "
                        f"Expected: {expected_summary}"
                    )

        # Check PoC references a file in NOTES/reqs/
        poc_section = self._extract_section_content(finding_content, "Proof of Concept")
        poc_matches = re.findall(
            r'(?:layer3-engagement/NOTES/reqs/[^\s)"`\]]+|NOTES/reqs/[^\s)"`\]]+|reqs/[^\s)"`\]]+)',
            poc_section,
        )
        if poc_matches:
            # Verify at least one referenced file exists
            resolved_poc_paths = [self._resolve_record_path(path) for path in poc_matches]
            existing_poc_paths = [path for path in resolved_poc_paths if path.exists()]
            any_exists = bool(existing_poc_paths)
            if not any_exists:
                errors.append(
                    f"PoC file(s) not found: "
                    f"{', '.join(str(path) for path in resolved_poc_paths)}"
                )
            else:
                poc_contents = [path.read_text(errors="replace") for path in existing_poc_paths]
                if all(self._is_metadata_only_poc(content) for content in poc_contents):
                    errors.append(
                        "PoC artifact content is metadata-only; include executable proof steps."
                    )
        elif "Proof of Concept" not in missing_fields:
            # Section exists but no reqs/ path — allowed if inline PoC
            # contains actual commands (code fences with content).
            has_inline_poc = bool(re.search(
                r'```(?:bash|sh|python|curl|text)?\s*\n.+?\n```',
                poc_section,
                re.DOTALL,
            ))
            if not has_inline_poc:
                errors.append("Proof of Concept section needs inline commands or a NOTES/reqs/ file reference")

        if self._has_placeholder_tokens(finding_content):
            unresolved = sorted(
                key for key in set(self._PLACEHOLDER_KEY_PATTERN.findall(finding_content))
                if key != "LIKELIHOOD_RATIONALE"
            )
            if unresolved:
                errors.append(
                    "Placeholder tokens remain in finding record: "
                    + ", ".join(unresolved)
                )
            else:
                errors.append("Placeholder tokens remain in finding record")

        valid = len(missing_fields) == 0 and len(errors) == 0
        return ValidationResult(valid, missing_fields, errors)

    def merge_finding_output(self, finding_id: str) -> bool:
        """Read NNN-output.md from .bra/artifacts/ and splice numbered fields into FINDINGS.md.

        Output file format (numbered fields, no signals):
            1: <cwe number e.g. 22>
            2: <description text>
            3: <impact text>
            4: <attack vector text>
            5: <remediation text>
            6: <tools & versions>

        Returns True if merge succeeded, False if output file missing.
        """
        fid = self._normalize_finding_id(finding_id)
        output_path = self.bra_state_dir / "artifacts" / f"{fid}-output.md"
        if not output_path.exists():
            return False

        raw = output_path.read_text(errors="replace")

        fields: dict[int, str] = {}
        current_key: int | None = None
        current_lines: list[str] = []

        for line in raw.splitlines():
            m = re.match(r'^(\d+):\s*(.*)', line)
            if m:
                if current_key is not None:
                    fields[current_key] = "\n".join(current_lines).strip()
                current_key = int(m.group(1))
                current_lines = [m.group(2)]
            elif current_key is not None:
                current_lines.append(line)

        if current_key is not None:
            fields[current_key] = "\n".join(current_lines).strip()

        mapping = {
            1: ("CWE_ID",             lambda v: f"CWE-{v}" if not v.upper().startswith("CWE") else v),
            2: ("DESCRIPTION",        lambda v: v),
            3: ("IMPACT",             lambda v: v),
            4: ("ATTACK_VECTOR",      lambda v: v),
            5: ("REMEDIATION",        lambda v: v),
            6: ("TOOLS_AND_VERSIONS", lambda v: v),
        }

        if not self.findings_path.exists():
            return False

        content = self.findings_path.read_text(errors="replace")
        finding_slice = self._extract_finding_slice(content, fid)
        if not finding_slice:
            return False

        start, end, section = finding_slice
        for field_num, (token, transform) in mapping.items():
            if field_num in fields:
                value = transform(fields[field_num])
                section = section.replace(f"{{{{PENDING:{token}}}}}", value)

        content = content[:start] + section + content[end:]
        self.findings_path.write_text(content)
        output_path.unlink(missing_ok=True)
        return True

    def get_documentation_prompt(
        self,
        finding: "PendingFinding",
        all_pending: "list[PendingFinding] | None" = None,
    ) -> str:
        """Build prompt telling the subagent what to document.

        Targets ONE finding at a time with inline schema and explicit
        workflow steps. Eliminates the external schema file reference.
        """
        finding_id = self._normalize_finding_id(finding.id)
        title = finding.title or "Untitled"
        severity = (finding.severity or "INFO").upper()
        findings_path = str(self.findings_path)
        findings_path_rel = self._relative_to_workspace(self.findings_path)
        reqs_path = str(self.reqs_dir)
        reqs_path_rel = self._relative_to_workspace(self.reqs_dir)
        reqfiles_path = str(self.reqs_dir / "reqfiles")
        intel_path = str(self.intel_path)
        captures_log_path = str(self.bra_state_dir / "logs" / "captures.log")
        artifacts_raw_path = str(self.bra_state_dir / "artifacts" / "raw")
        system_context_snapshot = self._build_system_context_snapshot(finding_id)
        inline_evidence = self._build_inline_evidence(finding_id)
        inline_evidence_slim = self._build_inline_evidence(
            finding_id,
            skip_skeleton=True,
            section_header="## Evidence\n\n",
        )

        # Build already-documented list from FINDINGS.md
        documented_block = ""
        if self.findings_path.exists():
            documented: list[str] = []
            for m in re.finditer(
                r'## \[FINDING-(\d{3})\]\s*(.*)', self.findings_path.read_text()
            ):
                existing_id = self._normalize_finding_id(m.group(1))
                if existing_id == finding_id:
                    continue
                documented.append(f"FINDING-{existing_id}: {m.group(2).strip()}")
            if documented:
                items = "\n".join(f"- {d}" for d in documented)
                documented_block = (
                    f"Already documented in FINDINGS.md:\n{items}\n"
                    f"Do not modify these. Append new records after the last finding.\n\n"
                )

        # Queue status — show only the assigned finding, not the full list
        pending = all_pending or [finding]
        queue_block = f">>> FINDING-{finding_id} ({finding.severity}): {finding.title}"
        fastpath_enabled = self.is_fastpath_enabled()
        slowpath_enabled = self.is_slowpath_enabled()
        fastpath_note = (
            "FASTPATH is enabled via FINDINGS-FASTPATH token.\n"
            "System-managed sections are pre-populated and must NOT be edited:\n"
            "- Affected Artifact\n"
            "- Reproduction Steps\n"
            "- Proof of Concept\n"
            "- Observed Evidence\n\n"
            if fastpath_enabled
            else ""
        )
        slowpath_note = (
            "SLOWPATH-FINDINGS is enabled.\n"
            "System-managed sections/hashes are script-materialized; keep them intact.\n"
            "Subagent focus: Description, Impact, Attack Vector, Severity reasoning,\n"
            "Likelihood, Remediation, Attack Surface, Tools & Versions.\n\n"
            if slowpath_enabled
            else ""
        )
        ownership_block = (
            "## Ownership (SLOWPATH)\n\n"
            "Script-owned (DO NOT EDIT):\n"
            "- Affected Artifact (including Artifact Hash + Evidence Ref)\n"
            "- Reproduction Steps\n"
            "- Proof of Concept\n"
            "- Observed Evidence\n\n"
            "Subagent-owned (EDIT THESE):\n"
            "- Header metadata: CVSS, CWE (and only fix Severity/Title/Status when clearly wrong)\n"
            "- Description\n"
            "- Impact\n"
            "- Attack Vector\n"
            "- Severity (vector + score rationale)\n"
            "- Likelihood (level only)\n"
            "- Remediation\n"
            "- Attack Surface\n"
            "- Tools & Versions\n\n"
            if slowpath_enabled
            else ""
        )
        skeleton_instruction_block = (
            f"A skeleton for FINDING-{finding_id} already exists in {findings_path_rel} with\n"
            f"{{{{PENDING:...}}}} placeholders. Locate `## [FINDING-{finding_id}]` in the skeleton\n"
            f"shown below and replace placeholders only in subagent-owned fields.\n"
            f"Do not edit script-owned sections.\n"
            f"Keep the section structure unchanged.\n\n"
            if slowpath_enabled
            else (
                f"A skeleton for FINDING-{finding_id} already exists in {findings_path_rel} with\n"
                f"{{{{PENDING:...}}}} placeholders. Locate `## [FINDING-{finding_id}]` in the skeleton\n"
                f"shown below and replace every placeholder with real content.\n"
                f"Keep the section structure unchanged.\n\n"
            )
        )
        workflow_block = (
            f"The skeleton and all evidence are already shown above. Do NOT read any files.\n"
            f"1. Write a file called `./{finding_id}-output.md` with ONLY these numbered fields:\n"
            f"   1: <cwe-number-only, e.g. 22>\n"
            f"   2: <description — 1-3 sentences>\n"
            f"   3: <impact — 2-4 lines>\n"
            f"   4: <attack vector — 1-3 lines>\n"
            f"   5: <remediation — specific actionable fix>\n"
            f"   6: <tools & versions, e.g. curl 7.x / lighttpd 1.4.76>\n"
            f"   Use the inlined evidence above. No other keys, no markdown headers.\n\n"
            if slowpath_enabled
            else (
                f"1. Read the required files from the Key Paths table.\n"
                f"2. Replace ALL {{{{PENDING:...}}}} placeholders with real content from the evidence.\n"
                f"3. Create PoC file at {reqs_path}/finding-{finding_id}-poc.[ext].\n"
                f"4. Write the completed record to {findings_path}.\n"
                f"5. The validator auto-checks after every Write/Edit.\n"
                f"   If all sections are present, non-empty, and placeholders gone,\n"
                f"   FINDING-{finding_id} is dequeued automatically.\n\n"
            )
        )
        required_sections_block = (
            "### Required sections (validator enforces all sections):\n"
            "- Script-owned: Affected Artifact, Reproduction Steps, Proof of Concept, Observed Evidence\n"
            "- Subagent-owned: Description, Impact, Attack Vector, Severity, Likelihood, Remediation, Attack Surface, Tools & Versions\n"
            "- Required metadata values: CVSS and CWE must be concrete (no placeholders)\n"
            if slowpath_enabled
            else (
                "### Required sections (ALL must be present and non-empty):\n"
                "- Affected Artifact\n"
                "  - **Artifact** must be the FULL URL with protocol+host+path (e.g. `http://192.168.18.9/admin`), NOT a command name like `curl /`.\n"
                "  - **Original** must also be the full URL. **Local** is the path to evidence file.\n"
                "  - Artifact Hash is materialized by scripts from captures. It must be SHA256 or `N/A`.\n"
                "- Description — 1-3 substantive sentences explaining the vulnerability. Do NOT just repeat the title.\n"
                "- Impact — 2-4 lines, worst-case consequence first. Be specific about what an attacker gains.\n"
                "- Attack Vector — 1-3 lines describing how an attacker exploits this.\n"
                "- Reproduction Steps — exact commands with real IPs/ports from the engagement.\n"
                f"- Proof of Concept — save PoC script to {reqs_path}/finding-{finding_id}-poc.[ext]\n"
                "- Observed Evidence — table: Evidence | Location | Hash | Timestamp | Tool\n"
                "- Severity — CVSS v3.1 vector + score. Adjust the pre-populated vector to match actual impact.\n"
                "  Score each metric (AV/AC/PR/UI/S/C/I/A) based on real evidence, not defaults.\n"
                "  CVSS metric quick-map: AV=attack path, AC=exploit complexity, PR=privileges, UI=user interaction,\n"
                "  S=scope change, C/I/A=confidentiality/integrity/availability impact.\n"
                "- Likelihood — set only the level value (e.g. High/Medium/Low). No rationale text.\n"
                "- Remediation — specific, actionable fix for THIS vulnerability. Not generic advice.\n"
                "  Example: 'Add HTTP Basic Auth or session-based authentication to the /admin endpoint'\n"
                "  NOT: 'Add authentication/authorization checks'\n"
                "- Attack Surface — category of affected component\n"
                "- Tools & Versions"
            )
        )
        quality_rules_block = (
            f"- Do NOT read any files. Do NOT use Bash. Your only tool is Write.\n"
            f"- Write ONLY the 6 numbered fields to ./{finding_id}-output.md — one Write call, done.\n"
            f"- No markdown headers, no extra keys, just `1: value` through `6: value`.\n"
            f"- CWE field (1) must be the bare number only, e.g. `1: 22` not `1: CWE-22`.\n"
            f"- Never invent hashes. Keep script-materialized hash values; use `N/A` only when no hashable artifact exists.\n"
            f"- NEVER repeat the title as the description. Expand with technical detail.\n"
            f"- CVSS header table value must match the score in the Severity section.\n"
            f"- All IPs, ports, and URLs must come from the inlined evidence above — never invent them.\n"
            if slowpath_enabled
            else (
                f"- Do not use Bash in findings mode. Use Read to check files, then Write/Edit to update records.\n"
                f"- Reproduction Steps and PoC commands must use exact executed commands from {captures_log_path}.\n"
                f"- Evidence must quote exact proving lines from {artifacts_raw_path}/ output (no invented values).\n"
                f"- If FASTPATH or SLOWPATH is enabled, never edit system-managed sections listed at the top.\n"
                f"- Never invent hashes. Keep script-materialized hash values; use `N/A` only when no hashable artifact exists.\n"
                f"- NEVER repeat the title as the description. Expand with technical detail.\n"
                f"- CVSS header table value must match the score in the Severity section.\n"
                f"- All IPs, ports, and URLs must come from INTEL.md — never invent them.\n"
            )
        )

        output_path = str(self.bra_state_dir / "artifacts" / f"{finding_id}-output.md")

        if slowpath_enabled:
            return (
                f"FINDING DOCUMENTATION REQUIRED — You are blocked from other work.\n\n"
                f"## Target: FINDING-{finding_id} — {title} ({severity})\n\n"
                f"All evidence is inlined below. Do NOT read any files. Do NOT use Bash.\n"
                f"Your only tool is Write. Make one Write call — then stop.\n\n"
                f"{inline_evidence_slim}"
                f"## Task\n\n"
                f"Write to: `{output_path}`\n\n"
                f"Using the evidence above, write the actual technical content for a professional "
                f"penetration testing report. Each field should be a natural paragraph of 2-4 sentences "
                f"with real, specific detail from the evidence.\n\n"
                f"Field 1 — CWE: bare integer only (e.g. 22)\n"
                f"Field 2 — Description: what is broken, where it exists in the target, and why it is "
                f"exploitable. Do not restate the title.\n"
                f"Field 3 — Impact: worst-case consequence first, then what specific data or access an "
                f"attacker gains. Reference actual endpoints or files from the evidence.\n"
                f"Field 4 — Attack Vector: the exact endpoint, parameter, and command from the evidence "
                f"that demonstrates exploitation.\n"
                f"Field 5 — Remediation: specific code/config fix — input validation, allowlisting, or "
                f"access controls for this exact vulnerability. Not generic advice.\n"
                f"Field 6 — Tools & Versions: tools used in testing and the target software version if "
                f"known from the evidence.\n\n"
                f"Output format — each field starts with its number and a colon. "
                f"Multi-line values are fine; the next field starts when a new number appears:\n"
                f"```\n"
                f"1: 22\n"
                f"2: First sentence describing the vulnerability.\n"
                f"Second sentence with more technical detail.\n"
                f"3: Worst-case impact sentence.\n"
                f"Second sentence about specific data exposed.\n"
                f"4: Attack vector sentence with exact curl command.\n"
                f"5: Specific remediation action.\n"
                f"Second sentence on implementation detail.\n"
                f"6: curl 7.x / lighttpd 1.4.x\n"
                f"```\n\n"
                f"## Rules\n\n"
                f"- CWE (field 1): bare integer only. `1: 22` — not `CWE-22`.\n"
                f"- Fields 2-5: write actual technical content, 2-4 sentences each.\n"
                f"- All values from the inlined evidence — never invent IPs, paths, or versions.\n"
                f"- No markdown headers, no extra fields. Just fields 1-6.\n"
            )

        return (
            f"FINDING DOCUMENTATION REQUIRED — You are blocked from other work.\n\n"
            f"## Current Target: FINDING-{finding_id}\n\n"
            f"**{title}** ({severity})\n\n"
            f"{fastpath_note}"
            f"{slowpath_note}"
            f"{ownership_block}"
            f"## Key Paths\n\n"
            f"| What | Path |\n"
            f"|------|------|\n"
            f"| FINDINGS record file | {findings_path_rel} |\n"
            f"| Pre-built evidence | {reqs_path_rel}/finding-{finding_id}-evidence.txt |\n"
            f"| PoC scripts | {reqs_path_rel}/finding-{finding_id}-poc.[ext] |\n\n"
            f"{skeleton_instruction_block}"
            f"{documented_block}"
            f"{system_context_snapshot}"
            f"{inline_evidence}"
            f"## Workflow\n\n"
            f"{workflow_block}"
            f"Use the optional prompt snippets below only as orientation; source of truth is file content.\n\n"
            f"## Required Schema\n\n"
            f"{required_sections_block}\n\n"
            f"### QUALITY RULES — violations cause re-work:\n"
            f"{quality_rules_block}\n"
            f"### Required metadata in header table:\n"
            f"ID, Title, Severity, CVSS, CWE, Status\n\n"
            f"## Assigned Finding\n\n"
            f"{queue_block}\n\n"
            f"If details are unknown, write 'Unknown (pending capture)' and continue.\n"
            f"Do not ask follow-up questions; clear this finding first.\n"
        )

    def _build_inline_evidence(
        self,
        finding_id: str,
        max_chars_per_evidence: int = 4000,
        skip_skeleton: bool = False,
        section_header: str = "## Optional Prompt Snippets\n\nBounded snippets are provided for orientation only.\nAll evidence needed is already inlined in this prompt — do NOT read any files.\n\n",
    ) -> str:
        """Build a lightweight, finding-scoped prompt context block.

        Includes only:
        1. The current finding skeleton from FINDINGS.md
        2. A bounded preview of finding-NNN-evidence.txt (if present and non-trivial)
        3. A minimal provenance snapshot (if present)
        4. Fallback: best matching raw artifact excerpt when evidence is metadata-only

        Never inlines full captures.log, raw artifact directories, or INTEL.md.
        """
        normalized_id = self._normalize_finding_id(finding_id)
        sections: list[str] = []

        # Fetch the pending finding record so we can resolve capture artifacts
        finding = next((f for f in self.pending_queue if f.id == normalized_id), None)

        # Always inline the skeleton first so subagent knows what to fill
        if not skip_skeleton and self.findings_path.exists():
            try:
                fmd = self.findings_path.read_text(errors="replace")
                pat = re.compile(
                    rf'(## \[FINDING-{re.escape(normalized_id)}\].*?)(?=\n## \[FINDING-|\Z)',
                    re.DOTALL,
                )
                m = pat.search(fmd)
                if m:
                    sections.append(
                        f"### Skeleton to fill in — FINDING-{normalized_id}\n"
                        f"```markdown\n{m.group(1).strip()}\n```"
                    )
            except Exception:
                pass

        # 1. Minimal provenance snapshot, if present.
        context_file = self.reqs_dir / f"finding-{normalized_id}-context.md"
        if context_file.exists():
            try:
                content = context_file.read_text(errors="replace").strip()
                if content:
                    sections.append(
                        f"### Main-agent context: {self._relative_to_workspace(context_file)}\n"
                        f"```markdown\n{content}\n```"
                    )
            except Exception:
                pass

        # 2. Bounded preview of pre-built evidence file.
        evidence_file = self.reqs_dir / f"finding-{normalized_id}-evidence.txt"
        evidence_is_useful = False
        if evidence_file.exists():
            try:
                content = evidence_file.read_text(errors="replace").strip()
                if content and not self._is_metadata_only_evidence(content):
                    evidence_is_useful = True
                    if len(content) > max_chars_per_evidence:
                        content = (
                            content[:max_chars_per_evidence]
                            + "\n... [truncated — read the evidence file for full content]"
                        )
                    sections.append(
                        f"### Pre-built evidence: {evidence_file}\n"
                        f"```\n{content}\n```"
                    )
            except Exception:
                pass

        # 3. Fallback: if the evidence file is metadata-only, inline the raw artifact.
        # First try parsing "Raw artifact: <path>" from the evidence file itself,
        # then fall back to source_hint resolution.
        if not evidence_is_useful:
            raw_artifact = None
            raw_rel = None
            # Parse "Raw artifact: .bra/artifacts/raw/..." from evidence file
            try:
                evidence_file_path = self.reqs_dir / f"finding-{normalized_id}-evidence.txt"
                if evidence_file_path.exists():
                    for line in evidence_file_path.read_text(errors="replace").splitlines():
                        if line.startswith("Raw artifact:"):
                            rel = line.split(":", 1)[1].strip()
                            candidate = self.bra_state_dir.parent / rel
                            if candidate.exists():
                                raw_artifact = candidate
                                raw_rel = rel
                            break
            except Exception:
                pass
            # Fall back to source_hint resolution
            if raw_artifact is None and finding:
                try:
                    source_hint = self._extract_source_hint(finding.source_marker)
                    source_hint = self._resolve_source_hint_from_capture(source_hint, finding.source_marker)
                    candidate = self._find_best_raw_evidence_artifact(source_hint, finding.source_marker)
                    if candidate and candidate.exists():
                        raw_artifact = candidate
                        raw_rel = self._relative_to_workspace(candidate)
                except Exception:
                    pass
            if raw_artifact is not None:
                try:
                    raw_content = raw_artifact.read_text(errors="replace").strip()
                    if raw_content:
                        if len(raw_content) > max_chars_per_evidence:
                            raw_content = raw_content[:max_chars_per_evidence] + "\n... [truncated]"
                        sections.append(
                            f"### Raw capture artifact: {raw_rel}\n"
                            f"```\n{raw_content}\n```"
                        )
                except Exception:
                    pass

        if not sections:
            return ""

        return section_header + "\n\n".join(sections) + "\n\n"

    @staticmethod
    def _clip_prompt_text(text: str, max_chars: int) -> str:
        """Clip long prompt snippets with an explicit truncation marker."""
        raw = (text or "").strip()
        if len(raw) <= max_chars:
            return raw
        return raw[:max_chars] + "\n... [truncated]"

    def _build_system_context_snapshot(self, finding_id: str, max_chars_per_section: int = 1200) -> str:
        """Build compact read-only context from script-owned sections."""
        if not self.findings_path.exists():
            return ""
        content = self.findings_path.read_text(errors="replace")
        finding_slice = self._extract_finding_slice(content, self._normalize_finding_id(finding_id))
        if not finding_slice:
            return ""
        _, _, finding_content = finding_slice

        id_value = self._extract_metadata_value(finding_content, "ID") or f"FINDING-{finding_id}"
        severity_value = self._extract_metadata_value(finding_content, "Severity") or "Unknown"
        cvss_value = self._extract_metadata_value(finding_content, "CVSS") or "Unknown"
        cwe_value = self._extract_metadata_value(finding_content, "CWE") or "Unknown"

        sections: list[str] = []
        for section_name in self.SYSTEM_MANAGED_SECTIONS:
            body = self._extract_section_content(finding_content, section_name)
            if not body:
                continue
            sections.append(
                f"### {section_name} (read-only)\n"
                f"```markdown\n{self._clip_prompt_text(body, max_chars_per_section)}\n```"
            )

        if not sections:
            return ""

        return (
            "## Script Context (Read-only)\n\n"
            "These fields are script-owned. Use them as factual inputs for narrative/CVSS work.\n\n"
            f"- ID: {id_value}\n"
            f"- Severity: {severity_value}\n"
            f"- CVSS (current): {cvss_value}\n"
            f"- CWE (current): {cwe_value}\n\n"
            + "\n\n".join(sections)
            + "\n\n"
        )

    def check_undocumented(self) -> list["PendingFinding"]:
        """Check for findings in INTEL.md that lack records in FINDINGS.md.

        Reads INTEL.md for finding IDs in Key Issues Overview table,
        reads FINDINGS.md for ## [FINDING-XXX] headers, returns the diff.
        """
        intel_ids: set[str] = set()
        findings_ids: set[str] = set()
        findings_titles: dict[str, str] = {}
        key_issues_idx: int = -1

        # Parse INTEL.md finding IDs (only from Key Issues Overview section)
        if self.intel_path.exists():
            content = self.intel_path.read_text()
            key_issues_idx = content.find("## Key Issues Overview")
            if key_issues_idx != -1:
                for match in re.finditer(r'\|\s*(\d{3})\s*\|', content[key_issues_idx:]):
                    intel_ids.add(match.group(1))

        # Parse FINDINGS.md finding IDs
        if self.findings_path.exists():
            content = self.findings_path.read_text()
            for match in re.finditer(r'## \[FINDING-(\d{3})\]\s*(.*)', content):
                findings_ids.add(match.group(1))
                findings_titles[self._normalize_title(match.group(2))] = match.group(1)

        # Diff — findings in INTEL but not in FINDINGS, excluding already-completed IDs
        undocumented_ids = intel_ids - findings_ids - self._completed_ids

        result = []
        if undocumented_ids and self.intel_path.exists():
            content = self.intel_path.read_text()
            for uid in sorted(undocumented_ids):
                # Extract title and severity from table row
                row_pattern = rf'\|\s*{uid}\s*\|\s*([^|]*)\|\s*\*?\*?([^|*]*)\*?\*?\s*\|'
                row_match = re.search(row_pattern, content)
                title = row_match.group(1).strip() if row_match else "Unknown"
                severity = row_match.group(2).strip() if row_match else "INFO"
                result.append(PendingFinding(
                    id=uid,
                    severity=severity,
                    title=title,
                    source_marker=f"[FINDING] {severity}: {title}",
                ))

        # Fallback path: parse "## Vulns" table ONLY when the Key Issues Overview
        # section is entirely absent. If KIO exists and all IDs are documented,
        # result=[] is the correct answer — do NOT scan Vulnerabilities table.
        if not result and key_issues_idx == -1 and self.intel_path.exists():
            content = self.intel_path.read_text()
            vuln_match = re.search(
                r'##\s*(?:Vulns|Vulnerabilities)\s*\n+(\|.+)\n\|[-|\s]+\n((?:\|.+\n?)+)',
                content,
                re.IGNORECASE,
            )
            if vuln_match:
                header_cells = [
                    cell.strip().lower()
                    for cell in vuln_match.group(1).split("|")
                    if cell.strip()
                ]
                id_idx = next(
                    (i for i, cell in enumerate(header_cells) if cell in {"id", "finding id"}),
                    None,
                )
                title_idx = next(
                    (i for i, cell in enumerate(header_cells) if cell == "title"),
                    0 if header_cells else None,
                )
                severity_idx = next(
                    (i for i, cell in enumerate(header_cells) if cell == "severity"),
                    None,
                )
                pending_by_title = {
                    self._normalize_title(pf.title): pf
                    for pf in self.pending_queue
                }
                pending_by_id = {
                    self._normalize_finding_id(pf.id): pf
                    for pf in self.pending_queue
                }
                max_id = self.next_finding_id() - 1

                for row in vuln_match.group(2).strip().splitlines():
                    cells = [c.strip() for c in row.split("|") if c.strip()]
                    if len(cells) < 2:
                        continue

                    if title_idx is not None and title_idx < len(cells):
                        title = cells[title_idx].strip()
                    else:
                        title = cells[0].strip()
                    if not title:
                        continue

                    _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
                    raw_sev = ""
                    if severity_idx is not None and severity_idx < len(cells):
                        raw_sev = re.sub(r"[*_`]", "", cells[severity_idx]).strip().upper()
                    if raw_sev in _VALID_SEVERITIES:
                        severity = raw_sev
                    else:
                        severity = "INFO"
                        for cell in cells[1:]:
                            sev_match = re.search(
                                r'Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)',
                                cell,
                                re.IGNORECASE,
                            )
                            if sev_match:
                                severity = sev_match.group(1).upper()
                                break
                    norm_title = self._normalize_title(title)
                    row_id = ""
                    if id_idx is not None and id_idx < len(cells):
                        raw_id = cells[id_idx].strip()
                        digit_match = re.search(r"(\d{1,3})", raw_id)
                        if digit_match:
                            row_id = self._normalize_finding_id(digit_match.group(1))

                    # Skip if already documented
                    if norm_title in findings_titles:
                        continue
                    if row_id and row_id in findings_ids:
                        continue
                    if row_id and row_id in self._completed_ids:
                        continue

                    # Reuse existing pending ID for same title if available
                    existing_pending_by_id = pending_by_id.get(row_id) if row_id else None
                    if existing_pending_by_id:
                        result.append(existing_pending_by_id)
                        continue
                    existing_pending = pending_by_title.get(norm_title)
                    if existing_pending:
                        result.append(existing_pending)
                        continue

                    if row_id:
                        fid = row_id
                    else:
                        max_id += 1
                        fid = f"{max_id:03d}"
                    result.append(
                        PendingFinding(
                            id=fid,
                            severity=severity,
                            title=title,
                            source_marker=f"[FINDING] {severity}: {title}",
                        )
                    )

        return result

    def check_and_dequeue_completed(self) -> list[str]:
        """Validate pending findings and dequeue any that pass.

        Called after a Write/Edit to FINDINGS.md so the lock is
        released once the record is complete.

        Returns:
            List of finding IDs that were dequeued.
        """
        if not self.pending_queue:
            return []

        dequeued: list[str] = []
        # Work on a copy since dequeue_finding mutates the list
        for pf in list(self.pending_queue):
            if self.is_fastpath_enabled() or self.is_slowpath_enabled():
                self.materialize_system_sections(pf)
            if not self.is_slowpath_enabled():
                self._autofill_finding_record_defaults(pf)
            self._normalize_likelihood_for_finding(pf.id)
            result = self.validate_finding_record(pf.id)
            if result.valid:
                self.dequeue_finding(pf.id)
                dequeued.append(pf.id)
        return dequeued

    def next_finding_id(self) -> int:
        """Get the next finding ID by reading INTEL.md and FINDINGS.md."""
        max_id = 0
        # Check INTEL.md
        if self.intel_path.exists():
            content = self.intel_path.read_text()
            for m in re.findall(r'\|\s*(\d{3})\s*\|', content):
                max_id = max(max_id, int(m))
        # Check FINDINGS.md
        if self.findings_path.exists():
            content = self.findings_path.read_text()
            for m in re.findall(r'## \[FINDING-(\d{3})\]', content):
                max_id = max(max_id, int(m))
        # Check pending queue
        for pf in self.pending_queue:
            try:
                max_id = max(max_id, int(pf.id))
            except ValueError:
                pass
        return max_id + 1
