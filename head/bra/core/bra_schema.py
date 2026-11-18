"""Canonical .bra/ directory schema.

Single source of truth for what paths are valid inside .bra/ and their
access policies. All enforcement points (filesystem.py, file_hook.py,
file-guard.py) derive their rules from this schema.

Access levels:
    agent-writable  — Agent (Write/Edit tools) + system code
    append-only     — System code only, byte-size enforcement (logs)
    operator-only   — Operator via TUI/approval flow only
    system-only     — Governance scripts + head Python code only
"""

ACCESS_LEVELS = frozenset({
    "agent-writable",
    "append-only",
    "operator-only",
    "system-only",
})

# Schema entries. Keys ending in "/" are directories (match any sub-path).
# Keys without "/" are exact file matches.
BRA_SCHEMA: dict[str, dict[str, str]] = {
    # Agent-writable
    "artifacts/":              {"access": "agent-writable"},

    # Append-only (audit trail)
    "logs/":                   {"access": "append-only"},

    # Operator-only (approval tokens)
    "approvals/":              {"access": "operator-only"},
    "one-time-approvals/":     {"access": "operator-only"},
    "overrides.json":          {"access": "operator-only"},
    "anon_map.json":           {"access": "operator-only"},
    "TOOL_APPROVAL_DISABLED":  {"access": "operator-only"},
    "config/":                 {"access": "operator-only"},

    # System-only (governance state)
    "pipeline_state.json":     {"access": "system-only"},
    "hunt_state.json":         {"access": "system-only"},
    "improvement_state.json":  {"access": "system-only"},
    "engagement_meta.json":    {"access": "system-only"},
    "approved_targets.json":   {"access": "system-only"},
    "paths-remote.md":         {"access": "system-only"},
    "PRECHECK_REPORT.md":      {"access": "system-only"},
    "phase_context.md":        {"access": "system-only"},
    "last_capture.json":       {"access": "system-only"},
    "service_state.json":      {"access": "system-only"},
    "web-config.json":         {"access": "system-only"},
    "pending_findings.json":   {"access": "system-only"},
    "report_findings_filter.json": {"access": "system-only"},
    "STOP":                    {"access": "system-only"},
    "improvements/":           {"access": "system-only"},
    "locks/":                  {"access": "system-only"},
    "dry-run/":                {"access": "system-only"},
    "phase_state/":            {"access": "system-only"},
    "specs/":                  {"access": "system-only"},
    "ui/":                     {"access": "system-only"},
    "snapshots/":              {"access": "system-only"},
    "tmp/":                    {"access": "system-only"},
    ".claude/":                {"access": "system-only"},
    ".config/":                {"access": "system-only"},
    ".cache/":                 {"access": "system-only"},
    ".local/":                 {"access": "system-only"},
    ".ner-cache/":             {"access": "system-only"},
}


def resolve_access(rel_path: str) -> str | None:
    """Resolve a .bra/-relative path to its access level.

    Args:
        rel_path: Path relative to .bra/ (e.g., "artifacts/raw/scan.txt")

    Returns:
        Access level string, or None if path is not in the schema.
    """
    # Exact file match first
    if rel_path in BRA_SCHEMA:
        return BRA_SCHEMA[rel_path]["access"]

    # Directory prefix match (keys ending in "/")
    for schema_path, meta in BRA_SCHEMA.items():
        if schema_path.endswith("/") and rel_path.startswith(schema_path):
            return meta["access"]

    return None
