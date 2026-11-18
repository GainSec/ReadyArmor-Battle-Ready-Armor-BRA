"""Overrides — engagement-duration auto-approve rules.

Stores operator-defined rules in .bra/overrides.json.
When a block is detected, OverrideManager.match() checks for a
matching rule. If found, the operation is auto-approved without
prompting the operator.

Kill switch ALWAYS overrides these rules.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bra.core.approval import BlockedOperation


class OverrideManager:
    """Manages engagement-duration auto-approve rules."""

    def __init__(self, bra_root: Path):
        self.bra_root = bra_root
        self.path = bra_root / "overrides.json"
        self._recommendations_cache: list[dict] | None = None

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def _load(self) -> list[dict]:
        """Load rules from file. Returns [] on any error."""
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict) or "rules" not in data:
                return []
            return data["rules"]
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, rules: list[dict]) -> None:
        """Persist rules to file."""
        self.bra_root.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"rules": rules}, indent=2) + "\n")

    def _next_id(self, rules: list[dict]) -> str:
        """Generate next sequential ID (so-001, so-002, ...)."""
        max_num = 0
        for r in rules:
            rid = r.get("id", "")
            if rid.startswith("so-"):
                try:
                    max_num = max(max_num, int(rid[3:]))
                except ValueError:
                    pass
        return f"so-{max_num + 1:03d}"

    # ------------------------------------------------------------------
    # Token check
    # ------------------------------------------------------------------

    def _has_override_token(self) -> bool:
        """Check if OVERRIDE-APPROVAL token is present."""
        return (self.bra_root / "approvals" / "OVERRIDE-APPROVAL").exists()

    def _require_override_token(self) -> None:
        """Raise PermissionError if OVERRIDE-APPROVAL token is missing."""
        if not self._has_override_token():
            raise PermissionError(
                "OVERRIDE-APPROVAL token required to modify overrides"
            )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, rule_type: str, match: dict, action: str, layer: str = "3") -> str:
        """Add an override rule. Returns rule ID."""
        self._require_override_token()
        rules = self._load()
        rule_id = self._next_id(rules)
        rules.append({
            "id": rule_id,
            "type": rule_type,
            "match": match,
            "action": action,
            "enabled": True,
            "layer": layer,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": "operator",
        })
        self._save(rules)
        return rule_id

    def remove(self, rule_id: str) -> bool:
        """Remove an override rule by ID. Returns True if found."""
        self._require_override_token()
        rules = self._load()
        new_rules = [r for r in rules if r.get("id") != rule_id]
        if len(new_rules) == len(rules):
            return False
        self._save(new_rules)
        return True

    def disable(self, rule_id: str) -> bool:
        """Disable an override rule by ID. Returns True if found."""
        self._require_override_token()
        rules = self._load()
        for r in rules:
            if r.get("id") == rule_id:
                r["enabled"] = False
                self._save(rules)
                return True
        return False

    def enable(self, rule_id: str) -> bool:
        """Enable an override rule by ID. Returns True if found."""
        self._require_override_token()
        rules = self._load()
        for r in rules:
            if r.get("id") == rule_id:
                r["enabled"] = True
                self._save(rules)
                return True
        return False

    def remove_all(self) -> None:
        """Remove all override rules."""
        self._require_override_token()
        self._save([])

    def list_all(self) -> list[dict]:
        """Return all active override rules."""
        return self._load()

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(self, blocked: "BlockedOperation") -> dict | None:
        """Check if an override rule covers this block.

        Returns the matching rule dict, or None if no match
        (or kill switch is active).
        """
        if self._is_killswitch_active():
            return None

        rules = self._load()
        type_str = blocked.approval_type.value.upper()

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("type") != type_str:
                continue
            if self._matches(rule, blocked):
                return rule

        return None

    def _matches(self, rule: dict, blocked: "BlockedOperation") -> bool:
        """Check if a rule's match criteria cover this blocked operation."""
        match = rule.get("match", {})
        type_str = rule.get("type", "")

        if type_str == "TOKEN":
            return match.get("token") == blocked.token_name

        if type_str in ("SCOPE_ADD", "SCOPE_UPGRADE"):
            # Empty match = all targets
            return True

        if type_str == "TOOL":
            if match.get("tool_name") != blocked.tool_name:
                return False
            # Command is REQUIRED for TOOL overrides — a rule without a command
            # would blanket-approve every invocation of that tool.
            if "command" not in match:
                return False
            return match["command"] == blocked.command

        if type_str == "SCRIPT":
            # Empty match = all scripts; specific match = path must match
            if not match or not match.get("script_path"):
                return True
            return match.get("script_path") == blocked.script_path

        return False

    # ------------------------------------------------------------------
    # Cross-engagement recommendations (session-cached)
    # ------------------------------------------------------------------

    def check_recommendations(
        self,
        blocked: "BlockedOperation",
        overrides_md_path: "Path | None" = None,
    ) -> dict | None:
        """Check if a cross-engagement recommendation exists for this block.

        Session-cached: reads layer2-templates/overrides.md once per session.
        Returns the matching recommendation dict, or None.
        """
        if self._recommendations_cache is None:
            from bra.core.data_loaders import load_override_recommendations
            self._recommendations_cache = load_override_recommendations(overrides_md_path)

        type_str = blocked.approval_type.value.upper()

        for rec in self._recommendations_cache:
            if rec.get("type") != type_str:
                continue
            match = rec.get("match", {})

            if type_str == "TOKEN" and match.get("token") == blocked.token_name:
                return rec
            if type_str == "TOOL" and match.get("tool_name") == blocked.tool_name:
                return rec
            if type_str == "SCRIPT":
                if not match.get("script_path") or match.get("script_path") == blocked.script_path:
                    return rec
            if type_str in ("SCOPE_ADD", "SCOPE_UPGRADE"):
                return rec

        return None

    # ------------------------------------------------------------------
    # Audit trail — OVERRIDES.md decision recording
    # ------------------------------------------------------------------

    def record_decision(
        self,
        decision_type: str,
        subtype: str,
        decision: str,
        command: str = "",
        override_id: str | None = None,
        context: str = "",
        overrides_md_path: "Path | None" = None,
    ) -> None:
        """Append a structured decision entry to layer3-engagement/OVERRIDES.md.

        Args:
            decision_type: TOKEN, TOOL, SCRIPT, SCOPE_ADD, etc.
            subtype: Token name, tool name, or script path
            decision: APPROVED ONCE, APPROVED FOR ENGAGEMENT, or DENIED
            command: The command that triggered the decision
            override_id: Override rule ID if an engagement override was created
            context: Additional context for the decision
            overrides_md_path: Path to OVERRIDES.md. Defaults to layer3.
        """
        if overrides_md_path is None:
            from bra.config.settings import LAYER3
            overrides_md_path = LAYER3 / "OVERRIDES.md"

        if not overrides_md_path.exists():
            return

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        entry = f"\n### [{ts}] {decision_type} {subtype} — {decision}\n"
        if command:
            entry += f"- **Command:** `{command}`\n"
        if override_id:
            entry += f"- **Override ID:** {override_id}\n"
        if context:
            entry += f"- **Context:** {context}\n"

        with open(overrides_md_path, "a") as f:
            f.write(entry)

    def _is_killswitch_active(self) -> bool:
        """Check if kill switch is active (file-based only for speed)."""
        return (self.bra_root / "STOP").exists()
