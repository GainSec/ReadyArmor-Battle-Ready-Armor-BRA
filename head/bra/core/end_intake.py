"""Shared End Engagement intake helpers.

Single source of truth for report-type selection, inferred defaults,
required metadata, validation, and profile persistence.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any


REPORT_TYPES: tuple[str, ...] = ("generic", "vendor", "cna")

REPORT_TYPE_LABELS: dict[str, str] = {
    "generic": "Pen Test",
    "vendor": "Vendor/Client",
    "cna": "Research/CNA",
}

FIELD_LABELS: dict[str, str] = {
    "research_target": "Research Target",
    "vendor_name": "Vendor/Client",
    "firmware_version": "Firmware/Version",
    "researcher_name": "Consultant/Tester",
    "researcher_email": "Researcher Email",
    "pgp_key_id": "PGP Key",
    "vendor_contact": "Vendor/Client Contact",
}

ENV_KEY_MAP: dict[str, str] = {
    "research_target": "RESEARCH_TARGET",
    "vendor_name": "VENDOR_NAME",
    "firmware_version": "FIRMWARE_VERSION",
    "researcher_name": "RESEARCHER_NAME",
    "researcher_email": "RESEARCHER_EMAIL",
    "pgp_key_id": "PGP_KEY_ID",
    "vendor_contact": "VENDOR_CONTACT",
    "report_types": "REPORT_TYPES",
}

_ENV_TO_FIELD = {v: k for k, v in ENV_KEY_MAP.items()}


def normalize_report_types(value: Any) -> list[str]:
    """Normalize report type selection into a stable ordered list."""
    raw: list[str] = []
    if value is None:
        raw = []
    elif isinstance(value, str):
        raw = [part.strip().lower() for part in value.split(",")]
    else:
        for item in value:
            raw.append(str(item).strip().lower())

    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        if item in REPORT_TYPES and item not in seen:
            out.append(item)
            seen.add(item)

    if not out:
        return ["generic", "vendor", "cna"]
    return out


def _parse_shell_scalar(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        return value.strip("'").strip('"')
    if not tokens:
        return ""
    return tokens[0]


def _extract_scope_field(scope_content: str, label: str) -> str:
    pattern = rf"^\s*[-*]?\s*\*\*{re.escape(label)}:\*\*\s*(.+?)\s*$"
    match = re.search(pattern, scope_content, re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip()


def _infer_project_name(layer3_dir: Path, scope_content: str) -> str:
    """Infer project/target name for disclosure metadata."""
    scoped = _extract_scope_field(scope_content, "Name")
    if scoped and "_TBD" not in scoped:
        return scoped

    body_root = layer3_dir.parent
    project_root = body_root.parent if body_root.name == "body" else body_root
    return project_root.name.strip()


def profile_path(layer3_dir: Path) -> Path:
    return layer3_dir / "disclosure" / ".disclosure-profile.env"


def load_end_profile(layer3_dir: Path) -> dict[str, str]:
    """Load existing disclosure profile values from .env file."""
    profile_file = profile_path(layer3_dir)
    profile: dict[str, str] = {}
    if not profile_file.exists():
        return profile

    for raw in profile_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        field = _ENV_TO_FIELD.get(key.strip())
        if not field:
            continue
        profile[field] = _parse_shell_scalar(val)
    return profile


def infer_defaults(layer3_dir: Path) -> dict[str, str]:
    """Infer intake defaults from scope/profile/runtime artifacts."""
    profile = load_end_profile(layer3_dir)
    scope_file = layer3_dir / "SCOPE.md"
    scope_content = scope_file.read_text(encoding="utf-8") if scope_file.exists() else ""

    defaults: dict[str, str] = {
        # Research target is owned by project identity, not manual intake edits.
        "research_target": _infer_project_name(layer3_dir, scope_content) or profile.get("research_target", ""),
        "vendor_name": profile.get("vendor_name", "") or _extract_scope_field(scope_content, "Vendor"),
        "firmware_version": profile.get("firmware_version", "") or _extract_scope_field(scope_content, "Version"),
        "researcher_name": profile.get("researcher_name", ""),
        "researcher_email": profile.get("researcher_email", ""),
        "pgp_key_id": profile.get("pgp_key_id", ""),
        "vendor_contact": profile.get("vendor_contact", ""),
        "report_types": ",".join(
            normalize_report_types(profile.get("report_types", "generic,vendor,cna"))
        ),
    }
    return defaults


def required_fields_for_types(report_types: list[str], values: dict[str, str] | None = None) -> list[str]:
    """Compute required intake fields for selected report types.

    Current policy:
    - Research target is inferred from project identity and never prompted.
    - Researcher name is required only for CNA/research outputs.
    - Vendor/cna outputs require vendor + researcher contact fields.
    - Firmware/version is infer-only for now (not required/prompted).
    """
    required: list[str] = []

    if "cna" in report_types:
        required.append("researcher_name")

    if "vendor" in report_types or "cna" in report_types:
        required.extend(
            [
                "vendor_name",
                "researcher_email",
                "pgp_key_id",
                "vendor_contact",
            ]
        )

    # de-duplicate while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for key in required:
        if key not in seen:
            ordered.append(key)
            seen.add(key)
    return ordered


def visible_fields_for_types(report_types: list[str]) -> list[str]:
    """Compute metadata fields to render in intake forms for selected report types."""
    visible: list[str] = ["researcher_name"]

    if "vendor" in report_types or "cna" in report_types:
        visible.extend(
            [
                "vendor_name",
                "researcher_email",
                "pgp_key_id",
                "vendor_contact",
            ]
        )

    # De-duplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for key in visible:
        if key not in seen:
            ordered.append(key)
            seen.add(key)
    return ordered


def field_labels_for_types(report_types: list[str]) -> dict[str, str]:
    """Resolve dynamic UI labels for selected report types."""
    labels = dict(FIELD_LABELS)
    if "cna" in report_types:
        labels["researcher_name"] = "Researcher Name"
    elif "vendor" in report_types:
        labels["researcher_name"] = "Researcher/Consultant"
    else:
        labels["researcher_name"] = "Consultant/Tester"
    return labels


def build_end_intake_payload(
    layer3_dir: Path,
    report_types: list[str] | str | None = None,
) -> dict[str, Any]:
    """Build full intake payload for UI rendering."""
    defaults = infer_defaults(layer3_dir)
    selected = normalize_report_types(report_types or defaults.get("report_types"))
    fields = {k: v for k, v in defaults.items() if k != "report_types"}
    required = required_fields_for_types(selected, fields)
    missing = [k for k in required if not (fields.get(k) or "").strip()]

    return {
        "phase": "end_intake",
        "report_types": selected,
        "report_type_labels": REPORT_TYPE_LABELS,
        "fields": fields,
        "visible_fields": visible_fields_for_types(selected),
        "required_fields": required,
        "missing_fields": missing,
        "field_labels": field_labels_for_types(selected),
    }


def validate_end_intake_submission(
    layer3_dir: Path,
    report_types: list[str] | str | None,
    submitted_fields: dict[str, Any] | None,
) -> tuple[dict[str, str], list[str], list[str]]:
    """Validate submission and return normalized profile values.

    Returns:
        (profile_values, missing_fields, required_fields)
    """
    defaults = infer_defaults(layer3_dir)
    selected = normalize_report_types(report_types or defaults.get("report_types"))

    profile: dict[str, str] = {}
    for key in FIELD_LABELS:
        submitted_val = ""
        if isinstance(submitted_fields, dict):
            submitted_val = str(submitted_fields.get(key, "") or "").strip()
        profile[key] = submitted_val or str(defaults.get(key, "") or "").strip()

    # Keep research_target pinned to inferred project identity.
    profile["research_target"] = str(defaults.get("research_target", "") or "").strip()

    profile["report_types"] = ",".join(selected)

    required = required_fields_for_types(selected, profile)
    missing = [k for k in required if not (profile.get(k) or "").strip()]
    return profile, missing, required


def save_end_profile(layer3_dir: Path, profile: dict[str, str]) -> Path:
    """Persist normalized intake profile to disclosure/.disclosure-profile.env."""
    out = profile_path(layer3_dir)
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Disclosure profile generated by End Engagement intake"]
    for field, env_key in ENV_KEY_MAP.items():
        value = str(profile.get(field, "") or "")
        lines.append(f"{env_key}={shlex.quote(value)}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
