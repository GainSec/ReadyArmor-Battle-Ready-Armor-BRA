"""Lightweight single-finding documentation probe using Claude Agent SDK.

Run with:
  PYTHONPATH=.:head python3 -m bra.core.finding_probe --help

Purpose:
- Collect one finding's context from BRA canonical locations
- Build a deterministic prompt for finding write-up quality checks
- Run one Claude SDK turn and print raw assistant output
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bra.config.settings import BODY_ROOT, get_anthropic_api_key
from bra.core.agent import run_agent


DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_ALLOWED_TOOLS = ["Read", "Glob", "Grep"]


@dataclass
class ProbeConfig:
    finding_id: str
    severity: str
    title: str
    source_marker: str
    notes_dir: Path
    bra_state_dir: Path
    schema_path: Path
    model: str | None
    max_file_chars: int
    max_context_chars: int
    context_files: list[Path]
    extra_context: list[str]
    extra_instructions: list[str]
    include_tools: bool


def _coerce_bra_root(path: Path) -> Path:
    """Accept either BRA root or body/ path and return BRA root."""
    candidate = path.expanduser().resolve()
    if (candidate / "body").exists():
        return candidate
    if candidate.name == "body":
        return candidate.parent
    return candidate


def _validate_bra_install(path: Path) -> tuple[bool, str, Path | None]:
    """Validate BRA installation path and return (ok, reason, bra_root)."""
    bra_root = _coerce_bra_root(path)
    body = bra_root / "body"
    required = [
        body / "layer1",
        body / "layer2-templates",
        body / "layer3-engagement" / "NOTES" / "INTEL.md",
        body / "layer3-engagement" / "NOTES" / "FINDINGS.md",
        body / ".bra",
    ]
    if not bra_root.exists():
        return False, f"path does not exist: {bra_root}", None
    missing = [p for p in required if not p.exists()]
    if missing:
        missing_render = ", ".join(str(p) for p in missing)
        return False, f"missing BRA required path(s): {missing_render}", None
    return True, "ok", bra_root


def _normalize_finding_id(value: str) -> str:
    text = str(value or "").strip()
    return text.zfill(3) if text.isdigit() else text


def _read_text_limited(path: Path, max_chars: int) -> str:
    try:
        text = path.read_text(errors="replace")
    except Exception as exc:
        return f"[read error: {exc}]"
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    return f"{truncated}\n\n[truncated to {max_chars} chars]"


def _extract_finding_block(findings_md: str, finding_id: str) -> str:
    pattern = re.compile(
        rf"##\s+\[FINDING-{re.escape(finding_id)}\][\s\S]*?(?=\n##\s+\[FINDING-|\Z)",
        re.IGNORECASE,
    )
    match = pattern.search(findings_md)
    return match.group(0).strip() if match else ""


def _extract_source_hint(source_marker: str) -> str:
    match = re.search(r"source:\s*(.+)$", source_marker or "", re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _split_markdown_row(line: str) -> list[str]:
    text = line.strip()
    if not text.startswith("|"):
        return []
    parts = [part.strip() for part in text.strip("|").split("|")]
    return parts


def _extract_finding_identity_from_intel(
    intel_text: str,
    finding_id: str,
) -> tuple[str, str, str]:
    """Return (severity, title, source_marker) from INTEL vulnerabilities table."""
    section_match = re.search(
        r"##\s+(?:Vulnerabilities|Vulns|Key Issues Overview)\s*\n([\s\S]*?)(?=\n##\s+|\Z)",
        intel_text,
        re.IGNORECASE,
    )
    section = section_match.group(1) if section_match else intel_text
    table_lines = [line for line in section.splitlines() if line.strip().startswith("|")]
    if len(table_lines) < 3:
        raise ValueError("INTEL.md vulnerabilities table not found or malformed.")

    header_cells = [cell.lower() for cell in _split_markdown_row(table_lines[0])]
    idx_by_name = {name: idx for idx, name in enumerate(header_cells)}
    for required in ("id", "title", "severity"):
        if required not in idx_by_name:
            raise ValueError(f"INTEL vulnerabilities table missing '{required}' column.")

    wanted = _normalize_finding_id(finding_id)
    for line in table_lines[2:]:
        cells = _split_markdown_row(line)
        if not cells:
            continue
        id_idx = idx_by_name["id"]
        if id_idx >= len(cells):
            continue
        row_id = _normalize_finding_id(cells[id_idx])
        if row_id != wanted:
            continue

        title = cells[idx_by_name["title"]].strip() if idx_by_name["title"] < len(cells) else ""
        severity = cells[idx_by_name["severity"]].strip().upper() if idx_by_name["severity"] < len(cells) else ""
        source = ""
        if "source" in idx_by_name and idx_by_name["source"] < len(cells):
            source = cells[idx_by_name["source"]].strip()
        if not title:
            raise ValueError(f"INTEL row {wanted} has empty title.")
        if not severity:
            severity = "INFO"
        if not source:
            source = "Unknown (pending capture)"
        source_marker = f"[FINDING] {title} | {severity} | source: {source}"
        return severity, title, source_marker

    raise ValueError(f"Finding ID {wanted} not found in INTEL vulnerabilities table.")


def _tokenize_for_match(title: str, source_marker: str) -> set[str]:
    tokens: set[str] = set()
    for chunk in re.split(r"[^A-Za-z0-9./:_-]+", f"{title} {source_marker}"):
        cleaned = chunk.strip().lower()
        if len(cleaned) >= 4 and cleaned not in {"http", "https", "finding", "source"}:
            tokens.add(cleaned)
    return tokens


def _score_raw_artifact(path: Path, tokens: set[str], source_hint: str) -> tuple[int, float]:
    name = path.name.lower()
    score = 0

    if name.startswith("curl_"):
        score += 2
    if source_hint and source_hint.lower() in name:
        score += 5

    for token in tokens:
        if token in name:
            score += 2

    try:
        sample = path.read_text(errors="replace")[:12000].lower()
    except Exception:
        sample = ""

    if source_hint and source_hint.lower() in sample:
        score += 7
    for token in tokens:
        if token in sample:
            score += 1

    return score, path.stat().st_mtime


def _choose_raw_artifacts(raw_dir: Path, title: str, source_marker: str, limit: int = 3) -> list[Path]:
    if not raw_dir.exists():
        return []
    tokens = _tokenize_for_match(title, source_marker)
    source_hint = _extract_source_hint(source_marker)
    scored: list[tuple[int, float, Path]] = []
    for candidate in raw_dir.glob("*"):
        if not candidate.is_file():
            continue
        score, mtime = _score_raw_artifact(candidate, tokens, source_hint)
        if score > 0:
            scored.append((score, mtime, candidate))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in scored[:limit]]


def _append_context_block(
    blocks: list[str],
    title: str,
    content: str,
    budget_used: int,
    budget_total: int,
) -> int:
    if not content.strip():
        return budget_used
    payload = f"### {title}\n```text\n{content.rstrip()}\n```\n"
    if budget_used + len(payload) > budget_total:
        remaining = max(0, budget_total - budget_used)
        if remaining < 120:
            return budget_used
        clipped = payload[:remaining]
        payload = f"{clipped}\n\n[context budget reached]\n"
    blocks.append(payload)
    return budget_used + len(payload)


def build_probe_prompt(config: ProbeConfig) -> str:
    finding_id = _normalize_finding_id(config.finding_id)
    findings_md_path = config.notes_dir / "FINDINGS.md"
    intel_md_path = config.notes_dir / "INTEL.md"
    reqs_dir = config.notes_dir / "reqs"
    pending_path = config.bra_state_dir / "pending_findings.json"
    raw_dir = config.bra_state_dir / "artifacts" / "raw"

    context_blocks: list[str] = []
    used = 0

    if config.schema_path.exists():
        used = _append_context_block(
            context_blocks,
            f"Schema ({config.schema_path})",
            _read_text_limited(config.schema_path, config.max_file_chars),
            used,
            config.max_context_chars,
        )

    if findings_md_path.exists():
        findings_md_text = _read_text_limited(findings_md_path, config.max_file_chars * 2)
        finding_block = _extract_finding_block(findings_md_text, finding_id)
        if finding_block:
            used = _append_context_block(
                context_blocks,
                f"Existing FINDING-{finding_id} block",
                finding_block,
                used,
                config.max_context_chars,
            )
        else:
            used = _append_context_block(
                context_blocks,
                "FINDINGS.md (head)",
                findings_md_text[: config.max_file_chars],
                used,
                config.max_context_chars,
            )

    if intel_md_path.exists():
        intel_text = _read_text_limited(intel_md_path, config.max_file_chars * 2)
        intel_rows = []
        for line in intel_text.splitlines():
            lowered = line.lower()
            if finding_id in line or config.title.lower() in lowered:
                intel_rows.append(line)
        used = _append_context_block(
            context_blocks,
            "INTEL.md matched lines",
            "\n".join(intel_rows) if intel_rows else "[no direct line match found]",
            used,
            config.max_context_chars,
        )

    if pending_path.exists():
        used = _append_context_block(
            context_blocks,
            f"Pending queue ({pending_path})",
            _read_text_limited(pending_path, config.max_file_chars),
            used,
            config.max_context_chars,
        )

    req_candidates = sorted(reqs_dir.glob(f"finding-{finding_id}-*")) if reqs_dir.exists() else []
    if req_candidates:
        for req_file in req_candidates:
            used = _append_context_block(
                context_blocks,
                f"Req artifact ({req_file.name})",
                _read_text_limited(req_file, config.max_file_chars),
                used,
                config.max_context_chars,
            )

    raw_candidates = _choose_raw_artifacts(raw_dir, config.title, config.source_marker)
    for raw_file in raw_candidates:
        used = _append_context_block(
            context_blocks,
            f"Raw artifact ({raw_file.name})",
            _read_text_limited(raw_file, config.max_file_chars),
            used,
            config.max_context_chars,
        )

    for extra_path in config.context_files:
        if extra_path.exists():
            used = _append_context_block(
                context_blocks,
                f"Extra context ({extra_path})",
                _read_text_limited(extra_path, config.max_file_chars),
                used,
                config.max_context_chars,
            )

    for idx, inline in enumerate(config.extra_context, start=1):
        used = _append_context_block(
            context_blocks,
            f"Inline context {idx}",
            inline,
            used,
            config.max_context_chars,
        )

    source_hint = _extract_source_hint(config.source_marker) or "Unknown (pending capture)"
    poc_file = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-poc.sh"
    evidence_file = f"layer3-engagement/NOTES/reqs/finding-{finding_id}-evidence.txt"

    additional_instructions = ""
    if config.extra_instructions:
        rendered = "\n".join(f"- {line}" for line in config.extra_instructions if str(line).strip())
        if rendered.strip():
            additional_instructions = f"\nOperator-supplied additional instructions:\n{rendered}\n"

    instructions = f"""You are the BRA documenting agent.

Task: Draft one complete finding package for FINDING-{finding_id} without placeholders.

Finding identity:
- ID: FINDING-{finding_id}
- Severity: {config.severity}
- Title: {config.title}
- Source marker: {config.source_marker}
- Source hint: {source_hint}

Hard requirements:
- Follow BRA findings schema sections exactly.
- Do not output metadata-only PoC or evidence.
- PoC must be executable shell content appropriate for `finding-{finding_id}-poc.sh`.
- Evidence must include concrete proof details, hash references, and artifact linkage.
- Include CVSS vector + score and explicit likelihood.
- Keep artifact references scoped to BRA paths.
- If data is missing, use `Unknown (pending capture)` rather than inventing facts.
{additional_instructions}

Output format (in this exact order):
1) `## [FINDING-{finding_id}] ...` markdown record only
2) `FILE: {poc_file}` followed by fenced `bash` code block
3) `FILE: {evidence_file}` followed by fenced `text` block
4) Short validation checklist (5 bullets max)
"""

    context = "\n".join(context_blocks) if context_blocks else "[no context files loaded]"
    return f"{instructions}\n\nContext pack:\n\n{context}\n"


def _message_text_chunks(message: Any) -> list[str]:
    chunks: list[str] = []

    if isinstance(message, dict):
        msg_type = message.get("type")
        if msg_type in {"assistant_text", "text"}:
            text = str(message.get("content", "")).strip()
            if text:
                chunks.append(text)
        return chunks

    msg_class = type(message).__name__
    if msg_class == "AssistantMessage":
        for block in getattr(message, "content", []) or []:
            text = getattr(block, "text", "")
            if text and str(text).strip():
                chunks.append(str(text))
        return chunks

    msg_type = getattr(message, "type", None)
    if msg_type == "text":
        text = getattr(message, "content", "")
        if text and str(text).strip():
            chunks.append(str(text))
    return chunks


def _render_event_detail(message: Any) -> str:
    """Return a compact text description of one SDK message/event."""
    if isinstance(message, dict):
        msg_type = str(message.get("type", "dict"))
        if msg_type == "tool_use":
            name = str(message.get("name", ""))
            tool_use_id = str(message.get("id", "") or message.get("tool_use_id", ""))
            tool_input = message.get("input", {})
            return f"dict:{msg_type} name={name} id={tool_use_id} input={tool_input}"
        if msg_type == "tool_result":
            content = str(message.get("content", ""))
            return f"dict:{msg_type} content={content[:240]}"
        if msg_type in {"assistant_text", "text", "error"}:
            content = str(message.get("content", ""))
            return f"dict:{msg_type} content={content[:240]}"
        return f"dict:{msg_type} payload_keys={sorted(message.keys())}"

    msg_class = type(message).__name__
    if msg_class == "AssistantMessage":
        parts = []
        for block in getattr(message, "content", []) or []:
            text = getattr(block, "text", "")
            if text and str(text).strip():
                parts.append(f"text={str(text)[:200]}")
                continue
            name = getattr(block, "name", "")
            block_input = getattr(block, "input", None)
            if name and isinstance(block_input, dict):
                parts.append(f"tool_use name={name} input={str(block_input)[:180]}")
        return f"{msg_class} " + " | ".join(parts or ["(no blocks)"])

    if msg_class == "UserMessage":
        parts = []
        for block in getattr(message, "content", []) or []:
            content = getattr(block, "content", "") or getattr(block, "text", "")
            is_error = bool(getattr(block, "is_error", False))
            parts.append(f"is_error={is_error} content={str(content)[:180]}")
        return f"{msg_class} " + " | ".join(parts or ["(no blocks)"])

    if msg_class == "ResultMessage":
        result = getattr(message, "result", "")
        is_error = bool(getattr(message, "is_error", False))
        return f"{msg_class} is_error={is_error} result={str(result)[:240]}"

    if msg_class == "SystemMessage":
        subtype = getattr(message, "subtype", "")
        data = getattr(message, "data", {})
        return f"{msg_class} subtype={subtype} data={str(data)[:180]}"

    msg_type = getattr(message, "type", "")
    if msg_type:
        content = getattr(message, "content", "")
        return f"{msg_class}:{msg_type} content={str(content)[:240]}"
    return msg_class


async def run_probe(
    config: ProbeConfig,
    *,
    show_events: bool = False,
    full_flow: bool = False,
) -> tuple[int, str]:
    prompt = build_probe_prompt(config)

    if show_events or full_flow:
        print("=== PROMPT START ===")
        print(prompt)
        print("=== PROMPT END ===")

    allowed_tools = DEFAULT_ALLOWED_TOOLS if config.include_tools else []
    output_parts: list[str] = []
    had_error = False

    async for message in run_agent(
        prompt=prompt,
        allowed_tools=allowed_tools,
        model=config.model,
    ):
        if isinstance(message, dict) and message.get("type") == "error":
            had_error = True
            err = str(message.get("content", "Unknown error"))
            print(f"[error] {err}", file=sys.stderr)
            continue

        if show_events or full_flow:
            if full_flow:
                print(f"[event] {_render_event_detail(message)}")
            else:
                if isinstance(message, dict):
                    event_name = message.get("type", "dict")
                else:
                    event_name = type(message).__name__
                print(f"[event] {event_name}")

        for chunk in _message_text_chunks(message):
            print(chunk, end="" if chunk.endswith("\n") else "\n", flush=True)
            output_parts.append(chunk)

    return (1 if had_error else 0), "\n".join(output_parts).strip()


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-finding Claude SDK probe for BRA finding write-up quality.",
    )
    parser.add_argument("--finding-id", required=True, help="Finding numeric ID, e.g. 001")
    parser.add_argument("--severity", default="", help="Severity, e.g. CRITICAL")
    parser.add_argument("--title", default="", help="Finding title")
    parser.add_argument("--source-marker", default="", help="Source marker string")
    parser.add_argument(
        "--valid-bra",
        default="",
        help=(
            "Validate BRA installation path and auto-resolve finding "
            "identity from INTEL.md so only --finding-id is required."
        ),
    )
    parser.add_argument(
        "--notes-dir",
        default=str(BODY_ROOT / "layer3-engagement" / "NOTES"),
        help="Path to NOTES directory",
    )
    parser.add_argument(
        "--bra-state-dir",
        default=str(BODY_ROOT / ".bra"),
        help="Path to .bra state directory",
    )
    parser.add_argument(
        "--schema-path",
        default=str(BODY_ROOT / "layer2-templates" / "reference" / "evidence" / "findings-schema.md"),
        help="Path to findings schema markdown",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Claude model override")
    parser.add_argument("--max-file-chars", type=int, default=6000, help="Per-file context limit")
    parser.add_argument("--max-context-chars", type=int, default=40000, help="Total context budget")
    parser.add_argument(
        "--context-file",
        action="append",
        default=[],
        help="Extra context file path (repeatable)",
    )
    parser.add_argument(
        "--extra-context",
        action="append",
        default=[],
        help="Inline context string (repeatable)",
    )
    parser.add_argument(
        "--instruction",
        action="append",
        default=[],
        help="Extra operator instruction to include in prompt (repeatable).",
    )
    parser.add_argument(
        "--prompt-only",
        action="store_true",
        help="Print the built prompt and exit without calling Claude",
    )
    parser.add_argument(
        "--show-events",
        action="store_true",
        help="Print SDK event type lines while streaming output",
    )
    parser.add_argument(
        "--full-flow",
        action="store_true",
        help="Print full prompt and detailed SDK event payloads/tool flow.",
    )
    parser.add_argument(
        "--no-tools",
        action="store_true",
        help="Disable tool use (default allows Read/Glob/Grep only).",
    )
    parser.add_argument(
        "--save-output",
        default="",
        help="Optional file path to save final assistant output text",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    notes_dir = Path(args.notes_dir).expanduser().resolve()
    bra_state_dir = Path(args.bra_state_dir).expanduser().resolve()
    schema_path = Path(args.schema_path).expanduser().resolve()

    severity = str(args.severity).strip()
    title = str(args.title).strip()
    source_marker = str(args.source_marker).strip()

    if args.valid_bra:
        if severity or title or source_marker:
            print(
                "With --valid-bra, do not pass --severity/--title/--source-marker. "
                "These are derived from INTEL.md.",
                file=sys.stderr,
            )
            return 1
        ok, reason, bra_root = _validate_bra_install(Path(args.valid_bra))
        if not ok or not bra_root:
            print(f"--valid-bra check failed: {reason}", file=sys.stderr)
            return 1
        body_root = bra_root / "body"
        notes_dir = body_root / "layer3-engagement" / "NOTES"
        bra_state_dir = body_root / ".bra"
        schema_path = body_root / "layer2-templates" / "reference" / "evidence" / "findings-schema.md"

        intel_path = notes_dir / "INTEL.md"
        intel_text = intel_path.read_text(errors="replace")
        try:
            severity, title, source_marker = _extract_finding_identity_from_intel(
                intel_text,
                _normalize_finding_id(args.finding_id),
            )
        except ValueError as exc:
            print(f"Failed to derive finding from INTEL.md: {exc}", file=sys.stderr)
            return 1
    else:
        if not severity or not title or not source_marker:
            print(
                "Without --valid-bra you must provide --severity, --title, and --source-marker.",
                file=sys.stderr,
            )
            return 1

    cfg = ProbeConfig(
        finding_id=_normalize_finding_id(args.finding_id),
        severity=severity,
        title=title,
        source_marker=source_marker,
        notes_dir=notes_dir,
        bra_state_dir=bra_state_dir,
        schema_path=schema_path,
        model=(str(args.model).strip() or None),
        max_file_chars=max(500, int(args.max_file_chars)),
        max_context_chars=max(2000, int(args.max_context_chars)),
        context_files=[Path(p).expanduser().resolve() for p in args.context_file],
        extra_context=[str(x) for x in args.extra_context],
        extra_instructions=[str(x) for x in args.instruction],
        include_tools=not args.no_tools,
    )

    if args.prompt_only:
        print(build_probe_prompt(cfg))
        return 0

    if not get_anthropic_api_key():
        print(
            "ANTHROPIC_API_KEY is not set (env or saved runtime config). "
            "Set it before running the probe.",
            file=sys.stderr,
        )
        return 1

    exit_code, output = asyncio.run(
        run_probe(
            cfg,
            show_events=args.show_events,
            full_flow=args.full_flow,
        )
    )

    if args.save_output:
        out_path = Path(args.save_output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output + ("\n" if output else ""))
        print(f"\n[probe] saved output to {out_path}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
