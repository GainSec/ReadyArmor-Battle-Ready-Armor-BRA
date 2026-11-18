#!/usr/bin/env python3
"""Prompt A/B harness for engagement prompt formatting experiments."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))

from bra.config.settings import set_bra_root
from bra.config.settings import get_proxy_config, get_runtime_config
from bra.core.agent import run_agent


DEFAULT_ALLOWED_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_proxy_api_key() -> None:
    """Mirror engage.py behavior so direct harness runs work with local proxy routing."""
    if str(os.environ.get("ANTHROPIC_API_KEY", "")).strip():
        return
    proxy_cfg = get_proxy_config()
    if proxy_cfg.get("proxy_enabled"):
        os.environ["ANTHROPIC_API_KEY"] = "proxy-routed"


def _is_heading_line(line: str) -> bool:
    stripped = line.strip()
    return bool(
        stripped.startswith("#")
        or stripped.startswith("▶ ")
        or stripped.startswith("## ")
        or stripped.startswith("### ")
        or re.fullmatch(r"[═─\-]{3,}", stripped)
    )


def _is_structured_line(line: str) -> bool:
    stripped = line.strip()
    return bool(
        stripped.startswith(("- ", "* ", "|"))
        or re.match(r"^\d+\.\s+", stripped)
        or _is_heading_line(stripped)
    )


def compact_prompt(prompt: str) -> str:
    """Remove formatting-only whitespace while preserving content and numbering."""
    lines = [line.rstrip() for line in prompt.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    compacted: list[str] = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped:
            compacted.append(line)
            continue

        prev = compacted[-1] if compacted else ""
        next_nonempty = ""
        for future in lines[idx + 1 :]:
            if future.strip():
                next_nonempty = future
                break

        if not prev or not next_nonempty:
            continue
        if _is_structured_line(prev) or _is_structured_line(next_nonempty):
            continue
        if compacted and compacted[-1] == "":
            continue
        compacted.append("")

    return "\n".join(compacted).strip()


def _split_sections(lines: list[str]) -> list[tuple[str | None, list[str]]]:
    sections: list[tuple[str | None, list[str]]] = []
    current_header: str | None = None
    current_lines: list[str] = []
    for line in lines:
        if line.startswith("▶ ") or line.startswith("## "):
            if current_header is not None or current_lines:
                sections.append((current_header, current_lines))
            current_header = line.strip()
            current_lines = []
        else:
            current_lines.append(line)
    if current_header is not None or current_lines:
        sections.append((current_header, current_lines))
    return sections


def _nonempty(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip()]


def _compress_key_value_lines(lines: list[str], sep: str = "; ") -> str:
    return sep.join(_nonempty(lines))


def _compress_markdown_table(lines: list[str], prefix: str) -> list[str]:
    rows = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) >= 3:
            rows.append(f"{cells[0]}={cells[1]} ({cells[2]})")
        elif len(cells) == 2:
            rows.append(f"{cells[0]}={cells[1]}")
    return [f"{prefix}: " + "; ".join(rows)] if rows else []


def _compress_tool_resolution(lines: list[str]) -> list[str]:
    available: list[str] = []
    missing: list[str] = []
    current: list[str] | None = None
    for line in _nonempty(lines):
        if line.startswith("### Available"):
            current = available
            continue
        if line.startswith("### Missing"):
            current = missing
            continue
        if line.startswith("- ") and current is not None:
            current.append(line[2:].strip())
        elif current is None and not line.startswith("### "):
            continue
    out: list[str] = []
    if available:
        out.append("Available tools: " + ", ".join(available))
    if missing:
        out.append("Missing tools: " + ", ".join(missing))
    return out


def _compress_artifacts(lines: list[str]) -> list[str]:
    items = [line[2:].strip() for line in _nonempty(lines) if line.strip().startswith("- ")]
    totals = [line for line in _nonempty(lines) if line.startswith("Total:")]
    out: list[str] = []
    if items:
        out.append("Artifacts: " + "; ".join(items))
    out.extend(totals)
    return out


def _compress_questions(lines: list[str]) -> list[str]:
    items = [line[2:].strip() for line in _nonempty(lines) if line.strip().startswith("- ")]
    return ["Questions: " + "; ".join(items)] if items else []


def _compress_host_environment(lines: list[str]) -> list[str]:
    intro = []
    fields = []
    for line in _nonempty(lines):
        if line.startswith("- "):
            fields.append(line[2:].strip())
        else:
            intro.append(line)
    out: list[str] = []
    if intro:
        out.append(" ".join(intro))
    if fields:
        keep_prefixes = (
            "Hostname:", "OS:", "Kernel:", "Architecture:", "Shell:",
            "Default Interface:", "Default IPv4:", "Wi-Fi IPv4 Addresses:",
            "Ethernet IPv4 Addresses:", "Tool Availability:",
        )
        filtered = [field for field in fields if field.startswith(keep_prefixes)]
        out.append("Host: " + "; ".join(filtered))
    return out


def _compress_targets(lines: list[str]) -> list[str]:
    tags = []
    current_label = ""
    for line in _nonempty(lines):
        if line.endswith(":") and not line.startswith("- "):
            current_label = line[:-1]
            continue
        if line.startswith("- ") or line.startswith("  - "):
            item = line.split("-", 1)[1].strip()
            tags.append(f"{current_label}: {item}" if current_label else item)
    return ["Targets: " + "; ".join(tags)] if tags else []


def aggressive_compact_prompt(prompt: str) -> str:
    """Collapse formatting-heavy prompt sections into denser equivalents."""
    compacted = compact_prompt(prompt)
    lines = compacted.splitlines()
    rendered: list[str] = []

    for header, body in _split_sections(lines):
        body_lines = _nonempty(body)
        if header is None:
            rendered.extend(body_lines)
            continue

        if header == "▶ PREFLIGHT CHECK":
            rendered.append("▶ PREFLIGHT CHECK: " + _compress_key_value_lines(body))
            continue
        if header == "▶ METHODOLOGY DETECTION":
            rendered.append("▶ METHODOLOGY DETECTION: " + _compress_key_value_lines(body))
            continue
        if header == "▶ GENERATING PHASE CONTEXT":
            rendered.append("▶ GENERATING PHASE CONTEXT")
            continue
        if header == "## Tool Resolution":
            rendered.append(header)
            rendered.extend(_compress_tool_resolution(body))
            continue
        if header == "## Engagement Summary":
            rendered.append(header)
            rendered.append(" | ".join(body_lines))
            continue
        if header == "## Layer References":
            rendered.append(header)
            rendered.extend(_compress_markdown_table(body, "Layers"))
            continue
        if header == "## Targets (From Layer 3)":
            rendered.append(header)
            rendered.extend(_compress_targets(body))
            continue
        if header == "## Existing Artifacts":
            rendered.append(header)
            rendered.extend(_compress_artifacts(body))
            continue
        if header == "## Key Findings":
            rendered.append(header)
            rendered.append(" ".join(body_lines))
            continue
        if header == "## Methodology Guidance (Layer 2)":
            rendered.append(header)
            rendered.extend(body_lines)
            continue
        if header == "## Token Status (Layer 1: tokens.md)":
            rendered.append(header)
            rendered.extend(_compress_markdown_table(body, "Tokens"))
            continue
        if header == "## Questions for You":
            rendered.append(header)
            rendered.extend(_compress_questions(body))
            continue
        if header == "## Host Environment (Auto-Detected)":
            rendered.append(header)
            rendered.extend(_compress_host_environment(body))
            continue

        rendered.append(header)
        rendered.extend(body_lines)

    return "\n".join(line for line in rendered if line.strip()).strip()


def fixed_first_turn_prompt(prompt: str) -> str:
    """Resolve the initial-turn contradiction: scope validation is required before proceeding."""
    compacted = aggressive_compact_prompt(prompt)
    replacement = "\n".join(
        [
            "## FIRST ACTION: Validate Scope",
            "Before proceeding with any methodology work, scope validation is required.",
            "This first turn is only for selecting how to handle required scope validation before any file read or methodology action.",
            "Required next step: read and validate layer3-engagement/SCOPE.md before proceeding.",
            "After scope is read and validated, summarize it briefly and then offer these exact post-validation options:",
            "1. Confirm scope and proceed",
            "2. Revise scope (tell me what to change)",
            "3. Ask a clarifying question",
            "4. Cancel engagement",
            "For this initial turn, do not offer any option that skips or bypasses scope validation.",
            "For this initial turn, end with 'What would you like to do?' and only these options:",
            "1. Read and validate scope",
            "2. Revise scope before validation",
            "3. Ask a clarifying question",
            "4. Cancel engagement",
            "Do NOT list issues as numbered items - put issues in prose or bullet points.",
            "ONLY use numbered lists for selectable options.",
        ]
    )
    pattern = re.compile(
        r"## FIRST ACTION: Validate Scope.*?(?=\n## |\n▶ |\Z)",
        re.DOTALL,
    )
    rewritten, count = pattern.subn(replacement, compacted, count=1)
    if count == 0:
        raise ValueError("Unable to locate first-action scope section in prompt")
    return rewritten.strip()


def _text_stats(text: str) -> dict[str, int]:
    lines = text.splitlines()
    return {
        "chars": len(text),
        "lines": len(lines),
        "non_empty_lines": sum(1 for line in lines if line.strip()),
    }


def extract_anthropic_response_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for block in payload.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            text = str(block.get("text", "") or "").strip()
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip()


def extract_openai_response_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", []) or []
    if not choices:
        return ""
    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()
    chunks: list[str] = []
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = str(block.get("text", "") or "").strip()
                if text:
                    chunks.append(text)
    return "\n".join(chunks).strip()


def _message_text_chunks(message: Any) -> list[str]:
    if isinstance(message, dict):
        msg_type = str(message.get("type", ""))
        if msg_type in {"assistant_text", "text"}:
            content = str(message.get("content", "") or "").strip()
            return [content] if content else []
        return []

    if hasattr(message, "content") and not hasattr(message, "result"):
        chunks: list[str] = []
        for block in getattr(message, "content", []) or []:
            text = str(getattr(block, "text", "") or "").strip()
            if text:
                chunks.append(text)
        return chunks

    if hasattr(message, "result"):
        text = str(getattr(message, "result", "") or "").strip()
        return [text] if text else []

    return []


async def run_case(name: str, prompt: str, model: str | None = None, timeout_seconds: float = 120.0) -> dict[str, Any]:
    response_chunks: list[str] = []
    timed_out = False
    try:
        async with asyncio.timeout(timeout_seconds):
            async for message in run_agent(prompt, allowed_tools=DEFAULT_ALLOWED_TOOLS, model=model):
                response_chunks.extend(_message_text_chunks(message))
    except TimeoutError:
        timed_out = True

    response = "\n".join(chunk for chunk in response_chunks if chunk).strip()
    if timed_out:
        response = f"{response}\n[Timed out waiting for turn completion]".strip()
    return {
        "name": name,
        "prompt": prompt,
        "response": response,
        "prompt_stats": _text_stats(prompt),
        "response_stats": _text_stats(response),
    }


async def run_case_messages(name: str, prompt: str, model: str | None = None, timeout_seconds: float = 120.0) -> dict[str, Any]:
    proxy_cfg = get_proxy_config()
    base_url = f"http://127.0.0.1:{proxy_cfg['proxy_port']}" if proxy_cfg.get("proxy_enabled") else str(os.environ.get("ANTHROPIC_BASE_URL", "")).strip()
    if not base_url:
        raise RuntimeError("No local Anthropic-compatible endpoint available")

    runtime_model = model or str(get_runtime_config().get("model") or "").strip() or "claude-sonnet-4-6"
    headers = {
        "x-api-key": os.environ.get("ANTHROPIC_API_KEY", "proxy-routed"),
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": runtime_model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.post(f"{base_url}/v1/messages", headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

    text = extract_anthropic_response_text(data)
    return {
        "name": name,
        "prompt": prompt,
        "response": text,
        "prompt_stats": _text_stats(prompt),
        "response_stats": _text_stats(text),
    }


async def run_case_backend(name: str, prompt: str, model: str | None = None, timeout_seconds: float = 120.0) -> dict[str, Any]:
    proxy_cfg = get_proxy_config()
    base_url = str(proxy_cfg.get("proxy_backend_url") or "").strip()
    if not base_url:
        raise RuntimeError("No proxy_backend_url configured")

    configured_map = proxy_cfg.get("proxy_model_map") or {}
    mapped_model = next(iter(configured_map.values()), "")
    runtime_model = model or mapped_model or "qwen3"
    if "/" in runtime_model:
        runtime_model = runtime_model.rsplit("/", 1)[-1]

    headers = {
        "authorization": f"Bearer {proxy_cfg.get('proxy_backend_api_key', 'dummy-key')}",
        "content-type": "application/json",
    }
    payload = {
        "model": runtime_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

    text = extract_openai_response_text(data)
    return {
        "name": name,
        "prompt": prompt,
        "response": text,
        "prompt_stats": _text_stats(prompt),
        "response_stats": _text_stats(text),
    }


def write_report(output_dir: Path, cases: list[dict[str, Any]]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"generated_at": _utc_now(), "cases": []}

    summary_lines = [
        "# Prompt A/B Harness Report",
        "",
    ]

    for case in cases:
        stem = case["name"]
        prompt_path = output_dir / f"{stem}.prompt.txt"
        response_path = output_dir / f"{stem}.response.txt"
        prompt_path.write_text(case["prompt"] + "\n", encoding="utf-8")
        response_path.write_text((case["response"] or "") + "\n", encoding="utf-8")

        manifest["cases"].append(
            {
                "name": stem,
                "prompt_file": prompt_path.name,
                "response_file": response_path.name,
                "prompt_stats": case["prompt_stats"],
                "response_stats": case["response_stats"],
            }
        )

        summary_lines.extend(
            [
                f"## {stem}",
                "",
                f"- Prompt chars: {case['prompt_stats']['chars']}",
                f"- Prompt lines: {case['prompt_stats']['lines']}",
                f"- Response chars: {case['response_stats']['chars']}",
                f"- Response lines: {case['response_stats']['lines']}",
                "",
            ]
        )

    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summary_path = output_dir / "summary.md"
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    return summary_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run baseline and compacted prompt variants through BRA agent runtime.")
    parser.add_argument("--bra-root", default="body", help="BRA body root")
    parser.add_argument("--prompt-file", required=True, help="Path to source prompt text file")
    parser.add_argument("--model", default="", help="Optional model override")
    parser.add_argument("--output-dir", default="", help="Directory to write prompt/response artifacts")
    parser.add_argument("--timeout-seconds", type=float, default=120.0, help="Per-case timeout")
    parser.add_argument("--transport", choices=["sdk", "messages", "backend"], default="messages", help="How to send the prompt")
    return parser.parse_args(argv)


async def _async_main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    bra_root = Path(args.bra_root).resolve()
    set_bra_root(bra_root)
    ensure_proxy_api_key()

    prompt_file = Path(args.prompt_file).resolve()
    prompt = prompt_file.read_text(encoding="utf-8")
    compact = compact_prompt(prompt)
    aggressive = aggressive_compact_prompt(prompt)
    fixed = fixed_first_turn_prompt(prompt)
    model = str(args.model).strip() or None

    output_dir = Path(args.output_dir).resolve() if args.output_dir else bra_root / ".bra" / "prompt-ab" / _utc_now()
    runner = {
        "sdk": run_case,
        "messages": run_case_messages,
        "backend": run_case_backend,
    }[args.transport]
    cases = [
        await runner("baseline", prompt, model=model, timeout_seconds=args.timeout_seconds),
        await runner("compact", compact, model=model, timeout_seconds=args.timeout_seconds),
        await runner("aggressive", aggressive, model=model, timeout_seconds=args.timeout_seconds),
        await runner("fixed", fixed, model=model, timeout_seconds=args.timeout_seconds),
    ]
    summary_path = write_report(output_dir, cases)

    print(f"Report written to: {summary_path}")
    for case in cases:
        print(
            f"{case['name']}: prompt_chars={case['prompt_stats']['chars']} "
            f"response_chars={case['response_stats']['chars']}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_async_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
