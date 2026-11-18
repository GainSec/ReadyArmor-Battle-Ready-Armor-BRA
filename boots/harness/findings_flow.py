"""Findings-flow test harness.

Reproduces the exact prompt construction and tool restrictions boots uses
when findings are pending (runner.py:363-395) — without the production queue
lifecycle plumbing.

Usage:
    python3 boots/harness/findings_flow.py --bra-root body --finding-id 001 --prompt-only
"""

from __future__ import annotations

import os, sys
import time
import re
from pathlib import Path

# Project root: boots/harness/../../ = BRA-V14-DEV/
_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(_ROOT), str(_ROOT / "head"), str(_ROOT / "boots")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
os.chdir(_ROOT)

import argparse
import asyncio

from bra.config.settings import set_bra_root
from bra.core.finding_enforcer import FindingEnforcer, PendingFinding

# ---------------------------------------------------------------------------
# API key — paste here, or set ANTHROPIC_API_KEY env, or put in apikey.txt
# ---------------------------------------------------------------------------
API_KEY = ""

def _resolve_api_key() -> str | None:
    """API_KEY variable > env > apikey.txt > settings config."""
    if API_KEY:
        os.environ["ANTHROPIC_API_KEY"] = API_KEY
        return API_KEY
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return os.environ["ANTHROPIC_API_KEY"].strip()
    harness_apikey = Path(__file__).resolve().parent / "apikey.txt"
    for candidate in (harness_apikey, _ROOT / "apikey.txt"):
        if candidate.exists():
            key = candidate.read_text().strip()
            if key:
                os.environ["ANTHROPIC_API_KEY"] = key
                return key
    from bra.config.settings import get_anthropic_api_key
    return get_anthropic_api_key()


# ---------------------------------------------------------------------------
# Prompt construction — mirrors runner.py findings path
# ---------------------------------------------------------------------------

ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit"]


def build_effective_prompt(
    enforcer: FindingEnforcer,
    target_finding: PendingFinding,
    pending: list[PendingFinding],
    user_prompt: str,
) -> str:
    """Build the exact prompt boots findings subagent sends.

    Runner path sends only get_documentation_prompt(...) to run_agent.
    The harness keeps the user_prompt parameter for backward-compatible
    UI wiring but does not append it to the effective prompt.
    """
    _ = user_prompt  # Intentionally ignored for parity with runner.
    return enforcer.get_documentation_prompt(
        target_finding,
        all_pending=pending,
    )


def extract_finding_entry(findings_path: Path, finding_id: str) -> str:
    """Extract full markdown block for a finding from FINDINGS.md."""
    if not findings_path.exists():
        return ""

    normalized_id = str(finding_id or "").strip()
    if normalized_id.isdigit():
        normalized_id = normalized_id.zfill(3)
    if not normalized_id:
        return ""

    content = findings_path.read_text()
    pattern = re.compile(
        rf"^## \[FINDING-{re.escape(normalized_id)}\].*?(?=^## \[FINDING-\d{{3}}\]|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        return ""
    return match.group(0).strip() + "\n"


# ---------------------------------------------------------------------------
# Default user prompt
# ---------------------------------------------------------------------------

DEFAULT_USER_PROMPT = "continue"


def get_handoff_prompt() -> str:
    """Generate full handoff prompt via agentic-handler.py (engage.py:1511).

    Only used when --user-prompt handoff is passed explicitly.
    """
    from bra.core.bridge import run_script

    result = run_script("agentic-handler.py", timeout=30)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    raise RuntimeError(f"agentic-handler.py failed: {result.stderr}")


# ---------------------------------------------------------------------------
# Finding resolution
# ---------------------------------------------------------------------------

def resolve_finding(
    enforcer: FindingEnforcer,
    finding_id: str,
) -> tuple[PendingFinding, list[PendingFinding]]:
    """Resolve a finding ID to a PendingFinding with its queue context.

    Checks the existing pending queue first, then falls back to
    check_undocumented() to discover findings from INTEL.md.
    """
    # Check existing pending queue
    for pf in enforcer.pending_queue:
        if pf.id == finding_id:
            return pf, enforcer.pending_queue

    # Discover undocumented findings from INTEL.md
    undocumented = enforcer.check_undocumented()
    for pf in undocumented:
        if pf.id == finding_id:
            return pf, undocumented if undocumented else [pf]

    # Synthesize a minimal PendingFinding so the harness can still run
    print(f"[warn] FINDING-{finding_id} not found in queue or INTEL.md — using placeholder", file=sys.stderr)
    placeholder = PendingFinding(
        id=finding_id,
        severity="INFO",
        title="Unknown finding (placeholder)",
        source_marker=f"[FINDING] INFO: Unknown finding (placeholder)",
    )
    return placeholder, [placeholder]


# ---------------------------------------------------------------------------
# Agent execution + message extraction (mirrors runner._process_message)
# ---------------------------------------------------------------------------

async def run_finding_flow(
    effective_prompt: str,
    show_events: bool = False,
    timeout_seconds: int = 300,
) -> str:
    """Run the agent with the findings prompt and collect output text.

    Uses the same run_agent() entry point and allowed_tools as boots.
    Message extraction mirrors runner.py:_process_message shapes.
    """
    from bra.core.agent import run_agent

    output_parts: list[str] = []

    def _ts() -> str:
        return time.strftime("%H:%M:%S", time.localtime())

    try:
        async with asyncio.timeout(timeout_seconds):
            async for message in run_agent(effective_prompt, allowed_tools=ALLOWED_TOOLS):
                # Dict messages (our custom shapes from agent.py)
                if isinstance(message, dict):
                    msg_type = message.get("type", "")
                    if show_events:
                        print(f"{_ts()}  [event] dict:{msg_type}", file=sys.stderr)
                    if msg_type == "session_init":
                        sid = message.get("session_id", "")
                        print(f"[session] {sid}", file=sys.stderr)
                    elif msg_type in ("assistant_text", "text"):
                        content = str(message.get("content", ""))
                        if content.strip():
                            print(content, end="", flush=True)
                            output_parts.append(content)
                    elif msg_type == "error":
                        err = str(message.get("content", ""))
                        print(f"\n[error] {err}", file=sys.stderr)
                        output_parts.append(f"\n[ERROR] {err}\n")
                    elif msg_type == "tool_use" and show_events:
                        name = message.get("name", "")
                        print(f"{_ts()}  [tool_use] {name}", file=sys.stderr)
                    elif msg_type == "tool_result" and show_events:
                        preview = str(message.get("content", ""))[:120]
                        print(f"{_ts()}  [tool_result] {preview}", file=sys.stderr)
                    continue

                # SDK object messages
                msg_class = type(message).__name__
                if show_events:
                    print(f"{_ts()}  [event] {msg_class}", file=sys.stderr)

                if msg_class == "AssistantMessage":
                    content = getattr(message, "content", [])
                    for block in content:
                        if hasattr(block, "text"):
                            text = str(block.text)
                            if text.strip():
                                print(text, end="", flush=True)
                                output_parts.append(text)
                        elif show_events:
                            tool_name = str(getattr(block, "name", "") or "")
                            if tool_name:
                                print(f"{_ts()}  [tool_use] {tool_name}", file=sys.stderr)

                elif msg_class == "ResultMessage":
                    result = getattr(message, "result", "")
                    is_error = bool(getattr(message, "is_error", False))
                    if result and is_error:
                        err = str(result)
                        print(f"\n[error] {err}", file=sys.stderr)
                        output_parts.append(f"\n[ERROR] {err}\n")

                elif msg_class == "SystemMessage":
                    subtype = getattr(message, "subtype", "")
                    if subtype == "init":
                        data = getattr(message, "data", {})
                        sid = data.get("session_id", "")
                        if sid:
                            print(f"[session] {sid}", file=sys.stderr)
    except TimeoutError:
        msg = f"Findings flow timed out after {timeout_seconds}s"
        print(f"\n[error] {msg}", file=sys.stderr)
        output_parts.append(f"\n[ERROR] {msg}\n")

    print()  # Final newline
    return "".join(output_parts)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def run_validation(enforcer: FindingEnforcer, finding_id: str) -> bool:
    """Validate the finding record and print pass/fail."""
    result = enforcer.validate_finding_record(finding_id)
    if result.valid:
        print(f"\n[PASS] FINDING-{finding_id} validated successfully")
        return True

    print(f"\n[FAIL] FINDING-{finding_id} validation failed")
    if result.missing_fields:
        print(f"  Missing fields: {', '.join(result.missing_fields)}")
    if result.errors:
        for err in result.errors:
            print(f"  Error: {err}")
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Findings-flow test harness — mirrors exact boots prompt construction",
    )
    parser.add_argument(
        "--bra-root",
        default="body",
        help="Path to BRA root directory (default: body)",
    )
    parser.add_argument(
        "--finding-id",
        required=True,
        help="Finding ID to document (e.g. 001)",
    )
    parser.add_argument(
        "--user-prompt",
        default=None,
        help="Deferred user request (default: 'write up findings'. Use 'handoff' for agentic-handler.py)",
    )
    parser.add_argument(
        "--prompt-only",
        action="store_true",
        help="Print effective prompt and exit (no API call)",
    )
    parser.add_argument(
        "--show-events",
        action="store_true",
        help="Print SDK event types during streaming",
    )
    parser.add_argument(
        "--save-output",
        default=None,
        help="Override output file path",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Hard timeout for a single findings_flow run (default: 300)",
    )
    parser.add_argument(
        "--print-finding-entry",
        action="store_true",
        help="Print the full FINDINGS.md entry for --finding-id after execution",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()

    # Resolve BRA root
    bra_root = Path(args.bra_root).resolve()
    if not bra_root.exists():
        print(f"[error] BRA root not found: {bra_root}", file=sys.stderr)
        return 1

    # Point settings at the right root
    set_bra_root(bra_root)

    notes_dir = bra_root / "layer3-engagement" / "NOTES"
    bra_state_dir = bra_root / ".bra"
    bra_state_dir.mkdir(parents=True, exist_ok=True)

    if not notes_dir.exists():
        print(f"[error] NOTES directory not found: {notes_dir}", file=sys.stderr)
        return 1

    # Initialize enforcer (same as runner.py:169-178)
    enforcer = FindingEnforcer(notes_dir, bra_state_dir)

    # Resolve the target finding
    target, pending = resolve_finding(enforcer, args.finding_id)
    print(f"[info] Target: FINDING-{target.id} ({target.severity}: {target.title})", file=sys.stderr)
    print(f"[info] Pending queue: {len(pending)} finding(s)", file=sys.stderr)

    # Build user prompt
    if args.user_prompt == "handoff":
        user_prompt = get_handoff_prompt()
    elif args.user_prompt:
        user_prompt = args.user_prompt
    else:
        user_prompt = DEFAULT_USER_PROMPT

    # Build the exact effective prompt
    effective_prompt = build_effective_prompt(enforcer, target, pending, user_prompt)

    # --prompt-only: print and exit
    if args.prompt_only:
        print(effective_prompt)
        if args.print_finding_entry:
            entry = extract_finding_entry(enforcer.findings_path, target.id)
            if entry:
                print("\n\n--- FINDINGS.md entry ---\n")
                print(entry, end="")
            else:
                print(f"\n[warn] FINDING-{target.id} entry not found in {enforcer.findings_path}", file=sys.stderr)
        print(f"\n--- allowed_tools: {ALLOWED_TOOLS}", file=sys.stderr)
        return 0

    # Fastpath preflight: deterministically materialize/dequeue before any model call.
    if enforcer.is_fastpath_enabled():
        preflight_dequeued = enforcer.check_and_dequeue_completed()
        if target.id in preflight_dequeued:
            print(f"[info] Fastpath preflight validated FINDING-{target.id}; skipping model run", file=sys.stderr)
            return 0

    # Verify API key
    api_key = _resolve_api_key()
    if not api_key:
        print("[error] No API key found (set API_KEY in script, ANTHROPIC_API_KEY env, or apikey.txt)", file=sys.stderr)
        return 1

    print(f"[info] Running agent with allowed_tools={ALLOWED_TOOLS}", file=sys.stderr)
    print("---", file=sys.stderr)

    # Run the agent
    output = await run_finding_flow(
        effective_prompt,
        show_events=args.show_events,
        timeout_seconds=max(30, int(args.timeout_seconds)),
    )

    # Save output
    output_path = Path(args.save_output) if args.save_output else (
        Path(__file__).parent / "output" / f"finding-{args.finding_id}-output.md"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output)
    print(f"\n[info] Output saved to {output_path}", file=sys.stderr)

    # Validate
    print("---", file=sys.stderr)
    valid = run_validation(enforcer, args.finding_id)

    if args.print_finding_entry:
        entry = extract_finding_entry(enforcer.findings_path, target.id)
        if entry:
            print("\n--- FINDINGS.md entry ---\n")
            print(entry, end="")
        else:
            print(f"[warn] FINDING-{target.id} entry not found in {enforcer.findings_path}", file=sys.stderr)

    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
