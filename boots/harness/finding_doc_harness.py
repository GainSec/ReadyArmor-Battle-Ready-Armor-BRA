"""Finding Documentation Harness.

Shows the EXACT prompt FindingEnforcer.get_documentation_prompt() sends to
the production subagent for a given INTEL.md Key Issues Overview finding ID,
then optionally runs the subagent in a sandbox (temp FINDINGS.md, real
artifacts) and prints the full ## [FINDING-NNN] block it produces.

Standalone usage:
    python3 boots/harness/finding_doc_harness.py --bra-root body --finding-id 001 --prompt-only
    python3 boots/harness/finding_doc_harness.py --bra-root body --finding-id 001
    python3 boots/harness/finding_doc_harness.py --bra-root body --finding-id 001 --seed-mode autofilled

Web GUI: Debug → Harnesses → Finding Documentation
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator

# ---------------------------------------------------------------------------
# Path bootstrap (same pattern as findings_flow.py)
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(_ROOT), str(_ROOT / "head"), str(_ROOT / "boots")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
os.chdir(_ROOT)

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec

if TYPE_CHECKING:
    from bra.core.finding_enforcer import FindingEnforcer, PendingFinding

ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit"]

SEED_MODES = ["skeleton_only", "autofilled"]


# ---------------------------------------------------------------------------
# API key resolution (same as findings_flow.py)
# ---------------------------------------------------------------------------


def _resolve_api_key() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return os.environ["ANTHROPIC_API_KEY"].strip()
    candidate = Path(__file__).parent / "apikey.txt"
    if candidate.exists():
        key = candidate.read_text().strip()
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
            return key
    try:
        from bra.config.settings import get_anthropic_api_key
        return get_anthropic_api_key()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# INTEL.md resolution — Key Issues Overview only
# ---------------------------------------------------------------------------


def _resolve_from_intel(intel_path: Path, finding_id: str) -> "PendingFinding | None":
    """Resolve a PendingFinding from INTEL.md ## Key Issues Overview by numeric ID.

    Only looks in the Key Issues Overview table — the canonical source of
    numbered findings. Does not touch the ## Vulnerabilities fallback.
    """
    from bra.core.finding_enforcer import PendingFinding

    if not intel_path.exists():
        return None

    content = intel_path.read_text()
    kio_idx = content.find("## Key Issues Overview")
    if kio_idx == -1:
        return None

    # Match: | 001 | Title | Severity | ... |
    row_pat = rf'\|\s*{re.escape(finding_id)}\s*\|\s*([^|]+)\|\s*\*?\*?([^|*]+?)\*?\*?\s*\|'
    m = re.search(row_pat, content[kio_idx:])
    if not m:
        return None

    title = m.group(1).strip()
    severity = m.group(2).strip().upper()

    return PendingFinding(
        id=finding_id,
        severity=severity,
        title=title,
        source_marker=f"[FINDING] {severity}: {title}",
    )


# ---------------------------------------------------------------------------
# Sandbox: temp FINDINGS.md + reqs/, real artifacts
# ---------------------------------------------------------------------------


def _make_sandbox_findings(notes_dir: Path, bra_state_dir: Path) -> tuple[Path, Path]:
    """Create a temp FINDINGS.md and reqs/ dir for sandbox runs.

    Real INTEL.md, captures.log, and artifacts/raw/ stay at their original
    paths — the subagent reads those directly. Only FINDINGS.md (writes) is
    sandboxed.

    Returns (tmp_findings_path, tmp_reqs_dir).
    Caller is responsible for cleaning up the parent tmpdir.
    """
    tmp = Path(tempfile.mkdtemp(prefix="bra_doc_harness_"))
    tmp_notes = tmp / "NOTES"
    tmp_notes.mkdir()
    tmp_reqs = tmp_notes / "reqs"
    tmp_reqs.mkdir()

    # Fresh FINDINGS.md — no pre-existing entries
    (tmp_notes / "FINDINGS.md").write_text("# Findings\n\n---\n\n")

    # Symlink INTEL.md so the enforcer can read intel_path from the same dir
    intel_src = notes_dir / "INTEL.md"
    if intel_src.exists():
        (tmp_notes / "INTEL.md").symlink_to(intel_src)

    return tmp_notes / "FINDINGS.md", tmp_reqs


def _extract_finding_block(content: str, finding_id: str) -> str:
    """Extract the ## [FINDING-NNN] block from FINDINGS.md content."""
    pat = re.compile(
        rf'(## \[FINDING-{re.escape(finding_id)}\].*?)(?=\n## \[FINDING-|\Z)',
        re.DOTALL,
    )
    m = pat.search(content)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Core prompt + run logic
# ---------------------------------------------------------------------------


def build_exact_prompt(
    notes_dir: Path,
    bra_state_dir: Path,
    finding_id: str,
    sandbox_findings_path: Path,
    seed_mode: str,
) -> tuple[str, "PendingFinding"]:
    """Build the exact FindingEnforcer documentation prompt for a given finding.

    Uses a sandboxed FINDINGS.md path so writes go to the temp file.
    Returns (prompt_text, pending_finding).
    """
    from bra.config.settings import set_bra_root
    from bra.core.finding_enforcer import FindingEnforcer

    set_bra_root(notes_dir.parent.parent)  # body/

    # Enforcer pointed at sandbox FINDINGS.md, real INTEL.md and state dir
    enforcer = FindingEnforcer(sandbox_findings_path.parent, bra_state_dir)
    # Override the paths so reqs/ is in the sandbox
    enforcer.findings_path = sandbox_findings_path
    enforcer.intel_path = notes_dir / "INTEL.md"

    pf = _resolve_from_intel(notes_dir / "INTEL.md", finding_id)
    if pf is None:
        raise ValueError(
            f"FINDING-{finding_id} not found in INTEL.md ## Key Issues Overview"
        )

    # Symlink real reqs files (evidence.txt, context.md) into sandbox reqs/ so
    # _build_inline_evidence() shows exactly what fires in a live session.
    # If they don't exist (new engagement, no materializer yet) that's fine —
    # the subagent falls back to captures.log + raw artifacts + INTEL.md.
    real_reqs = notes_dir / "reqs"
    for suffix in (
        f"finding-{finding_id}-context.md",
        f"finding-{finding_id}-evidence.txt",
    ):
        src = real_reqs / suffix
        dst = enforcer.reqs_dir / suffix
        if src.exists() and not dst.exists():
            try:
                dst.symlink_to(src)
            except Exception:
                pass

    # Seed the skeleton into sandbox FINDINGS.md
    enforcer.enqueue_finding(pf.id, pf.severity, pf.title, pf.source_marker)

    if seed_mode == "autofilled":
        # Apply autofill — simulates the state after fastpath token substitution
        enforcer._autofill_finding_record_defaults(pf)

    prompt = enforcer.get_documentation_prompt(pf, all_pending=[pf])
    return prompt, pf


async def run_subagent_sandbox(
    prompt: str,
    sandbox_findings_path: Path,
    bra_state_dir: Path,
    finding_id: str,
    show_events: bool = False,
) -> tuple[str, str]:
    """Run the production subagent against the sandbox FINDINGS.md.

    Returns (raw_agent_output, produced_finding_block).
    """
    from bra.core.agent import run_agent

    output_parts: list[str] = []

    def _ts() -> str:
        return time.strftime("%H:%M:%S", time.localtime())

    async for message in run_agent(prompt, allowed_tools=ALLOWED_TOOLS):
        if isinstance(message, dict):
            mtype = message.get("type", "")
            if mtype in ("assistant_text", "text"):
                content = str(message.get("content", ""))
                if content.strip():
                    output_parts.append(content)
            elif mtype == "tool_use" and show_events:
                print(f"{_ts()}  [tool] {message.get('name', '')}", file=sys.stderr)
            elif mtype == "error":
                output_parts.append(f"\n[ERROR] {message.get('content', '')}\n")
        else:
            cls = type(message).__name__
            if cls == "AssistantMessage":
                for block in getattr(message, "content", []):
                    if hasattr(block, "text") and str(block.text).strip():
                        output_parts.append(str(block.text))
            elif cls == "ResultMessage":
                err = str(getattr(message, "result", ""))
                if getattr(message, "is_error", False) and err:
                    output_parts.append(f"\n[ERROR] {err}\n")

    raw_output = "".join(output_parts)
    produced_block = _extract_finding_block(
        sandbox_findings_path.read_text(errors="replace"),
        finding_id,
    )
    return raw_output, produced_block


# ---------------------------------------------------------------------------
# Web GUI BaseHarness integration
# ---------------------------------------------------------------------------


class FindingDocHarness(BaseHarness):
    name = "finding_doc"
    label = "Finding Documentation"
    description = (
        "Show exact subagent prompt and/or run in sandbox to see "
        "the FINDINGS.md entry the subagent produces"
    )

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="finding_id",
                type="text",
                required=True,
                default="001",
                help="Finding ID from INTEL.md Key Issues Overview (e.g. 001, 002)",
            ),
            ParamSpec(
                name="seed_mode",
                type="select",
                required=False,
                default="skeleton_only",
                help=(
                    "skeleton_only: raw {{PENDING:*}} tokens (tests subagent cold). "
                    "autofilled: tokens pre-filled by fastpath (tests subagent on top of autofill)."
                ),
                options=SEED_MODES,
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        finding_id = str(params.get("finding_id", "")).strip().zfill(3)
        seed_mode = params.get("seed_mode", "skeleton_only")
        if seed_mode not in SEED_MODES:
            seed_mode = "skeleton_only"

        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        bra_state_dir = bra_root / ".bra"

        tmp_dir = Path(tempfile.mkdtemp(prefix="bra_doc_harness_prompt_"))
        try:
            sandbox_notes = tmp_dir / "NOTES"
            sandbox_notes.mkdir()
            (sandbox_notes / "reqs").mkdir()
            sandbox_findings = sandbox_notes / "FINDINGS.md"
            sandbox_findings.write_text("# Findings\n\n---\n\n")
            intel_src = notes_dir / "INTEL.md"
            if intel_src.exists():
                (sandbox_notes / "INTEL.md").symlink_to(intel_src)

            prompt, pf = build_exact_prompt(
                notes_dir, bra_state_dir, finding_id, sandbox_findings, seed_mode
            )
        finally:
            shutil.rmtree(str(tmp_dir), ignore_errors=True)

        return HarnessResult(
            prompt=prompt,
            allowed_tools=ALLOWED_TOOLS,
            metadata={
                "finding_id": finding_id,
                "seed_mode": seed_mode,
                "source": "FindingEnforcer.get_documentation_prompt()",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        finding_id = str(params.get("finding_id", "")).strip().zfill(3)
        seed_mode = params.get("seed_mode", "skeleton_only")
        if seed_mode not in SEED_MODES:
            seed_mode = "skeleton_only"

        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        bra_state_dir = bra_root / ".bra"

        tmp_root = Path(tempfile.mkdtemp(prefix="bra_doc_harness_"))
        try:
            sandbox_findings = tmp_root / "NOTES" / "FINDINGS.md"
            sandbox_findings.parent.mkdir(parents=True, exist_ok=True)
            (tmp_root / "NOTES" / "reqs").mkdir()
            sandbox_findings.write_text("# Findings\n\n---\n\n")

            intel_src = notes_dir / "INTEL.md"
            if intel_src.exists():
                (tmp_root / "NOTES" / "INTEL.md").symlink_to(intel_src)

            try:
                prompt, pf = build_exact_prompt(
                    notes_dir, bra_state_dir, finding_id, sandbox_findings, seed_mode
                )
            except ValueError as e:
                yield f"ERROR: {e}\n"
                return

            yield f"FINDING-{finding_id}: {pf.severity} — {pf.title}\n"
            yield f"Seed mode: {seed_mode}\n"
            yield f"Sandbox: {sandbox_findings}\n\n"
            yield "Running subagent...\n\n"

            from bra.core.agent import run_agent
            from bra.core.finding_enforcer import FindingEnforcer

            async for message in run_agent(prompt, allowed_tools=ALLOWED_TOOLS):
                if isinstance(message, dict):
                    mtype = message.get("type", "")
                    if mtype in ("assistant_text", "text"):
                        content = str(message.get("content", ""))
                        if content:
                            yield content
                    elif mtype == "tool_use":
                        yield f"\n[tool: {message.get('name', '')}]\n"
                    elif mtype == "error":
                        yield f"\n[ERROR: {message.get('content', '')}]\n"
                else:
                    cls = type(message).__name__
                    if cls == "AssistantMessage":
                        for block in getattr(message, "content", []):
                            if hasattr(block, "text"):
                                yield str(block.text)

            produced = _extract_finding_block(
                sandbox_findings.read_text(errors="replace"), finding_id
            )

            yield f"\n\n{'='*60}\n"
            yield f"PRODUCED ## [FINDING-{finding_id}] ENTRY:\n"
            yield f"{'='*60}\n\n"
            yield produced if produced else "[NOTHING WRITTEN TO FINDINGS.md]\n"

            # Validate in sandbox
            enforcer = FindingEnforcer(sandbox_findings.parent, bra_state_dir)
            enforcer.findings_path = sandbox_findings
            result = enforcer.validate_finding_record(finding_id)
            yield f"\n\n{'='*60}\n"
            yield f"VALIDATION: {'PASS ✓' if result.valid else 'FAIL ✗'}\n"
            if result.missing_fields:
                yield f"Missing fields: {', '.join(result.missing_fields)}\n"
            for err in result.errors:
                yield f"Error: {err}\n"
            yield f"{'='*60}\n"

        finally:
            shutil.rmtree(str(tmp_root), ignore_errors=True)


harness = FindingDocHarness()


# ---------------------------------------------------------------------------
# Standalone CLI — mirrors findings_flow.py usage pattern
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Finding Documentation Harness — shows exact production subagent prompt "
            "and optionally runs it in a sandbox."
        )
    )
    p.add_argument(
        "--bra-root",
        default="body",
        help="Path to BRA body directory (default: body)",
    )
    p.add_argument(
        "--finding-id",
        required=True,
        help="Finding ID from INTEL.md Key Issues Overview (e.g. 001)",
    )
    p.add_argument(
        "--seed-mode",
        default="skeleton_only",
        choices=SEED_MODES,
        help=(
            "skeleton_only: raw {{PENDING:*}} skeleton (default). "
            "autofilled: tokens pre-substituted by fastpath autofill."
        ),
    )
    p.add_argument(
        "--prompt-only",
        action="store_true",
        help="Print the exact subagent prompt and exit (no API call).",
    )
    p.add_argument(
        "--show-events",
        action="store_true",
        help="Print SDK tool-use events to stderr during streaming.",
    )
    p.add_argument(
        "--save-output",
        default=None,
        help="Save raw agent output to this file (default: harness/output/finding-NNN-doc.md).",
    )
    return p.parse_args()


async def _main() -> int:
    args = _parse_args()

    bra_root = Path(args.bra_root).resolve()
    if not bra_root.exists():
        print(f"[error] BRA root not found: {bra_root}", file=sys.stderr)
        return 1

    finding_id = str(args.finding_id).strip().zfill(3)
    notes_dir = bra_root / "layer3-engagement" / "NOTES"
    bra_state_dir = bra_root / ".bra"

    # Validate finding exists in INTEL.md
    intel_path = notes_dir / "INTEL.md"
    pf_check = _resolve_from_intel(intel_path, finding_id)
    if pf_check is None:
        print(
            f"[error] FINDING-{finding_id} not found in INTEL.md ## Key Issues Overview",
            file=sys.stderr,
        )
        print(
            "[hint] Only findings listed in the Key Issues Overview table are supported.",
            file=sys.stderr,
        )
        return 1

    print(
        f"[info] FINDING-{finding_id}: {pf_check.severity} — {pf_check.title}",
        file=sys.stderr,
    )
    print(f"[info] Seed mode: {args.seed_mode}", file=sys.stderr)

    # Build sandbox
    tmp_root = Path(tempfile.mkdtemp(prefix="bra_doc_harness_"))
    try:
        sandbox_notes = tmp_root / "NOTES"
        sandbox_notes.mkdir()
        (sandbox_notes / "reqs").mkdir()
        sandbox_findings = sandbox_notes / "FINDINGS.md"
        sandbox_findings.write_text("# Findings\n\n---\n\n")
        if intel_path.exists():
            (sandbox_notes / "INTEL.md").symlink_to(intel_path)

        prompt, pf = build_exact_prompt(
            notes_dir, bra_state_dir, finding_id, sandbox_findings, args.seed_mode
        )

        if args.prompt_only:
            print(prompt)
            print(f"\n--- allowed_tools: {ALLOWED_TOOLS}", file=sys.stderr)
            return 0

        # Verify API key
        api_key = _resolve_api_key()
        if not api_key:
            print(
                "[error] No API key. Set ANTHROPIC_API_KEY or put key in "
                "boots/harness/apikey.txt",
                file=sys.stderr,
            )
            return 1

        print(f"[info] Running subagent (allowed_tools={ALLOWED_TOOLS})", file=sys.stderr)
        print("---", file=sys.stderr)

        raw_output, produced_block = await run_subagent_sandbox(
            prompt, sandbox_findings, bra_state_dir, finding_id,
            show_events=args.show_events,
        )

        # Save raw output
        save_path = (
            Path(args.save_output)
            if args.save_output
            else Path(__file__).parent / "output" / f"finding-{finding_id}-doc.md"
        )
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(raw_output)
        print(f"[info] Raw agent output saved to {save_path}", file=sys.stderr)

        # Print the produced finding block
        print("\n" + "=" * 60)
        print(f"PRODUCED ## [FINDING-{finding_id}] ENTRY:")
        print("=" * 60 + "\n")
        print(produced_block if produced_block else "[NOTHING WRITTEN TO FINDINGS.md]")

        # Validate
        from bra.core.finding_enforcer import FindingEnforcer

        enforcer = FindingEnforcer(sandbox_notes, bra_state_dir)
        enforcer.findings_path = sandbox_findings
        result = enforcer.validate_finding_record(finding_id)

        print("\n" + "=" * 60)
        print(f"VALIDATION: {'PASS ✓' if result.valid else 'FAIL ✗'}")
        if result.missing_fields:
            print(f"  Missing: {', '.join(result.missing_fields)}")
        for err in result.errors:
            print(f"  Error: {err}")
        print("=" * 60)

        return 0 if result.valid else 1

    finally:
        shutil.rmtree(str(tmp_root), ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
