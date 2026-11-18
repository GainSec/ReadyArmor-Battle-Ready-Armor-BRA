#!/usr/bin/env python3
"""Probe the exact prompt and evidence a subagent would receive for a given finding.
Optionally runs the real subagent end-to-end in a sandbox.

Usage:
    python head/probe_subagent_prompt.py 009              # print prompt + evidence + summary
    python head/probe_subagent_prompt.py 009 --run        # run real subagent, show produced block + validation
    python head/probe_subagent_prompt.py --list           # list all queued findings
    python head/probe_subagent_prompt.py 3                # pads to 003

Output flags (probe mode only):
    --prompt-only       print only the documentation prompt
    --evidence-only     print only the inline evidence block
    --skeleton-only     print only the current FINDINGS.md skeleton for this finding
    --raw-artifact      print the resolved raw artifact path and first 2000 chars
    --show-events       (--run only) print tool-use events to stderr while streaming
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve repo layout
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent          # BRA-V15-1-DEV/
BODY_ROOT = REPO_ROOT / "body"
HEAD_ROOT = REPO_ROOT / "head"

NOTES_DIR = BODY_ROOT / "layer3-engagement" / "NOTES"
BRA_STATE = BODY_ROOT / ".bra"

FINDINGS_TOOLS = ["Write"]  # Write-only: agent writes NNN-output.md to .bra/artifacts/
FINDINGS_SYSTEM_PROMPT = (
    "You are a world-class offensive security operator writing detailed technical sections "
    "for a professional penetration testing report. "
    "Write 2-4 sentences of substantive technical content for each numbered field. "
    "Use a single Write call to output the file. Do not read any files."
)

DEFAULT_TIMEOUT_SECONDS = 90       # one Read + one Write should be well under 90s
DEFAULT_MAX_CHARS = 40_000         # ~10k tokens — stops runaway generation

# Add head/ to sys.path so we can import bra.*
for _p in (str(HEAD_ROOT), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pad_id(raw: str) -> str:
    """Normalise a finding ID to zero-padded 3-digit string."""
    raw = raw.strip().upper().removeprefix("FINDING-")
    try:
        return f"{int(raw):03d}"
    except ValueError:
        return raw


def _load_queue() -> list[dict]:
    """Load the raw pending queue from .bra/pending_findings.json."""
    pf = BRA_STATE / "pending_findings.json"
    if not pf.exists():
        return []
    try:
        data = json.loads(pf.read_text())
        if isinstance(data, list):
            return data
        return data.get("pending", [])
    except Exception:
        return []


def _list_findings(queue: list[dict]) -> None:
    print(f"{'ID':<8} {'SEV':<10} TITLE")
    print("-" * 60)
    for item in queue:
        fid = item.get("id", "?")
        sev = item.get("severity", "?")
        title = item.get("title", "?")
        marker = item.get("source_marker", "")
        cap = ""
        m = re.search(r"capture_id:\s*(\S+)", marker, re.IGNORECASE)
        if m:
            cap = f"  [capture_id: {m.group(1)}]"
        print(f"FINDING-{fid:<4} {sev:<10} {title}{cap}")


def _section(title: str, content: str, width: int = 80) -> str:
    bar = "=" * width
    return f"\n{bar}\n  {title}\n{bar}\n{content}\n"


def _extract_finding_block(content: str, fid: str) -> str:
    pat = re.compile(
        rf'(## \[FINDING-{re.escape(fid)}\].*?)(?=\n## \[FINDING-|\Z)',
        re.DOTALL,
    )
    m = pat.search(content)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Sandbox setup
# ---------------------------------------------------------------------------

def _make_sandbox(fid: str, enforcer) -> tuple[Path, Path]:
    """Create a temp dir with a fresh FINDINGS.md + reqs/, symlink real INTEL.md
    and any existing evidence/context files.  Returns (sandbox_findings, tmp_root).
    """
    tmp = Path(tempfile.mkdtemp(prefix=f"bra_probe_{fid}_"))
    tmp_notes = tmp / "NOTES"
    tmp_notes.mkdir()
    tmp_reqs = tmp_notes / "reqs"
    tmp_reqs.mkdir()

    sandbox_findings = tmp_notes / "FINDINGS.md"
    sandbox_findings.write_text("# Findings\n\n---\n\n")

    intel_src = NOTES_DIR / "INTEL.md"
    if intel_src.exists():
        (tmp_notes / "INTEL.md").symlink_to(intel_src)

    # Symlink real evidence/context files so _build_inline_evidence() fires
    real_reqs = NOTES_DIR / "reqs"
    for suffix in (f"finding-{fid}-evidence.txt", f"finding-{fid}-context.md"):
        src = real_reqs / suffix
        dst = tmp_reqs / suffix
        if src.exists() and not dst.exists():
            try:
                dst.symlink_to(src)
            except Exception:
                pass

    return sandbox_findings, tmp


# ---------------------------------------------------------------------------
# Subagent runner
# ---------------------------------------------------------------------------

async def _run_subagent(
    fid: str,
    finding,
    enforcer_cls,
    show_events: bool,
    timeout_seconds: int,
    max_chars: int,
) -> None:
    from bra.core.agent import run_agent
    from bra.config.settings import set_bra_root

    set_bra_root(BODY_ROOT)

    # Use the real FINDINGS.md — governance hooks block writes to temp dirs
    enforcer = enforcer_cls(notes_dir=NOTES_DIR, bra_state_dir=BRA_STATE)

    # Ensure the skeleton exists in the real FINDINGS.md
    if not any(f.id == fid for f in enforcer.pending_queue):
        enforcer.enqueue_finding(
            finding.id, finding.severity, finding.title, finding.source_marker
        )

    prompt = enforcer.get_documentation_prompt(finding, all_pending=[finding])

    # Delete any leftover output file so the agent always writes fresh (no read-before-write confusion)
    output_file = BRA_STATE / "artifacts" / f"{fid}-output.md"
    if output_file.exists():
        output_file.unlink()
        print(f"[probe] Cleaned up leftover {output_file.name}", flush=True)

    tmp_root = None
    try:

        print(_section(f"PROMPT SENT TO SUBAGENT — FINDING-{fid}", prompt))
        print(
            f"\n[probe] Spawning subagent  timeout={timeout_seconds}s  max_chars={max_chars:,}"
            f"  tools={FINDINGS_TOOLS}\n",
            flush=True,
        )

        ts = lambda: time.strftime("%H:%M:%S")
        event_count = 0
        total_chars = 0
        kill_reason: str | None = None

        async def _stream() -> None:
            nonlocal event_count, total_chars, kill_reason
            async for message in run_agent(prompt, allowed_tools=FINDINGS_TOOLS, system_prompt=FINDINGS_SYSTEM_PROMPT, cwd=str(BRA_STATE / "artifacts")):
                event_count += 1
                if isinstance(message, dict):
                    mtype = message.get("type", "")
                    if mtype in ("assistant_text", "text"):
                        content = str(message.get("content", ""))
                        if content.strip():
                            print(content, end="", flush=True)
                            total_chars += len(content)
                    elif mtype == "tool_use":
                        if show_events:
                            print(
                                f"\n{ts()}  [tool] {message.get('name', '')}  "
                                f"{str(message.get('input', ''))[:120]}",
                                file=sys.stderr,
                            )
                    elif mtype == "error":
                        print(f"\n[ERROR] {message.get('content', '')}", flush=True)
                else:
                    cls = type(message).__name__
                    if cls == "AssistantMessage":
                        for block in getattr(message, "content", []):
                            if hasattr(block, "text") and str(block.text).strip():
                                txt = str(block.text)
                                print(txt, end="", flush=True)
                                total_chars += len(txt)
                    elif cls == "ResultMessage":
                        if getattr(message, "is_error", False):
                            print(f"\n[ERROR] {getattr(message, 'result', '')}", flush=True)

                if total_chars >= max_chars:
                    kill_reason = f"max_chars={max_chars:,} reached ({total_chars:,} chars generated)"
                    break

        try:
            await asyncio.wait_for(_stream(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            kill_reason = f"timeout={timeout_seconds}s exceeded"

        if kill_reason:
            print(f"\n\n[probe] KILLED — {kill_reason}", flush=True)
        print(f"[probe] Subagent done — {event_count} events, {total_chars:,} chars generated", flush=True)

        # Merge numbered output file into FINDINGS.md
        merged = enforcer.merge_finding_output(fid)
        print(f"[probe] Merge: {'OK — output spliced into FINDINGS.md' if merged else 'SKIPPED — output file not found'}", flush=True)

        # Extract and show what was written to the real FINDINGS.md
        produced = _extract_finding_block(
            enforcer.findings_path.read_text(errors="replace"), fid
        )
        print(_section(
            f"PRODUCED ## [FINDING-{fid}] ENTRY",
            produced if produced else "[NOTHING WRITTEN TO FINDINGS.md]",
        ))

        # Validate
        result = enforcer.validate_finding_record(fid)
        status = "PASS ✓" if result.valid else "FAIL ✗"
        detail_lines = []
        if result.missing_fields:
            detail_lines.append(f"Missing fields: {', '.join(result.missing_fields)}")
        for err in result.errors:
            detail_lines.append(f"Error: {err}")
        print(_section(
            f"VALIDATION — FINDING-{fid}",
            f"{status}\n" + ("\n".join(detail_lines) if detail_lines else "All checks passed."),
        ))

    finally:
        if tmp_root:
            shutil.rmtree(str(tmp_root), ignore_errors=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("finding_id", nargs="?",
                        help="Finding number (e.g. 001, FINDING-003, 7)")
    parser.add_argument("--list", action="store_true",
                        help="List all queued findings and exit")
    parser.add_argument("--run", action="store_true",
                        help="Spawn a real subagent end-to-end in a sandbox and show produced block + validation")
    parser.add_argument("--show-events", action="store_true",
                        help="(--run) print tool-use events to stderr while streaming")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, metavar="SECS",
                        help=f"(--run) kill subagent after this many seconds (default: {DEFAULT_TIMEOUT_SECONDS})")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS, metavar="N",
                        help=f"(--run) kill after ~N chars of generated text (default: {DEFAULT_MAX_CHARS:,})")
    parser.add_argument("--prompt-only", action="store_true",
                        help="Print only the documentation prompt")
    parser.add_argument("--evidence-only", action="store_true",
                        help="Print only the inline evidence block")
    parser.add_argument("--skeleton-only", action="store_true",
                        help="Print only the FINDINGS.md skeleton slice")
    parser.add_argument("--raw-artifact", action="store_true",
                        help="Print the resolved raw artifact path and first 2000 chars")
    args = parser.parse_args()

    queue = _load_queue()

    if args.list:
        _list_findings(queue)
        return

    if not args.finding_id:
        parser.print_help()
        sys.exit(1)

    fid = _pad_id(args.finding_id)

    entry = next((e for e in queue if _pad_id(str(e.get("id", ""))) == fid), None)
    if entry is None:
        print(f"[!] FINDING-{fid} not found in pending queue.")
        print(f"    Queue has {len(queue)} entries. Use --list to see them.")
        sys.exit(1)

    try:
        from bra.core.finding_enforcer import FindingEnforcer, PendingFinding
    except ImportError as e:
        print(f"[!] Cannot import bra: {e}")
        print(f"    Ensure {HEAD_ROOT} is on PYTHONPATH or run from repo root.")
        sys.exit(1)

    enforcer = FindingEnforcer(notes_dir=NOTES_DIR, bra_state_dir=BRA_STATE)

    finding = next((f for f in enforcer.pending_queue if f.id == fid), None)
    if finding is None:
        finding = PendingFinding.from_dict(entry)
        enforcer.pending_queue.insert(0, finding)

    all_pending = list(enforcer.pending_queue)

    # --run: full end-to-end subagent test in sandbox
    if args.run:
        asyncio.run(_run_subagent(
            fid, finding, FindingEnforcer,
            show_events=args.show_events,
            timeout_seconds=args.timeout,
            max_chars=args.max_chars,
        ))
        return

    # -----------------------------------------------------------------------
    # Probe-only output
    # -----------------------------------------------------------------------
    only_flags = [args.prompt_only, args.evidence_only, args.skeleton_only, args.raw_artifact]
    show_all = not any(only_flags)

    if show_all or args.prompt_only:
        prompt = enforcer.get_documentation_prompt(finding, all_pending=all_pending)
        print(_section(f"DOCUMENTATION PROMPT — FINDING-{fid}", prompt))

    if show_all or args.evidence_only:
        evidence = enforcer._build_inline_evidence(fid)
        print(_section(f"INLINE EVIDENCE BLOCK — FINDING-{fid}",
                       evidence if evidence.strip() else "(empty — no evidence content found)"))

    if show_all or args.skeleton_only:
        skeleton = "(FINDINGS.md not found)"
        if enforcer.findings_path.exists():
            content = enforcer.findings_path.read_text(errors="replace")
            pat = re.compile(
                rf'(## \[FINDING-{re.escape(fid)}\].*?)(?=\n## \[FINDING-|\Z)',
                re.DOTALL,
            )
            m = pat.search(content)
            skeleton = m.group(1) if m else f"(FINDING-{fid} not found in FINDINGS.md)"
        print(_section(f"FINDINGS.md SKELETON — FINDING-{fid}", skeleton))

    if show_all or args.raw_artifact:
        source_hint = enforcer._extract_source_hint(finding.source_marker)
        resolved_hint = enforcer._resolve_source_hint_from_capture(source_hint, finding.source_marker)
        raw_artifact = enforcer._find_best_raw_evidence_artifact(
            resolved_hint or source_hint, finding.source_marker
        )
        if raw_artifact:
            rel = enforcer._relative_to_workspace(raw_artifact)
            content = raw_artifact.read_text(errors="replace")
            preview = content[:2000] + ("\n... [truncated]" if len(content) > 2000 else "")
            print(_section(
                f"RESOLVED RAW ARTIFACT — FINDING-{fid}",
                f"Path: {rel}\nSize: {len(content)} chars\n\n{preview}",
            ))
        else:
            cap_m = re.search(r"capture_id:\s*(\S+)", finding.source_marker, re.IGNORECASE)
            cap_id = cap_m.group(1) if cap_m else "(none)"
            print(_section(
                f"RESOLVED RAW ARTIFACT — FINDING-{fid}",
                f"(none — capture_id '{cap_id}' did not resolve and fuzzy match found nothing)\n"
                f"source_hint: {source_hint!r}\n"
                f"resolved_hint: {resolved_hint!r}\n"
                f"source_marker: {finding.source_marker}",
            ))

    if show_all:
        evidence_file = enforcer.reqs_dir / f"finding-{fid}-evidence.txt"
        context_file = enforcer.reqs_dir / f"finding-{fid}-context.md"
        poc_file = enforcer.reqs_dir / f"finding-{fid}-poc.sh"

        cap_m = re.search(r"capture_id:\s*(\S+)", finding.source_marker, re.IGNORECASE)
        cap_id = cap_m.group(1) if cap_m else "(none)"

        from bra.core.capture_provenance import resolve_capture
        resolved = resolve_capture(cap_id, BRA_STATE)

        def file_status(p: Path) -> str:
            if not p.exists():
                return "MISSING"
            size = p.stat().st_size
            try:
                content = p.read_text(errors="replace")
                is_trivial = enforcer._is_metadata_only_evidence(content)
                note = " [metadata-only]" if is_trivial else ""
            except Exception:
                note = ""
            return f"{size} bytes{note}"

        lines = [
            f"Finding:       FINDING-{fid}",
            f"Title:         {finding.title}",
            f"Severity:      {finding.severity}",
            f"capture_id:    {cap_id}",
            f"  → resolves:  {'YES → ' + str(resolved.get('artifact_path', '')) if resolved else 'NO (not in evidence_index.jsonl)'}",
            f"evidence.txt:  {file_status(evidence_file)}",
            f"context.md:    {file_status(context_file)}",
            f"poc.sh:        {file_status(poc_file)}",
            f"Queue depth:   {len(all_pending)} pending",
        ]
        print(_section("SUMMARY", "\n".join(lines)))


if __name__ == "__main__":
    main()
