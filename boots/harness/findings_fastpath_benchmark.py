"""A/B benchmark for findings write-up speed: baseline vs deterministic fastpath.

Fastpath approximates 1/2/3/7:
- Preflight materialization of artifact/PoC/evidence from existing captures/raw.
- Prompt lock: model should not edit system-managed sections.
- Model focuses on narrative + severity/CVSS + likelihood level.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import shutil
import tempfile
import time
from pathlib import Path

from bra.config.settings import set_bra_root
from bra.core.finding_enforcer import FindingEnforcer
from boots.harness.findings_flow import (
    DEFAULT_USER_PROMPT,
    build_effective_prompt,
    resolve_finding,
    run_finding_flow,
)


def _clone_bra_root(src_root: Path, out_root: Path, label: str) -> Path:
    dest = out_root / f"{label}-body"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    # Minimal clone for findings workflow: avoid copying volatile backup trees.
    for sub in (".bra", "layer3-engagement"):
        src_sub = src_root / sub
        dst_sub = dest / sub
        if src_sub.exists():
            shutil.copytree(src_sub, dst_sub, symlinks=True)
    return dest


def _build_fastpath_prompt(enforcer: FindingEnforcer, finding_id: str, user_prompt: str) -> str:
    target, pending = resolve_finding(enforcer, finding_id)
    base = build_effective_prompt(enforcer, target, pending, user_prompt)
    guard = (
        "\n\nFASTPATH MODE (SYSTEM-MANAGED SECTIONS)\n"
        "Do NOT edit these sections: Affected Artifact, Reproduction Steps, Proof of Concept, "
        "Observed Evidence.\n"
        "Only edit: Description, Impact, Attack Vector, Severity, Likelihood, Remediation, "
        "Attack Surface, Tools & Versions.\n"
        "Likelihood must be value-only (High/Medium/Low/Info), no rationale text.\n"
        "Use existing command/output references from .bra/logs/captures.log and .bra/artifacts/raw only.\n"
    )
    return base + guard


def _preflight_materialize(enforcer: FindingEnforcer, finding_id: str) -> list[str]:
    target, _ = resolve_finding(enforcer, finding_id)
    changed: list[str] = []
    normalized_id = str(target.id).zfill(3) if str(target.id).isdigit() else str(target.id)
    target_poc = enforcer.reqs_dir / f"finding-{normalized_id}-poc.sh"
    if target_poc.exists() and enforcer._is_placeholder_poc(target_poc.read_text()):  # noqa: SLF001
        target_poc.unlink()
        changed.append("removed_placeholder_poc")
    materialized = enforcer.materialize_system_sections(target)
    if materialized:
        changed.extend(f"materialize:{item}" for item in materialized)
    if enforcer._normalize_likelihood_for_finding(target.id):  # noqa: SLF001
        changed.append("normalize_likelihood")
    return changed


async def _run_mode(
    label: str,
    src_bra_root: Path,
    out_root: Path,
    finding_id: str,
    timeout_seconds: int,
    fastpath: bool,
) -> dict:
    mode_root = _clone_bra_root(src_bra_root, out_root, label)
    set_bra_root(mode_root)

    notes_dir = mode_root / "layer3-engagement" / "NOTES"
    bra_state = mode_root / ".bra"
    enforcer = FindingEnforcer(notes_dir, bra_state)

    preflight_changes: list[str] = []
    if fastpath:
        preflight_changes = _preflight_materialize(enforcer, finding_id)
        prompt = _build_fastpath_prompt(enforcer, finding_id, DEFAULT_USER_PROMPT)
    else:
        target, pending = resolve_finding(enforcer, finding_id)
        prompt = build_effective_prompt(enforcer, target, pending, DEFAULT_USER_PROMPT)

    stdout_sink = io.StringIO()
    start = time.perf_counter()
    with contextlib.redirect_stdout(stdout_sink):
        output = await run_finding_flow(
            prompt,
            show_events=False,
            timeout_seconds=timeout_seconds,
        )
    elapsed = time.perf_counter() - start

    result = enforcer.validate_finding_record(finding_id)
    output_path = out_root / f"{label}-finding-{finding_id}-output.md"
    output_path.write_text(output)

    return {
        "label": label,
        "elapsed_seconds": round(elapsed, 2),
        "valid": result.valid,
        "missing": result.missing_fields,
        "errors": result.errors,
        "output_path": str(output_path),
        "mode_root": str(mode_root),
        "preflight_changes": preflight_changes,
    }


async def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark findings baseline vs fastpath.")
    parser.add_argument("--bra-root", default="body", help="BRA root to clone for each mode.")
    parser.add_argument("--finding-id", required=True, help="Finding ID, e.g. 003")
    parser.add_argument("--timeout-seconds", type=int, default=300, help="Per-mode timeout.")
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="Only run fastpath mode.",
    )
    args = parser.parse_args()

    src = Path(args.bra_root).resolve()
    if not src.exists():
        raise SystemExit(f"BRA root not found: {src}")

    out_root = Path(tempfile.mkdtemp(prefix="findings-bench-", dir=str((Path(__file__).parent / "output").resolve())))
    print(f"Benchmark output dir: {out_root}")

    results: list[dict] = []
    if not args.skip_baseline:
        print("Running baseline...")
        results.append(
            await _run_mode(
                label="baseline",
                src_bra_root=src,
                out_root=out_root,
                finding_id=args.finding_id,
                timeout_seconds=max(30, args.timeout_seconds),
                fastpath=False,
            )
        )

    print("Running fastpath (1+2+3+7)...")
    results.append(
        await _run_mode(
            label="fastpath",
            src_bra_root=src,
            out_root=out_root,
            finding_id=args.finding_id,
            timeout_seconds=max(30, args.timeout_seconds),
            fastpath=True,
        )
    )

    print("\n=== SUMMARY ===")
    for r in results:
        print(
            f"{r['label']}: elapsed={r['elapsed_seconds']}s valid={r['valid']} "
            f"preflight={r['preflight_changes']} output={r['output_path']}"
        )
        if r["missing"]:
            print(f"  missing: {r['missing']}")
        if r["errors"]:
            print(f"  errors: {r['errors']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
