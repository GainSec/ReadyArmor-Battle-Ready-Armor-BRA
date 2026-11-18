"""CLI entry point for BRA.

Usage:
    bra              Launch TUI (default)
    bra --minimal    Minimal output mode
    bra status       Show project status
    bra --help       Show all commands
"""

import typer
from typing import Optional
from pathlib import Path

from bra import __version__
from bra.config.settings import get_runtime_config, set_runtime_config

app = typer.Typer(
    name="bra",
    help="Battle Ready Armor - AI-orchestrated security assessment framework",
    no_args_is_help=False,
)
profile_app = typer.Typer(help="Manage TUI profiles")
app.add_typer(profile_app, name="profile")


def version_callback(value: bool):
    if value:
        print(f"Battle Ready Armor v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit"
    ),
    minimal: bool = typer.Option(
        False, "--minimal", "-m",
        help="Minimal output mode (no TUI)"
    ),
    resume: bool = typer.Option(
        False, "--resume", "-r",
        help="Resume without banner"
    ),
    status_flag: bool = typer.Option(
        False, "--status", "-s",
        help="Quick status check"
    ),
    quick: bool = typer.Option(
        False, "--quick", "-q",
        help="Auto-detect and suggest next action"
    ),
    new: bool = typer.Option(
        False, "--new", "-n",
        help="Initialize new engagement"
    ),
    model: Optional[str] = typer.Option(
        None, "--model",
        help="Claude model override (e.g. claude-sonnet-4-6)",
    ),
    ui_profile: Optional[str] = typer.Option(
        None, "--ui-profile",
        help="TUI profile override (e.g. command-center, executive-minimal, neon-ops)",
    ),
):
    """Launch BRA. No command defaults to TUI."""
    if ctx.invoked_subcommand is not None:
        return

    if model is not None:
        set_runtime_config(model=model, persist=True)
    if ui_profile is not None:
        set_runtime_config(ui_profile=ui_profile, ui_pack=ui_profile, persist=False)

    # Handle flags
    if status_flag:
        _show_status()
        return

    if quick:
        _quick_action(minimal)
        return

    if new:
        _new_engagement(minimal)
        return

    if resume:
        _resume_engagement(minimal)
        return

    # Default: launch TUI or minimal mode
    if minimal:
        _run_minimal()
    else:
        _run_tui()


def _show_status():
    """Show quick status."""
    from bra.core.bridge import detect_session_state, run_script

    state = detect_session_state()
    print(f"Session state: {state}")

    # Try to run status.py if available
    try:
        result = run_script("status.py", "--compact")
        print(result.stdout)
    except FileNotFoundError:
        print("(status.py not available)")


def _quick_action(minimal: bool):
    """Auto-detect and suggest next action."""
    from bra.core.bridge import detect_session_state

    state = detect_session_state()
    print(f"[bra] Session state: {state}")

    if state == "FRESH":
        print("[bra] Suggested: Run 'bra --new' to initialize")
    elif state == "NEEDS_SCOPE":
        print("[bra] Suggested: Run 'bra scope' to define scope")
    elif state == "READY":
        print("[bra] Suggested: Run 'bra' to start engagement")
    elif state == "IN_PROGRESS":
        print("[bra] Suggested: Run 'bra --resume' to continue")
    else:
        print("[bra] Engagement complete")


def _new_engagement(minimal: bool):
    """Initialize new engagement."""
    print("[bra] Initializing new engagement...")
    try:
        from bra.core.bridge import run_script
        result = run_script("precheck.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] precheck.py not available - creating directories manually")


def _resume_engagement(minimal: bool):
    """Resume engagement."""
    print("[bra] Resuming engagement...")
    # Will launch agent in resume mode


def _run_minimal():
    """Run in minimal mode."""
    import asyncio
    try:
        asyncio.run(_run_minimal_async())
    except KeyboardInterrupt:
        print("\n[bra] Interrupted by user")


async def _run_minimal_async():
    """Async implementation of minimal mode."""
    from bra.ui.minimal import MinimalRenderer
    from bra.core.bridge import detect_session_state
    from bra.core.runner import AgentRunner

    renderer = MinimalRenderer()
    project = _get_project_name()
    renderer.header(project)

    # Check state before proceeding
    state = detect_session_state()

    if state == "FRESH":
        renderer.error("No engagement initialized. Run: bra --new")
        return

    if state == "NEEDS_SCOPE":
        renderer.error("Scope not configured. Run: bra scope")
        return

    renderer.info(f"Session: {state}")
    runtime_config = get_runtime_config()
    model_info = runtime_config.get("model")
    if model_info:
        renderer.info(f"Model: {model_info}")

    # Show tokens
    info = _get_engagement_info()
    renderer.tokens(info["tokens"])

    # Generate handoff prompt
    handoff = _generate_handoff_prompt(info)

    # Create runner with callbacks wired to renderer
    # Note: on_options needs special handling for async input
    runner = AgentRunner(
        model=runtime_config.get("model"),
        on_text=renderer.text,
        on_command=renderer.command,
        on_output=renderer.command_output,
        on_finding=renderer.finding,
        on_lead=renderer.lead,
        on_options=lambda opts: _schedule_options_handler(opts, runner, renderer),
        on_error=renderer.error,
        on_phase_change=renderer.phase,
    )

    renderer.info("Starting agent...")

    # Run agent
    try:
        await runner.run(handoff)
    except Exception as e:
        renderer.error(f"Agent error: {e}")


def _schedule_options_handler(options: list[str], runner: "AgentRunner", renderer: "MinimalRenderer"):
    """Schedule async options handler from sync callback context."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_handle_options_async(options, runner, renderer))
    except RuntimeError:
        # No running loop - handle synchronously
        response = renderer.prompt_options(options)
        if response:
            runner.send_input(response)


def _get_project_name() -> str:
    """Get project name from scope file."""
    info = _get_engagement_info()
    return info.get("name", "unknown")


def _get_engagement_info() -> dict:
    """Get engagement info from scope and notes files.

    Returns:
        dict with 'name', 'type', 'findings', 'leads', 'tokens' keys
    """
    info = {"name": "unknown", "type": "unknown", "findings": 0, "leads": 0, "tokens": []}
    try:
        from bra.config.settings import LAYER3, APPROVALS_DIR

        # Parse SCOPE.md for name, type, and inline approvals
        scope_file = LAYER3 / "SCOPE.md"
        if scope_file.exists():
            content = scope_file.read_text()
            for line in content.splitlines():
                if "**Name:**" in line:
                    info["name"] = line.split("**Name:**")[1].strip()
                elif "**Type:**" in line:
                    info["type"] = line.split("**Type:**")[1].strip()
                # Check for inline approval tokens (e.g., "ACTIVE-TESTING-APPROVAL: YES")
                elif "-APPROVAL:" in line and "YES" in line.upper():
                    token = line.split(":")[0].strip()
                    if token not in info["tokens"]:
                        info["tokens"].append(token)

        # Also check approvals directory for token files
        if APPROVALS_DIR.exists():
            for token_file in APPROVALS_DIR.iterdir():
                if token_file.is_file():
                    token = token_file.name
                    if token not in info["tokens"]:
                        info["tokens"].append(token)

        # Count findings from NOTES/FINDINGS.md
        findings_file = LAYER3 / "NOTES" / "FINDINGS.md"
        if findings_file.exists():
            content = findings_file.read_text()
            # Count lines starting with "### [" which indicate findings
            info["findings"] = content.count("### [")

        # Count leads from NOTES/LEADS.md
        leads_file = LAYER3 / "NOTES" / "LEADS.md"
        if leads_file.exists():
            content = leads_file.read_text()
            # Count lines starting with "### " after the header (leads format)
            lines = content.splitlines()
            info["leads"] = sum(1 for line in lines if line.startswith("### ") and not line.startswith("### ["))
    except Exception:
        pass
    return info


def _generate_handoff_prompt(info: dict) -> str:
    """Generate handoff prompt for agent.

    Args:
        info: Engagement info from _get_engagement_info()

    Returns:
        Formatted handoff prompt string
    """
    from bra.config.settings import LAYER3

    # Extract targets from SCOPE.md
    network_targets = []
    local_targets = []
    scope_file = LAYER3 / "SCOPE.md"

    if scope_file.exists():
        content = scope_file.read_text()
        in_network = False
        in_local = False
        for line in content.splitlines():
            if "### Network Targets" in line:
                in_network, in_local = True, False
            elif "### Local Targets" in line:
                in_network, in_local = False, True
            elif line.startswith("---"):
                in_network, in_local = False, False
            elif line.startswith("- ") and "None" not in line:
                target = line[2:].strip()
                if in_network:
                    network_targets.append(target)
                elif in_local:
                    local_targets.append(target)

    # Build prompt
    lines = [
        "## Engagement Summary",
        f"Target: {info.get('name', 'unknown')}",
        f"Type: {info.get('type', 'unknown')}",
        "Phase: Intelligence",
        "",
        "## Targets",
    ]

    if network_targets:
        lines.append("Network:")
        for t in network_targets:
            lines.append(f"  - {t}")
    if local_targets:
        lines.append("Local:")
        for t in local_targets:
            lines.append(f"  - {t}")
    if not network_targets and not local_targets:
        lines.append("  (none defined)")

    lines.extend([
        "",
        "## Token Status",
    ])

    tokens = info.get("tokens", [])
    active_status = "GRANTED" if "ACTIVE-TESTING-APPROVAL" in tokens else "Not Set"
    destruct_status = "GRANTED" if "DESTRUCTIVE-APPROVAL" in tokens else "Not Set"
    lines.append(f"ACTIVE-TESTING-APPROVAL: {active_status}")
    lines.append(f"DESTRUCTIVE-APPROVAL: {destruct_status}")

    lines.extend([
        "",
        "## Ready to Execute",
        'Tell me what to pursue, or say "continue" for methodology-driven next step.',
    ])

    return "\n".join(lines)


async def _handle_options_async(
    options: list[str],
    runner: "AgentRunner",
    renderer: "MinimalRenderer",
) -> None:
    """Handle options asynchronously by running input() in thread pool.

    Args:
        options: List of option strings
        runner: AgentRunner instance to send response to
        renderer: MinimalRenderer for displaying options
    """
    import asyncio

    loop = asyncio.get_event_loop()
    # Run blocking input() in thread pool executor
    response = await loop.run_in_executor(None, renderer.prompt_options, options)
    if response:
        # Use select_option for numbered input or store response for custom input
        try:
            option_num = int(response)
            selected = runner.select_option(option_num)
            if selected:
                await runner.continue_with_input(selected)
        except ValueError:
            # Custom text input
            await runner.continue_with_input(response)


def _run_tui():
    """Run TUI."""
    from bra.ui.app import BRAApp

    info = _get_engagement_info()
    runtime = get_runtime_config()
    app = BRAApp(
        project=info["name"],
        engagement_type=info["type"],
        findings=info["findings"],
        leads=info["leads"],
        tokens=info["tokens"],
        ui_profile=runtime.get("ui_pack") or runtime.get("ui_profile"),
    )
    try:
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop_active_agents_sync()


# ==================== Commands ====================

@profile_app.command("list")
def profile_list():
    """List available TUI profiles."""
    from bra.ui_v2.pack_engine import list_packs

    for name in list_packs():
        print(name)


@profile_app.command("validate")
def profile_validate(name: str = typer.Argument(..., help="Profile name")):
    """Validate a TUI profile file."""
    from bra.ui_v2.pack_engine import PackValidationError, load_pack

    try:
        load_pack(name, fallback_to_default=False)
        print(f"valid: {name}")
    except (FileNotFoundError, PackValidationError) as exc:
        print(f"invalid: {name}: {exc}")
        raise typer.Exit(code=1)


@profile_app.command("use")
def profile_use(name: str = typer.Argument(..., help="Profile name")):
    """Persist body-local active profile selection."""
    from bra.ui_v2.pack_engine import PackValidationError, load_pack

    try:
        load_pack(name, fallback_to_default=False)
    except (FileNotFoundError, PackValidationError) as exc:
        print(f"invalid: {name}: {exc}")
        raise typer.Exit(code=1)

    set_runtime_config(ui_profile=name, ui_pack=name, persist=True)
    print(f"active profile set: {name}")


@profile_app.command("migrate")
def profile_migrate(
    name: str = typer.Argument(..., help="Legacy profile name to migrate"),
):
    """Migrate a legacy v1 profile to a v2 pack file."""
    from bra.ui_v2.pack_engine import migrate_profile_to_pack_file

    try:
        out = migrate_profile_to_pack_file(name)
    except FileNotFoundError as exc:
        print(f"migration failed: {exc}")
        raise typer.Exit(code=1)
    print(f"migrated: {name} -> {out}")


@profile_app.command("doctor")
def profile_doctor():
    """Show active pack diagnostics and resolution paths."""
    from bra.ui_v2.pack_engine import doctor

    payload = doctor()
    print(f"active: {payload.get('active')}")
    print(f"valid: {payload.get('valid')}")
    if payload.get("loaded"):
        print(f"loaded: {payload.get('loaded')}")
    if payload.get("error"):
        print(f"error: {payload.get('error')}")
    print(f"available: {len(payload.get('available', []))}")

@app.command()
def status():
    """Show project health dashboard."""
    _show_status()


@app.command()
def scope():
    """Interactive scope intake."""
    print("[bra] Running scope intake...")
    try:
        from bra.core.bridge import run_script
        result = run_script("scope-intake.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] scope-intake.py not available")


@app.command()
def precheck():
    """Verify environment readiness."""
    try:
        from bra.core.bridge import run_script
        result = run_script("precheck.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] precheck.py not available")


@app.command()
def tokens(
    action: str = typer.Argument(..., help="grant|revoke|list"),
    token: Optional[str] = typer.Argument(None, help="Token name"),
):
    """Manage approval tokens."""
    from bra.config.settings import APPROVALS_DIR

    if action == "list":
        print("Active tokens:")
        if APPROVALS_DIR.exists():
            for f in APPROVALS_DIR.iterdir():
                if f.is_file():
                    print(f"  - {f.name}")
        else:
            print("  (none)")
    elif action == "grant" and token:
        APPROVALS_DIR.mkdir(parents=True, exist_ok=True)
        (APPROVALS_DIR / token).touch()
        print(f"Granted: {token}")
    elif action == "revoke" and token:
        token_file = APPROVALS_DIR / token
        if token_file.exists():
            token_file.unlink()
            print(f"Revoked: {token}")
        else:
            print(f"Token not found: {token}")
    else:
        print("Usage: bra tokens grant|revoke|list [TOKEN]")


@app.command()
def backup(
    action: str = typer.Argument("create", help="create|list|restore|verify|prune"),
):
    """Manage backups."""
    try:
        from bra.core.bridge import run_script

        if action == "create":
            result = run_script("backup.py")
        elif action == "list":
            result = run_script("backup.py", "--list")
        else:
            result = run_script("backup.py", f"--{action}")

        print(result.stdout)
    except FileNotFoundError:
        print("[bra] backup.sh not available")


@app.command()
def reset(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes"),
    archive: bool = typer.Option(True, "--archive/--no-archive", help="Create archive first"),
):
    """Archive and reset engagement."""
    try:
        from bra.core.bridge import run_script

        args = []
        if dry_run:
            args.append("--dry-run")
        if not archive:
            args.append("--no-archive")

        result = run_script("reset.py", *args)
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] reset.sh not available")


# ==================== Setup & Status Commands ====================

@app.command()
def deploy():
    """Prepare environment for engagement."""
    try:
        from bra.core.bridge import run_script
        result = run_script("deploy.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] deploy.sh not available")


@app.command()
def audit():
    """Comprehensive project audit."""
    try:
        from bra.core.bridge import run_script
        result = run_script("audit.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] audit.sh not available")


@app.command(name="dry-run")
def dry_run_cmd():
    """Lifecycle health check simulation."""
    try:
        from bra.core.bridge import run_script
        result = run_script("dry-run.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] dry-run.sh not available")


@app.command()
def validate():
    """Validate tool/skill mappings."""
    try:
        from bra.core.bridge import run_script
        result = run_script("validate-mappings.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] validate-mappings.sh not available")


# ==================== Approvals & Tokens Commands ====================

@app.command(name="approve-target")
def approve_target(
    target: str = typer.Argument(..., help="Target to approve (IP, domain, etc.)"),
):
    """Add target to approved scope."""
    try:
        from bra.core.bridge import run_script
        result = run_script("approve-target.py", target)
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] approve-target.py not available")


@app.command(name="approve-scan")
def approve_scan(
    scan_type: str = typer.Argument(..., help="Scan type to approve"),
):
    """Approve aggressive scan type."""
    try:
        from bra.core.bridge import run_script
        result = run_script("approve-scan.py", scan_type)
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] approve-scan.sh not available")


@app.command()
def offensive():
    """Offensive testing approval gate."""
    try:
        from bra.core.bridge import run_script
        result = run_script("offensive_gate.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] offensive_gate.sh not available")


@app.command(name="approval-gate")
def approval_gate():
    """Pitch approval status."""
    try:
        from bra.core.bridge import run_script
        result = run_script("approval-gate.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] approval-gate.sh not available")


# ==================== Leads & Findings Commands ====================

@app.command()
def leads():
    """Lead selection & test planning."""
    try:
        from bra.core.bridge import run_script
        result = run_script("leads.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] leads.sh not available")


@app.command(name="materialize-notes")
def materialize_notes(
    notes_dir: Optional[str] = typer.Option(
        None,
        "--notes-dir",
        help="Path to NOTES directory (defaults to body/layer3-engagement/NOTES)",
    ),
    bra_state_dir: Optional[str] = typer.Option(
        None,
        "--bra-state-dir",
        help="Path to .bra state directory (defaults to body/.bra)",
    ),
):
    """Replay marker/capture provenance into INTEL.md, LEADS.md, and FINDINGS.md."""
    from bra.config.settings import BRA_STATE, LAYER3
    from bra.core.findings_materializer import materialize_findings_from_events
    from bra.core.notes_materializer import replay_marker_events_to_notes

    resolved_notes = Path(notes_dir) if notes_dir else (LAYER3 / "NOTES")
    resolved_bra = Path(bra_state_dir) if bra_state_dir else BRA_STATE

    if not resolved_notes.exists():
        print(f"[bra] NOTES directory not found: {resolved_notes}")
        raise typer.Exit(code=1)
    if not resolved_bra.exists():
        print(f"[bra] BRA state directory not found: {resolved_bra}")
        raise typer.Exit(code=1)

    findings_result = materialize_findings_from_events(resolved_notes, resolved_bra)
    intel_result = replay_marker_events_to_notes(resolved_notes, resolved_bra)
    print(
        "[bra] materialize-notes complete: "
        f"intel_events={intel_result.get('intel', 0)}, "
        f"lead_events={intel_result.get('leads', 0)}, "
        f"finding_events={findings_result.get('findings', 0)}"
    )


@app.command()
def hunt():
    """Lead hunting & gap analysis."""
    try:
        from bra.core.bridge import run_script
        result = run_script("hunt.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] hunt.sh not available")


@app.command()
def stats():
    """Engagement statistics."""
    try:
        from bra.core.bridge import run_script
        result = run_script("stats.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] stats.sh not available")


# ==================== Wrap-up & Disclosure Commands ====================

@app.command()
def lessons():
    """Generate lessons learned."""
    try:
        from bra.core.bridge import run_script
        result = run_script("lessons-learned.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] lessons-learned.sh not available")


@app.command()
def disclose():
    """Generate disclosure packages."""
    try:
        from bra.core.bridge import run_script
        result = run_script("disclose.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] disclose.sh not available")


# ==================== Framework Growth Commands ====================

@app.command()
def pitches():
    """Review and approve pitches."""
    try:
        from bra.core.bridge import run_script
        result = run_script("pitches.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] pitches.sh not available")


@app.command()
def growth():
    """Engagement growth engine."""
    try:
        from bra.core.bridge import run_script
        result = run_script("growth.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] growth.sh not available")


@app.command(name="self-improve")
def self_improve():
    """Incremental self-improvement."""
    try:
        from bra.core.bridge import run_script
        result = run_script("self-improvement.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] self-improvement.sh not available")


@app.command()
def dedupe():
    """Deduplicate integrated content."""
    try:
        from bra.core.bridge import run_script
        result = run_script("dedupe-integrated.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] dedupe-integrated.sh not available")


@app.command()
def ingest():
    """Integrate ingested content."""
    try:
        from bra.core.bridge import run_script
        result = run_script("integrate-ingest.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] integrate-ingest.sh not available")


# ==================== Archive & Transfer Commands ====================

@app.command()
def packup():
    """Archive engagement for transfer."""
    try:
        from bra.core.bridge import run_script
        result = run_script("packup.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] packup.sh not available")


@app.command()
def restore(
    archive: str = typer.Argument(..., help="Archive file to restore"),
):
    """Restore from backup archive."""
    try:
        from bra.core.bridge import run_script
        result = run_script("restore.py", archive)
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] restore.sh not available")


@app.command(name="prep-deploy")
def prep_deploy():
    """Package Layer 1 & 2 for deployment."""
    try:
        from bra.core.bridge import run_script
        result = run_script("prep-deploy.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] prep-deploy.sh not available")


# ==================== Remote & Ingest Commands ====================

@app.command(name="remote-ingest")
def remote_ingest(
    path: str = typer.Argument(..., help="Remote path to mount and ingest"),
):
    """Mount and ingest remote filesystem."""
    try:
        from bra.core.bridge import run_script
        result = run_script("remote-ingest.py", path)
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] remote-ingest.sh not available")


@app.command()
def harvest():
    """Collect artifacts with hashing."""
    try:
        from bra.core.bridge import run_script
        result = run_script("ref_harvest.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] ref_harvest.sh not available")


# ==================== Testing Commands ====================

@app.command()
def test():
    """Run framework tests."""
    try:
        from bra.core.bridge import run_script
        result = run_script("run-tests.py")
        print(result.stdout)
    except FileNotFoundError:
        print("[bra] run-tests.sh not available")


if __name__ == "__main__":
    app()
