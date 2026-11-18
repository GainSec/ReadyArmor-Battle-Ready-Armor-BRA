"""Agent-based report enhancement module.

After shell scripts (report-ready.sh, disclose.sh) produce base templates,
this module uses run_agent() to generate contextual content: executive
summaries, risk assessments, recommendations, and disclosure narratives.

Called as step 4 of the end-engagement sequence in boots/engage.py.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Maximum context chars sent in prompts to stay within limits.
_MAX_CONTEXT_CHARS = 50_000


async def enhance_reports(bra_root: str, report_types: list[str]) -> dict:
    """Orchestrate all report enhancements.

    Args:
        bra_root: Path to body root (contains layer3-engagement/, .bra/, etc.)
        report_types: List of report types selected (e.g. ["generic", "vendor", "cna"])

    Returns:
        Status dict with keys: success (bool), summary (str), details (dict per report).
    """
    root = Path(bra_root)
    results: dict[str, Any] = {}

    # Always enhance the main engagement report
    results["engagement_report"] = await _enhance_engagement_report(root)

    if "vendor" in report_types:
        results["vendor_submission"] = await _enhance_vendor_submission(root)

    if "cna" in report_types:
        results["cna_submission"] = await _enhance_cna_submission(root)

    succeeded = sum(1 for v in results.values() if v)
    total = len(results)
    summary = f"Enhanced {succeeded}/{total} reports"
    if succeeded == 0:
        summary = "Report enhancement skipped (no reports enhanced)"

    return {"success": succeeded > 0, "summary": summary, "details": results}


async def _enhance_engagement_report(root: Path) -> bool:
    """Enhance REPORT.md with agent-generated content."""
    report_file = root / "layer3-engagement" / "REPORT.md"
    if not report_file.exists():
        logger.info("REPORT.md not found, skipping enhancement")
        return False

    ctx = _collect_context(root)
    prompt = f"""You are writing sections for a penetration testing engagement report.

{ctx}

---

Generate the following sections. Use the EXACT section markers shown.
Write professionally for a mixed technical/executive audience.
Do NOT include file paths or internal framework references.

### SECTION: Executive Summary
Write 2-3 paragraphs: scope overview, key findings summary, overall risk
posture. Written for C-level executives who need to understand business impact.

### SECTION: Risk Summary
Write 1-2 paragraphs: severity distribution analysis, what the findings mean
for the target's security posture, comparison to industry baseline if relevant.

### SECTION: Recommendations Summary
Write 3-5 numbered recommendations prioritized by risk. Each should reference
specific findings and give actionable next steps.

### SECTION: Intelligence Highlights
Write 3-7 bullet points highlighting the most important intelligence gathered.
Reference specific services, endpoints, configurations, or behaviors observed.

### SECTION: Remediation Roadmap Immediate
Write 2-4 rows for a markdown table (| Finding | Action | Owner |) for
0-30 day actions based on critical/high findings.

### SECTION: Remediation Roadmap Short
Write 2-3 rows for 30-90 day actions based on medium findings.

### SECTION: Remediation Roadmap Long
Write 1-2 rows for 90+ day actions (regression prevention, hardening).
"""

    try:
        output = await _run_agent_for_text(prompt)
    except Exception as exc:
        import traceback
        logger.warning("Agent enhancement of REPORT.md failed: %s\n%s", exc, traceback.format_exc())
        print(f"[report-enhance] REPORT.md enhancement failed: {exc}", flush=True)
        return False

    if not output:
        return False

    sections = _parse_sections(output)
    if not sections:
        logger.warning("No sections parsed from agent output for REPORT.md")
        return False

    content = report_file.read_text(encoding="utf-8")
    patched = content

    # Map section names to report headings
    heading_map = {
        "Executive Summary": "Executive Summary",
        "Risk Summary": "Risk Summary",
        "Recommendations Summary": "Recommendations Summary",
        "Intelligence Highlights": "Intelligence Highlights",
        "Remediation Roadmap Immediate": "Immediate (0-30 days)",
        "Remediation Roadmap Short": "Short-term (30-90 days)",
        "Remediation Roadmap Long": "Long-term (90+ days)",
    }

    patches_applied = 0
    for section_name, section_content in sections.items():
        heading = heading_map.get(section_name)
        if not heading:
            continue
        new_content = _patch_section(patched, heading, section_content)
        if new_content != patched:
            patched = new_content
            patches_applied += 1

    if patches_applied > 0:
        report_file.write_text(patched, encoding="utf-8")
        logger.info("REPORT.md enhanced with %d sections", patches_applied)
        return True

    return False


async def _enhance_vendor_submission(root: Path) -> bool:
    """Enhance vendor-submission.md with agent-generated content."""
    vendor_file = root / "layer3-engagement" / "disclosure" / "vendor-submission.md"
    if not vendor_file.exists():
        logger.info("vendor-submission.md not found, skipping enhancement")
        return False

    ctx = _collect_context(root)
    prompt = f"""You are writing sections for a vendor security disclosure document.

{ctx}

---

Generate the following sections. Use the EXACT section markers shown.
Write professionally. This goes directly to the vendor's security team.

### SECTION: Introduction
Write 2-3 paragraphs: who the researcher is, what was tested, what was found
at a high level, commitment to responsible disclosure, and request for
acknowledgment.

### SECTION: Description
Write 1-2 paragraphs providing an aggregate description of the vulnerabilities
found. Summarize the types of issues, their commonalities, and affected
components.

### SECTION: Impact
Write 1-2 paragraphs on the aggregate security impact. What could an attacker
achieve? What data/systems are at risk? Be specific but don't include
exploitation details.
"""

    try:
        output = await _run_agent_for_text(prompt)
    except Exception as exc:
        logger.warning("Agent enhancement of vendor-submission.md failed: %s", exc)
        return False

    if not output:
        return False

    sections = _parse_sections(output)
    if not sections:
        return False

    content = vendor_file.read_text(encoding="utf-8")
    patched = content

    patches_applied = 0
    for section_name in ("Introduction", "Description", "Impact"):
        section_content = sections.get(section_name)
        if not section_content:
            continue
        new_content = _patch_section(patched, section_name, section_content)
        if new_content != patched:
            patched = new_content
            patches_applied += 1

    if patches_applied > 0:
        vendor_file.write_text(patched, encoding="utf-8")
        logger.info("vendor-submission.md enhanced with %d sections", patches_applied)
        return True

    return False


async def _enhance_cna_submission(root: Path) -> bool:
    """Enhance cna-submission.md with agent-generated content."""
    cna_file = root / "layer3-engagement" / "disclosure" / "cna-submission.md"
    if not cna_file.exists():
        logger.info("cna-submission.md not found, skipping enhancement")
        return False

    ctx = _collect_context(root, cna_mode=True)
    prompt = f"""You are writing sections for a CVE/CNA submission. Content must be suitable
for public disclosure — NO exploitation details, NO internal paths, NO PoC code.

{ctx}

---

Generate the following sections. Use the EXACT section markers shown.

### SECTION: Description
Write 1-2 concise paragraphs describing the vulnerability suitable for a
public CVE entry. Focus on what the vulnerability IS, not how to exploit it.
Reference CWE categories if applicable.

### SECTION: Impact
Write 1-2 concise paragraphs on impact WITHOUT exploitation details. What
is the worst-case outcome? What access does an attacker gain?
"""

    try:
        output = await _run_agent_for_text(prompt)
    except Exception as exc:
        logger.warning("Agent enhancement of cna-submission.md failed: %s", exc)
        return False

    if not output:
        return False

    sections = _parse_sections(output)
    if not sections:
        return False

    content = cna_file.read_text(encoding="utf-8")
    patched = content

    patches_applied = 0
    for section_name in ("Description", "Impact"):
        section_content = sections.get(section_name)
        if not section_content:
            continue
        new_content = _patch_section(patched, section_name, section_content)
        if new_content != patched:
            patched = new_content
            patches_applied += 1

    if patches_applied > 0:
        cna_file.write_text(patched, encoding="utf-8")
        logger.info("cna-submission.md enhanced with %d sections", patches_applied)
        return True

    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _filter_findings_content(content: str, include_ids: list) -> str:
    """Return FINDINGS.md content with only the specified finding IDs included."""
    include_set = {str(i).lstrip("0") or "0" for i in include_ids}
    # Split on ## [FINDING-NNN] headers, keep preamble + selected sections
    sections = re.split(r'(?=^## \[FINDING-\d+\])', content, flags=re.MULTILINE)
    kept: list[str] = []
    for section in sections:
        m = re.match(r'^## \[FINDING-(\d+)\]', section)
        if not m:
            kept.append(section)  # preamble / non-finding content
            continue
        fid = m.group(1).lstrip("0") or "0"
        if fid in include_set:
            kept.append(section)
    return "".join(kept)


def _collect_context(root: Path, *, cna_mode: bool = False) -> str:
    """Read engagement files and build a context string for the prompt."""
    parts: list[str] = []

    # Scope
    scope_file = root / "layer3-engagement" / "SCOPE.md"
    if scope_file.exists():
        parts.append("## Engagement Scope\n")
        parts.append(scope_file.read_text(encoding="utf-8"))

    # Engagement metadata
    meta_file = root / ".bra" / "engagement_meta.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            parts.append("\n## Engagement Metadata\n")
            parts.append(f"- Started: {meta.get('started_at', 'Unknown')}")
            parts.append(f"- Ended: {meta.get('ended_at', 'Unknown')}")
        except Exception:
            pass

    # Disclosure profile
    profile_file = root / "layer3-engagement" / "disclosure" / ".disclosure-profile.env"
    if profile_file.exists():
        parts.append("\n## Disclosure Profile\n")
        parts.append(profile_file.read_text(encoding="utf-8"))

    # Findings
    findings_file = root / "layer3-engagement" / "NOTES" / "FINDINGS.md"
    if findings_file.exists():
        findings_content = findings_file.read_text(encoding="utf-8")
        # Apply selection filter if present
        filter_file = root / ".bra" / "report_findings_filter.json"
        if filter_file.exists():
            try:
                include_ids = json.loads(filter_file.read_text(encoding="utf-8")).get("include")
                if include_ids is not None:
                    findings_content = _filter_findings_content(findings_content, include_ids)
            except Exception:
                pass
        if cna_mode:
            # Strip PoC sections for CNA context
            findings_content = re.sub(
                r'### Proof of Concept.*?(?=\n### |\n## |\Z)',
                '### Proof of Concept\n[Redacted for CNA context]\n',
                findings_content,
                flags=re.DOTALL,
            )
        label = "Finding Records (for context only — do not reproduce PoC details)" if cna_mode else "Finding Records"
        parts.append(f"\n## {label}\n")
        parts.append(findings_content)

    # Intel (not for CNA)
    if not cna_mode:
        intel_file = root / "layer3-engagement" / "NOTES" / "INTEL.md"
        if intel_file.exists():
            parts.append("\n## Intelligence Notes\n")
            parts.append(intel_file.read_text(encoding="utf-8"))

    # Stats (not for CNA)
    if not cna_mode:
        stats_file = root / "layer3-engagement" / "STATS.md"
        if stats_file.exists():
            parts.append("\n## Statistics\n")
            parts.append(stats_file.read_text(encoding="utf-8"))

    combined = "\n".join(parts)

    # Truncate if needed
    if len(combined) > _MAX_CONTEXT_CHARS:
        combined = combined[:_MAX_CONTEXT_CHARS] + "\n\n[... truncated for length ...]"

    return combined


async def _run_agent_for_text(prompt: str, model: Optional[str] = None) -> str:
    """Run a one-shot agent query and collect all text output.

    Uses the SDK ``query()`` helper which manages the subprocess lifecycle
    automatically (connect → query → disconnect) rather than the lower-level
    ``ClaudeSDKClient`` used by the main engage agent.  This avoids the
    subprocess-management issues that caused step 4 to hang.

    Returns concatenated text from all AssistantMessage blocks.
    """
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions
    except ImportError:
        raise RuntimeError("claude-agent-sdk is not installed")

    import os

    # Build a clean env without CLAUDECODE — the Claude CLI refuses to start
    # if it detects it's inside another Claude Code session.
    clean_env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    from bra.config.settings import get_proxy_config
    proxy_cfg = get_proxy_config()
    if proxy_cfg["proxy_enabled"]:
        clean_env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{proxy_cfg['proxy_port']}"

    opts = ClaudeAgentOptions(
        allowed_tools=["Read", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        env=clean_env,
    )
    if model:
        opts.model = model

    text_parts: list[str] = []

    async for message in query(prompt=prompt, options=opts):
        # SDK message object — extract text from AssistantMessage content blocks
        msg_class = type(message).__name__
        if msg_class == "AssistantMessage":
            for block in getattr(message, "content", []):
                text = getattr(block, "text", None)
                if text and str(text).strip():
                    text_parts.append(str(text))
        elif isinstance(message, dict) and message.get("type") == "error":
            raise RuntimeError(message.get("content", "Unknown error"))

    return "\n".join(text_parts)


def _parse_sections(output: str) -> dict[str, str]:
    """Parse agent output by ### SECTION: markers.

    Returns dict mapping section name to content.
    """
    sections: dict[str, str] = {}
    # Split on section markers
    parts = re.split(r'###\s*SECTION:\s*', output)

    for part in parts:
        if not part.strip():
            continue
        # First line is the section name
        name, _, content = part.partition('\n')
        name = name.strip()
        content = content.strip()
        if name and content:
            sections[name] = content

    return sections


def _patch_section(file_content: str, heading: str, new_content: str) -> str:
    """Replace content under a markdown heading with new content.

    Finds the heading (## or ###) and replaces everything between it and
    the next heading of equal or higher level, or a --- separator.
    """
    # Match ### or ## headings
    escaped = re.escape(heading)
    pattern = rf'(###?\s*{escaped}\s*\n\n?).*?(?=\n---|\n##[# ]|\Z)'
    replacement = rf'\g<1>{new_content}\n'
    result = re.sub(pattern, replacement, file_content, count=1, flags=re.DOTALL)
    return result
