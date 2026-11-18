#!/usr/bin/env python3
"""Native Ollama client with governance-aware gating."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "codellama:13b"


class OllamaGovernanceError(PermissionError):
    """Raised when fallback use is blocked by governance checks."""

    def __init__(self, reason: str, code: int) -> None:
        super().__init__(reason)
        self.code = code


def _detect_body_root() -> Path:
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if parent.name == "body":
            return parent
    return cwd


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(body_root: Path, level: str, message: str) -> None:
    try:
        log_file = body_root / ".bra" / "logs" / "fallback.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        pass


def _load_env_config(body_root: Path) -> tuple[str, str]:
    host = os.environ.get("OLLAMA_HOST", "")
    model = os.environ.get("OLLAMA_MODEL", "")

    cfg = body_root / ".bra" / "config" / "ollama.env"
    if cfg.is_file():
        try:
            for line in cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in line or line.strip().startswith("#"):
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key == "OLLAMA_HOST" and not host:
                    host = value
                if key == "OLLAMA_MODEL" and not model:
                    model = value
        except OSError:
            pass

    return host or DEFAULT_HOST, model or DEFAULT_MODEL


def _has_active_testing_token(body_root: Path) -> bool:
    if os.environ.get("ACTIVE_TESTING_APPROVAL") == "1":
        return True

    token_file = body_root / ".bra" / "approvals" / "ACTIVE-TESTING-APPROVAL"
    if token_file.is_file():
        return True

    roe_files = [body_root / "layer3-engagement" / "ROE.md", body_root / "layer1" / "rules" / "roe.md"]
    for path in roe_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r"ACTIVE-TESTING-APPROVAL\s*:\s*(GRANTED|SET|ENABLED)", text, re.IGNORECASE):
            return True
        if re.search(r"^\|\s*ACTIVE-TESTING-APPROVAL\s*\|\s*Set\b", text, re.IGNORECASE | re.MULTILINE):
            return True

    return False


def _killswitch_active(body_root: Path) -> bool:
    if os.environ.get("BRA_STOP") == "1":
        return True
    if (body_root / ".bra" / "STOP").is_file():
        return True

    claude_file = body_root / "CLAUDE.md"
    if not claude_file.is_file():
        return False
    try:
        text = claude_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    section = re.search(r"##\s*Kill\s*Switch(?P<section>.*?)(?:\n##\s|\Z)", text, re.IGNORECASE | re.DOTALL)
    if not section:
        return False
    return bool(re.search(r"```(?:\w+)?\s*STOP\s*```", section.group("section"), re.IGNORECASE | re.DOTALL))


def _ollama_governance_check(operation: str, body_root: Path) -> None:
    """Raise ``OllamaGovernanceError`` when operation is not allowed."""
    if _killswitch_active(body_root):
        reason = "Kill switch active"
        _log(body_root, "BLOCKED", f"{reason} - operation: {operation}")
        print("Kill switch active. Fallback operations blocked.", file=sys.stderr)
        raise OllamaGovernanceError(reason, 99)

    if not _has_active_testing_token(body_root):
        reason = "Missing ACTIVE-TESTING-APPROVAL token"
        _log(body_root, "BLOCKED", f"{reason} - operation: {operation}")
        print()
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║              FALLBACK BLOCKED — TOKEN REQUIRED                 ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print()
        print("Local LLM fallback requires ACTIVE-TESTING-APPROVAL token.")
        print()
        print("To provide token, use ONE of:")
        print("  1. Environment: ACTIVE_TESTING_APPROVAL=1 <command>")
        print("  2. File: touch .bra/approvals/ACTIVE-TESTING-APPROVAL")
        print("  3. ROE.md: Add 'ACTIVE-TESTING-APPROVAL: GRANTED'")
        print()
        raise OllamaGovernanceError(reason, 1)


def _request_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 20) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method="POST" if payload is not None else "GET")
    with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8", errors="replace")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Unexpected JSON payload")
    return parsed


def ollama_list_models(host: str | None = None, *, timeout: int = 10, body_root: Path | None = None) -> list[str]:
    """Return available model names from Ollama server."""
    root = _detect_body_root() if body_root is None else body_root
    resolved_host, _ = _load_env_config(root)
    endpoint = (host or resolved_host).rstrip("/") + "/api/tags"

    payload = _request_json(endpoint, timeout=timeout)
    models = payload.get("models", [])
    if not isinstance(models, list):
        return []

    names: list[str] = []
    for entry in models:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            names.append(entry["name"])
            print(f"  - {entry['name']}")
    return names


def ollama_check(model: str | None = None, host: str | None = None, *, body_root: Path | None = None) -> bool:
    """Return ``True`` when Ollama is reachable and the model exists."""
    root = _detect_body_root() if body_root is None else body_root
    resolved_host, resolved_model = _load_env_config(root)
    target_host = host or resolved_host
    target_model = model or resolved_model

    print(f"Checking Ollama connectivity...")

    try:
        models = ollama_list_models(target_host, body_root=root)
    except (error.URLError, ValueError, json.JSONDecodeError):
        _log(root, "ERROR", f"Ollama not reachable at {target_host}")
        print(f"Ollama not reachable at {target_host}")
        print()
        print("To start Ollama:")
        print("  brew install ollama    # Install if needed")
        print("  ollama serve           # Start the service")
        return False

    print("Ollama service reachable")

    ok = target_model in models
    if ok:
        print(f"Model '{target_model}' available")
        _log(root, "INFO", f"Health check passed: model={target_model}")
    else:
        print(f"Model '{target_model}' not found")
        print()
        print("To pull the model:")
        print(f"  ollama pull {target_model}")
        print()
        print("Available models:")
        for m in models:
            print(f"  - {m}")
        _log(root, "WARN", f"Model unavailable: {target_model}")
    return ok


def ollama_generate(prompt: str, model: str | None = None, host: str | None = None, *, timeout: int = 120, body_root: Path | None = None) -> str:
    """Generate non-streaming response text from Ollama."""
    root = _detect_body_root() if body_root is None else body_root
    _ollama_governance_check("generate", root)
    if not prompt.strip():
        raise ValueError("prompt is required")

    resolved_host, resolved_model = _load_env_config(root)
    target_host = host or resolved_host
    target_model = model or resolved_model
    endpoint = target_host.rstrip("/") + "/api/generate"

    payload = {"model": target_model, "prompt": prompt, "stream": False}
    _log(root, "GENERATE", f"model={target_model} prompt_length={len(prompt)}")

    print(f"Generating with {target_model}...", file=sys.stderr)

    try:
        response_payload = _request_json(endpoint, payload=payload, timeout=timeout)
    except (error.URLError, ValueError, json.JSONDecodeError) as exc:
        _log(root, "ERROR", f"No response from Ollama")
        print("Error: No response from Ollama", file=sys.stderr)
        raise RuntimeError("No response from Ollama") from exc
    if isinstance(response_payload.get("error"), str) and response_payload["error"]:
        _log(root, "ERROR", f"Ollama error: {response_payload['error']}")
        print(f"Error: {response_payload['error']}", file=sys.stderr)
        raise RuntimeError(str(response_payload["error"]))

    text = response_payload.get("response", "")
    if not isinstance(text, str) or not text:
        _log(root, "ERROR", "Empty response from Ollama")
        print("Error: Empty response", file=sys.stderr)
        raise RuntimeError("Empty response from Ollama")

    _log(root, "SUCCESS", f"Generated {len(text)} characters")
    return text


def ollama_generate_with_context(task: str, *, model: str | None = None, host: str | None = None, body_root: Path | None = None) -> str:
    """Generate response using engagement scope and plan context."""
    root = _detect_body_root() if body_root is None else body_root
    _ollama_governance_check("generate_with_context", root)
    if not task.strip():
        raise ValueError("task description is required")
    sections: list[str] = ["You are assisting with an authorized security engagement.", ""]

    scope = root / "layer3-engagement" / "SCOPE.md"
    if scope.is_file():
        sections.append("## Engagement Scope")
        sections.append(scope.read_text(encoding="utf-8", errors="ignore")[:3000])
        sections.append("")

    plan = root / "layer3-engagement" / "PLAN.md"
    if plan.is_file():
        sections.append("## Current Methodology")
        sections.append(plan.read_text(encoding="utf-8", errors="ignore")[:2000])
        sections.append("")

    sections.extend(
        [
            "## Task",
            task,
            "",
            "## Requirements",
            "- Generate working code or payload that accomplishes the task",
            "- Follow security testing best practices",
            "- Include concise comments for non-obvious logic",
            "- Output should be immediately usable",
        ]
    )
    return ollama_generate("\n".join(sections), model=model, host=host, body_root=root)


def _show_help() -> None:
    print(
        "ollama.py -- Local LLM Fallback Library\n\n"
        "Usage:\n"
        "  ollama.py --check [model]    Check Ollama connectivity\n"
        "  ollama.py --list             List available models\n"
        "  ollama.py --generate 'prompt' Generate response\n\n"
        "Environment:\n"
        "  OLLAMA_HOST   Ollama endpoint (default: http://localhost:11434)\n"
        "  OLLAMA_MODEL  Model to use (default: codellama:13b)\n\n"
        "Governance:\n"
        "  Requires ACTIVE-TESTING-APPROVAL token\n"
        "  Blocked by kill switch\n"
        "  All invocations logged to .bra/logs/fallback.log"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    try:
        if args[0] == "--check":
            model = args[1] if len(args) >= 2 else None
            return 0 if ollama_check(model=model) else 1

        if args[0] == "--list":
            ollama_list_models()
            return 0

        if args[0] == "--generate":
            prompt = " ".join(args[1:]).strip()
            if not prompt:
                print("Missing prompt", file=sys.stderr)
                return 2
            print(ollama_generate(prompt))
            return 0
    except OllamaGovernanceError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Unknown option: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
