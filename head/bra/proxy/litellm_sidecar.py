"""Manage a LiteLLM proxy as a subprocess sidecar."""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SidecarResult:
    ok: bool
    error: str = ""
    port: int = 0


@dataclass
class ProxySidecar:
    """Manages a LiteLLM proxy subprocess."""

    port: int = 4000
    config_dir: str = ""
    _process: Optional[subprocess.Popen] = field(default=None, init=False, repr=False)
    _clamp_process: Optional[subprocess.Popen] = field(default=None, init=False, repr=False)
    _log_file: Optional[Path] = field(default=None, init=False, repr=False)

    @property
    def upstream_port(self) -> int:
        return self.port + 1000

    @property
    def config_path(self) -> Path:
        base = Path(self.config_dir) if self.config_dir else Path.home() / ".bra"
        return base / "litellm_config.yaml"

    @property
    def log_path(self) -> Path:
        base = Path(self.config_dir) if self.config_dir else Path.home() / ".bra"
        return base / "logs" / "litellm.log"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def start(self, config_yaml: str, max_completion_tokens: int = 8192) -> SidecarResult:
        """Write config and launch LiteLLM proxy subprocess."""
        if self.is_running:
            return SidecarResult(ok=True, port=self.port)

        litellm_bin = shutil.which("litellm")
        if not litellm_bin:
            return SidecarResult(ok=False, error="LiteLLM is not installed. Run: pip install litellm")

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(config_yaml, encoding="utf-8")

        # Kill any stale process on our ports before starting
        self._clear_port()
        self._clear_port(self.upstream_port)

        # Write logs to body/.bra/logs/litellm.log so they show up in logviewer
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(self.log_path, "a", encoding="utf-8")
        self._log_file = self.log_path

        debug_mode = os.environ.get("BRA_PROXY_DEBUG") or os.environ.get("BRA_VERBOSE")

        try:
            self._process = subprocess.Popen(
                [
                    litellm_bin,
                    "--config", str(self.config_path),
                    "--port", str(self.upstream_port),
                    "--host", "127.0.0.1",
                    *(["--detailed_debug"] if debug_mode else []),
                ],
                stdout=log_fh,
                stderr=log_fh,
                env={
                    **os.environ,
                    "LITELLM_LOG": "DEBUG" if debug_mode else "ERROR",
                    "LITELLM_USE_CHAT_COMPLETIONS_URL_FOR_ANTHROPIC_MESSAGES": "true",
                },
            )
            self._clamp_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "bra.proxy.clamp_proxy",
                    "--listen-port",
                    str(self.port),
                    "--upstream-base-url",
                    f"http://127.0.0.1:{self.upstream_port}",
                    "--max-completion-tokens",
                    str(max_completion_tokens),
                ],
                stdout=log_fh,
                stderr=log_fh,
                env={**os.environ},
            )
        except Exception as exc:
            self.stop()
            log_fh.close()
            return SidecarResult(ok=False, error=f"Failed to start LiteLLM: {exc}")

        for _ in range(20):
            if self._process is None:
                try:
                    err_tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-500:]
                except Exception:
                    err_tail = "(no log output)"
                return SidecarResult(ok=False, error=f"LiteLLM failed to initialize: {err_tail}")
            if self._process.poll() is not None or (
                self._clamp_process is not None and self._clamp_process.poll() is not None
            ):
                # Read last lines from log file for error context
                try:
                    err_tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-500:]
                except Exception:
                    err_tail = "(no log output)"
                return SidecarResult(ok=False, error=f"LiteLLM exited early: {err_tail}")
            if await self._health_check():
                return SidecarResult(ok=True, port=self.port)
            await asyncio.sleep(0.5)

        self.stop()
        return SidecarResult(ok=False, error="LiteLLM proxy did not become healthy within 10s")

    def _clear_port(self, port: int | None = None) -> None:
        """Kill any stale process listening on our port."""
        target_port = self.port if port is None else port
        try:
            result = subprocess.run(
                ["lsof", "-ti", f":{target_port}"],
                capture_output=True, text=True, timeout=5,
            )
            for pid_str in result.stdout.strip().split():
                pid = int(pid_str)
                if pid != os.getpid():
                    os.kill(pid, signal.SIGTERM)
        except Exception:
            pass

    async def _health_check(self) -> bool:
        """Check if proxy is responding via httpx."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                return resp.status_code == 200
        except Exception:
            return False

    def stop(self) -> None:
        """Terminate the proxy subprocess if running."""
        if self._clamp_process is not None and self._clamp_process.poll() is None:
            self._clamp_process.send_signal(signal.SIGTERM)
            try:
                self._clamp_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._clamp_process.kill()
        self._clamp_process = None
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None
