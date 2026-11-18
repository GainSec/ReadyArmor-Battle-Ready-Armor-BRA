"""BaseHarness registry — dataclasses and auto-discovery for harness modules."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ParamSpec:
    name: str
    type: str  # "text" | "textarea" | "select" | "checkbox"
    required: bool
    default: str | None
    help: str
    options: list[str] | None = None

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "help": self.help,
        }
        if self.options is not None:
            d["options"] = self.options
        return d


@dataclass
class HarnessResult:
    prompt: str
    allowed_tools: list[str]
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "prompt": self.prompt,
            "allowed_tools": self.allowed_tools,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class BaseHarness:
    name: str = ""
    label: str = ""
    description: str = ""
    executable: bool = True

    def parameters(self) -> list[ParamSpec]:
        return []

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        raise NotImplementedError

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        raise NotImplementedError
        yield  # pragma: no cover — makes this an async generator

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "executable": self.executable,
            "params": [p.to_dict() for p in self.parameters()],
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_SKIP_MODULES = {"base", "findings_flow"}
_cache: list[BaseHarness] | None = None


def get_registry() -> list[BaseHarness]:
    """Auto-discover harness modules that expose a module-level `harness` var."""
    global _cache
    if _cache is not None:
        return _cache

    import boots.harness as _pkg

    harnesses: list[BaseHarness] = []

    for info in pkgutil.iter_modules(_pkg.__path__, prefix=_pkg.__name__ + "."):
        mod_short = info.name.rsplit(".", 1)[-1]
        if mod_short.startswith("_") or mod_short in _SKIP_MODULES:
            continue
        try:
            mod = importlib.import_module(info.name)
        except Exception:
            log.warning("harness: failed to import %s", info.name, exc_info=True)
            continue

        obj = getattr(mod, "harness", None)
        if isinstance(obj, BaseHarness):
            harnesses.append(obj)

    _cache = harnesses
    return _cache


def get_harness(name: str) -> BaseHarness | None:
    """Look up a registered harness by name."""
    for h in get_registry():
        if h.name == name:
            return h
    return None
