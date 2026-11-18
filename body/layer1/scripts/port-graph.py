#!/usr/bin/env python3
"""Build a code-truth dependency graph for layer1 Python ports."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCRIPT_REF_RE = re.compile(r"([A-Za-z0-9_./-]+\.(?:py|sh))")
RUN_SCRIPT_RE = re.compile(r"run_script\(\s*['\"]([A-Za-z0-9_.-]+\.sh)['\"]")


def _project_root() -> Path:
    # body/layer1/scripts/port-graph.py -> project root
    return Path(__file__).resolve().parents[3]


def _norm_script_name(raw: str) -> str:
    return Path(raw).name


def _iter_layer1_python_files(body_layer1: Path) -> list[Path]:
    return sorted(body_layer1.rglob("*.py"))


def _iter_python_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for rel in ("head", "boots", "body/layer1"):
        base = project_root / rel
        if not base.exists():
            continue
        out.extend(sorted(base.rglob("*.py")))
    return out


def build_graph(project_root: Path) -> dict[str, Any]:
    layer1_root = project_root / "body" / "layer1"
    scripts = _iter_layer1_python_files(layer1_root)
    pythons = _iter_python_files(project_root)

    script_nodes = [str(p.relative_to(project_root)) for p in scripts]
    python_nodes = [str(p.relative_to(project_root)) for p in pythons]

    script_edges: list[dict[str, str]] = []
    for script in scripts:
        rel = str(script.relative_to(project_root))
        text = script.read_text(errors="ignore")
        for match in SCRIPT_REF_RE.findall(text):
            target = _norm_script_name(match)
            if target.endswith((".py", ".sh")):
                script_edges.append({"from": rel, "to": target, "kind": "script_ref"})

    python_edges: list[dict[str, str]] = []
    for py in pythons:
        rel = str(py.relative_to(project_root))
        text = py.read_text(errors="ignore")
        for script_name in RUN_SCRIPT_RE.findall(text):
            python_edges.append({"from": rel, "to": _norm_script_name(script_name), "kind": "run_script"})

    python_ports = sorted(
        str(p.relative_to(project_root))
        for p in (project_root / "body" / "layer1" / "scripts").glob("*.py")
        if p.name != "__init__.py"
    )

    return {
        "project_root": str(project_root),
        "summary": {
            "layer1_python_files": len(script_nodes),
            "python_files": len(python_nodes),
            "script_edges": len(script_edges),
            "python_edges": len(python_edges),
            "python_ports": len(python_ports),
        },
        "nodes": {
            "layer1_python": script_nodes,
            "python": python_nodes,
            "python_ports": python_ports,
        },
        "edges": {
            "script": script_edges,
            "python": python_edges,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate layer1 dependency graph (code-truth).")
    parser.add_argument("--project-root", type=Path, default=_project_root())
    parser.add_argument("--output", type=Path, help="Write JSON graph to this path")
    args = parser.parse_args(argv)

    graph = build_graph(args.project_root.resolve())

    payload = json.dumps(graph, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
