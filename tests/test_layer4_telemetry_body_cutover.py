from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str) -> types.ModuleType:
    path = REPO_ROOT / relative_path
    head_root = str(REPO_ROOT / "head")
    if head_root not in sys.path:
        sys.path.insert(0, head_root)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Layer4TelemetryBodyCutoverTests(unittest.TestCase):
    def test_manager_portfolio_uses_body_only(self) -> None:
        module = _load_module("main_layer4_cutover", "boots/main.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            body_root = project_root / "body"
            root_layer4 = project_root / "layer4-telemetry"
            body_layer4 = body_root / "layer4-telemetry"
            root_layer4.mkdir(parents=True)
            body_layer4.mkdir(parents=True)

            root_payload = {
                "schema_version": 1,
                "engagements": [{"id": "root-only", "name": "ROOT"}],
                "live_fallbacks": {"current_bra": {"risk_level": "LOW"}},
            }
            body_payload = {
                "schema_version": 1,
                "engagements": [{"id": "body-only", "name": "BODY"}],
                "live_fallbacks": {"current_bra": {"risk_level": "HIGH"}},
            }
            (root_layer4 / "manager_portfolio.json").write_text(json.dumps(root_payload), encoding="utf-8")
            (body_layer4 / "manager_portfolio.json").write_text(json.dumps(body_payload), encoding="utf-8")

            with mock.patch.object(module, "get_bra_dir", return_value=str(project_root)):
                result = asyncio_run(module.get_manager_portfolio(True))
            self.assertEqual(result["engagements"][0]["id"], "body-only")

            (body_layer4 / "manager_portfolio.json").unlink()
            with mock.patch.object(module, "get_bra_dir", return_value=str(project_root)):
                result = asyncio_run(module.get_manager_portfolio(True))
            self.assertEqual(result, module._default_manager_portfolio_payload())

    def test_telemetry_stats_path_is_body_only(self) -> None:
        module = _load_module("telemetry_layer4_cutover", "boots/telemetry.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir) / "body"
            body_root.mkdir(parents=True)
            stats_path = body_root / "layer4-telemetry" / "stats.json"

            live = {
                "findings": {"total": 0, "by_severity": {}},
                "leads": {"total": 0, "by_status": {}},
                "artifacts": {"total": 0},
                "overrides": {"total": 0, "tools_used": []},
                "tokens": {"granted": [], "total_granted": 0},
                "tools": {"total": 0},
                "skills": {"total": 0},
                "methodologies": {"total": 0},
                "workflows": {"total": 0},
                "engagement": {"started_at": None},
                "service_health": {"targets_total": 0, "targets_responding": 0},
            }

            module.update_cumulative_stats(body_root, live)
            self.assertTrue(stats_path.is_file())
            self.assertFalse((body_root.parent / "layer4-telemetry" / "stats.json").exists())


def asyncio_run(awaitable):
    import asyncio

    return asyncio.run(awaitable)


if __name__ == "__main__":
    unittest.main()
