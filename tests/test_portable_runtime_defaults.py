from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "head"))

from bra.core.finding_enforcer import FindingEnforcer


def _gui_module():
    spec = importlib.util.spec_from_file_location("bra_portable_gui", REPO_ROOT / "boots" / "gui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gui_defaults_to_loopback_and_accepts_configured_host():
    gui = _gui_module()
    with patch.dict(os.environ, {}, clear=True):
        assert gui._parse_args([]).host == "127.0.0.1"
    with patch.dict(os.environ, {"BRA_GUI_HOST": "192.0.2.20"}):
        assert gui._parse_args([]).host == "192.0.2.20"
        assert gui._parse_args(["--host", "127.0.0.2"]).host == "127.0.0.2"


def test_poc_requires_an_explicit_target_before_calling_curl(tmp_path):
    notes = tmp_path / "NOTES"
    notes.mkdir()
    state = tmp_path / ".bra"
    state.mkdir()
    enforcer = FindingEnforcer(notes, state)
    script = enforcer._build_poc_script("demo", "Demo", "source /cgi-bin/demo", "")
    curl = tmp_path / "curl"
    record = tmp_path / "curl-argument"
    curl.write_text('#!/bin/sh\nprintf "%s\\n" "$2" > "$CURL_RECORD"\n')
    curl.chmod(0o700)
    env = {"PATH": str(tmp_path), "CURL_RECORD": str(record)}
    refused = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True, text=True)
    assert refused.returncode != 0
    assert "Set TARGET_HOST" in refused.stderr
    assert not record.exists()
    allowed = subprocess.run(
        ["/bin/bash", "-c", script], env={**env, "TARGET_HOST": "192.0.2.21:8080"},
        capture_output=True, text=True,
    )
    assert allowed.returncode == 0
    assert record.read_text().strip() == "http://192.0.2.21:8080/cgi-bin/demo"
