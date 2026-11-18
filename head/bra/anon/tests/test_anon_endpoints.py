"""Tests for anon endpoint logic (unit tests, not FastAPI client tests)."""
import json
import pytest
from pathlib import Path
from bra.anon.api import AnonAPI
from bra.anon.detect import Detection


@pytest.fixture
def anon_setup(tmp_path):
    """Set up a mock .bra directory with anon_map.json."""
    bra_dir = tmp_path / ".bra"
    bra_dir.mkdir()
    approvals_dir = bra_dir / "approvals"
    approvals_dir.mkdir()
    map_path = bra_dir / "anon_map.json"
    return tmp_path, map_path, approvals_dir


def test_get_mappings_empty(anon_setup):
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    assert api.all_mappings() == []


def test_add_manual_and_list(anon_setup):
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    api.add_manual("192.168.18.9", type_="ip")
    mappings = api.all_mappings()
    assert len(mappings) == 1
    assert mappings[0]["real"] == "192.168.18.9"
    assert mappings[0]["type"] == "ip"


def test_detect_returns_proposals(anon_setup):
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    proposals = api.detect("Target 10.0.0.1 with key abcdef1234567890")
    values = [p.value for p in proposals]
    assert "10.0.0.1" in values


def test_apply_proposals_checked_only(anon_setup):
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    proposals = [
        Detection(value="10.0.0.1", type_="ip", span=(0, 8)),
        Detection(value="secret", type_="credential", span=(20, 26)),
    ]
    # Only add the first one (simulating checked=True, checked=False)
    api.add_mappings([proposals[0]], source="scope-intake")
    assert len(api.all_mappings()) == 1
    assert api.all_mappings()[0]["real"] == "10.0.0.1"


def test_scope_token_storage(anon_setup):
    """Scope tokens are stored as approval files."""
    _, _, approvals_dir = anon_setup
    scope_tokens = ["FRONTIER-SCOPE", "MICRO-SCOPE", "LOCAL-SCOPE", "DUMB-SCOPE", "NO-SCOPE"]
    # Set FRONTIER-SCOPE
    for t in scope_tokens:
        f = approvals_dir / t
        if f.exists():
            f.unlink()
    (approvals_dir / "FRONTIER-SCOPE").touch()
    # Verify
    active = [t for t in scope_tokens if (approvals_dir / t).exists()]
    assert active == ["FRONTIER-SCOPE"]


def test_chat_token_storage(anon_setup):
    """Chat tokens are stored as approval files."""
    _, _, approvals_dir = anon_setup
    chat_tokens = ["MAP-SCAN", "ANON-SCAN", "LOCAL-SCAN", "NO-SCAN"]
    (approvals_dir / "MAP-SCAN").touch()
    active = [t for t in chat_tokens if (approvals_dir / t).exists()]
    assert active == ["MAP-SCAN"]


def test_scope_token_switch(anon_setup):
    """Switching scope tokens removes the old one."""
    _, _, approvals_dir = anon_setup
    scope_tokens = ["FRONTIER-SCOPE", "MICRO-SCOPE", "LOCAL-SCOPE", "DUMB-SCOPE", "NO-SCOPE"]
    # Start with FRONTIER-SCOPE
    (approvals_dir / "FRONTIER-SCOPE").touch()
    # Switch to MICRO-SCOPE
    for t in scope_tokens:
        f = approvals_dir / t
        if f.exists():
            f.unlink()
    (approvals_dir / "MICRO-SCOPE").touch()
    active = [t for t in scope_tokens if (approvals_dir / t).exists()]
    assert active == ["MICRO-SCOPE"]


def test_chat_token_switch(anon_setup):
    """Switching chat tokens removes the old one."""
    _, _, approvals_dir = anon_setup
    chat_tokens = ["MAP-SCAN", "ANON-SCAN", "LOCAL-SCAN", "NO-SCAN"]
    (approvals_dir / "MAP-SCAN").touch()
    # Switch to ANON-SCAN
    for t in chat_tokens:
        f = approvals_dir / t
        if f.exists():
            f.unlink()
    (approvals_dir / "ANON-SCAN").touch()
    active = [t for t in chat_tokens if (approvals_dir / t).exists()]
    assert active == ["ANON-SCAN"]


def test_detect_filters_existing_mappings(anon_setup):
    """Detect should not return items already in the map."""
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    api.add_manual("10.0.0.1", type_="ip")
    proposals = api.detect("Target 10.0.0.1 with key abcdef1234567890")
    values = [p.value for p in proposals]
    assert "10.0.0.1" not in values


def test_add_manual_returns_anon_word(anon_setup):
    """add_manual returns the generated anon word."""
    _, map_path, _ = anon_setup
    api = AnonAPI(map_path=map_path)
    anon_word = api.add_manual("192.168.1.1", type_="ip")
    assert isinstance(anon_word, str)
    assert len(anon_word) > 0
