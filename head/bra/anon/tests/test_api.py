"""Tests for the top-level anon API."""
import pytest
from pathlib import Path
from bra.anon.api import AnonAPI


@pytest.fixture
def anon(tmp_path):
    map_path = tmp_path / ".bra" / "anon_map.json"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    return AnonAPI(map_path=map_path)


def test_detect_finds_ips(anon):
    proposals = anon.detect("Target at 192.168.18.9 with key abc123def456ghij")
    values = [p.value for p in proposals]
    assert "192.168.18.9" in values


def test_detect_and_add_then_mask(anon):
    proposals = anon.detect("Target at 10.0.0.1")
    anon.add_mappings(proposals, source="test")
    masked = anon.mask("Connect to 10.0.0.1 on port 80")
    assert "10.0.0.1" not in masked


def test_unmask_reverses_mask(anon):
    proposals = anon.detect("Target at 10.0.0.1")
    anon.add_mappings(proposals, source="test")
    original = "Connect to 10.0.0.1 on port 80"
    masked = anon.mask(original)
    unmasked = anon.unmask(masked)
    assert unmasked == original


def test_save_persists(anon, tmp_path):
    proposals = anon.detect("Target 10.0.0.1")
    anon.add_mappings(proposals, source="test")
    anon.save()

    map_path = tmp_path / ".bra" / "anon_map.json"
    anon2 = AnonAPI(map_path=map_path)
    result = anon2.mask("Target 10.0.0.1")
    assert "10.0.0.1" not in result


def test_mask_noop_when_no_mappings(anon):
    text = "Nothing sensitive here"
    assert anon.mask(text) == text


def test_add_manual_mapping(anon):
    anon.add_manual("MySecretCorp", type_="operator-flagged")
    masked = anon.mask("Report for MySecretCorp")
    assert "MySecretCorp" not in masked
