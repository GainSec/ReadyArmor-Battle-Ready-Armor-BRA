"""Tests for report re-hydration script."""
import json
import pytest
from pathlib import Path
from bra.anon.api import AnonAPI
from bra.anon.rehydrate import rehydrate_file


def test_rehydrate_report(tmp_path):
    # Set up mapping
    map_path = tmp_path / ".bra" / "anon_map.json"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    api = AnonAPI(map_path=map_path)
    api.add_manual("192.168.18.9", type_="ip")
    api.save()

    # Get the anon word
    mapping = api.all_mappings()[0]
    anon_word = mapping["anon"]

    # Create a fake report with anonymized content
    report = tmp_path / "REPORT.md"
    report.write_text(f"# Report\n\nTarget at {anon_word} was vulnerable.\n")

    # Re-hydrate
    output = tmp_path / "REPORT-FINAL.md"
    rehydrate_file(report, map_path, output)

    result = output.read_text()
    assert "192.168.18.9" in result
    assert anon_word not in result


def test_rehydrate_preserves_non_anon_text(tmp_path):
    map_path = tmp_path / ".bra" / "anon_map.json"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    api = AnonAPI(map_path=map_path)
    api.add_manual("10.0.0.1", type_="ip")
    api.save()

    report = tmp_path / "REPORT.md"
    report.write_text("# Report\n\nNo anonymized content here.\n")

    output = tmp_path / "REPORT-FINAL.md"
    rehydrate_file(report, map_path, output)

    result = output.read_text()
    assert result == "# Report\n\nNo anonymized content here.\n"


def test_rehydrate_multiple_mappings(tmp_path):
    map_path = tmp_path / ".bra" / "anon_map.json"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    api = AnonAPI(map_path=map_path)
    api.add_manual("192.168.18.9", type_="ip")
    api.add_manual("AA:BB:CC:DD:EE:FF", type_="mac")
    api.save()

    m1 = api.all_mappings()[0]
    m2 = api.all_mappings()[1]

    report = tmp_path / "REPORT.md"
    report.write_text(f"IP: {m1['anon']}, MAC: {m2['anon']}\n")

    output = tmp_path / "REPORT-FINAL.md"
    rehydrate_file(report, map_path, output)

    result = output.read_text()
    assert "192.168.18.9" in result
    assert "AA:BB:CC:DD:EE:FF" in result
    assert m1["anon"] not in result
    assert m2["anon"] not in result
