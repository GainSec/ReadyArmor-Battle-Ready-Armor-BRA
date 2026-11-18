# head/bra/anon/tests/test_integration.py
"""Integration test for the full anonymization flow."""
import json
import pytest
from pathlib import Path
from bra.anon.api import AnonAPI
from bra.anon.rehydrate import rehydrate_file

SYNTHETIC_HEX_VALUE = "a1" * 16


@pytest.fixture
def body_root(tmp_path):
    bra = tmp_path / ".bra"
    bra.mkdir()
    (tmp_path / "layer3-engagement" / "NOTES").mkdir(parents=True)
    return tmp_path


def test_full_anonymization_flow(body_root):
    map_path = body_root / ".bra" / "anon_map.json"
    api = AnonAPI(map_path=map_path)
    api.set_engagement("test-engagement")

    # 1. Scope intake: operator enters raw text
    # Note: IPs must not be followed by '.' (sentence punctuation) because
    # the detector's negative lookahead rejects dots to avoid version-string
    # false positives.  Use comma/newline/space instead.
    raw_scope = (
        "Target: Android Auto Dongle, IP: 192.168.18.9, "
        "Hotspot password: 12345678, "
        "Backend at 198.51.100.57:8080, "
        f"API key: {SYNTHETIC_HEX_VALUE}"
    )

    # 2. Detection
    proposals = api.detect(raw_scope)
    values = [p.value for p in proposals]
    assert "192.168.18.9" in values
    assert "198.51.100.57" in values
    assert SYNTHETIC_HEX_VALUE in values

    # 3. Operator approves all
    api.add_mappings(proposals, source="scope-intake")
    api.save()

    # 4. Mask scope text
    masked_scope = api.mask(raw_scope)
    assert "192.168.18.9" not in masked_scope
    assert "198.51.100.57" not in masked_scope
    assert SYNTHETIC_HEX_VALUE not in masked_scope

    # 5. Write anonymized SCOPE.md
    scope_path = body_root / "layer3-engagement" / "SCOPE.md"
    scope_path.write_text(f"# Scope\n\n{masked_scope}\n")

    # 6. Simulate chat masking (MAP-SCAN)
    chat_input = "Run nmap on 192.168.18.9"
    masked_chat = api.mask(chat_input)
    assert "192.168.18.9" not in masked_chat

    # 7. Simulate LLM response unmasking
    # LLM responds with anon word
    ip_mapping = next(m for m in api.all_mappings() if m["real"] == "192.168.18.9")
    llm_response = f"Scan results for {ip_mapping['anon']} show port 80 open"
    unmasked_response = api.unmask(llm_response)
    assert "192.168.18.9" in unmasked_response

    # 8. Report re-hydration
    report_path = body_root / "layer3-engagement" / "REPORT.md"
    report_path.write_text(f"# Report\n\n{masked_scope}\n")
    output_path = body_root / "REPORT-FINAL.md"
    rehydrate_file(report_path, map_path, output_path)
    final = output_path.read_text()
    assert "192.168.18.9" in final
    assert "198.51.100.57" in final
