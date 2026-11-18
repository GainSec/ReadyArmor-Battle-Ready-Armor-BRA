from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class EngageAnonUiTests(unittest.TestCase):
    def test_wizard_contains_privacy_posture_and_anon_review_flow(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("engageWizardPhase === 'privacy_posture'", page)
        self.assertIn("Select your privacy posture before scope intake.", page)
        self.assertIn("engageWizardPhase === 'anon_review'", page)
        self.assertIn("engageAnonConfirm()", page)
        self.assertIn("engageAnonScopeToken:", page)
        self.assertIn("engageAnonChatToken:", page)
        self.assertIn("/api/anon/config", page)
        self.assertIn("/api/anon/detect", page)
        self.assertIn("/api/anon/apply", page)

    def test_loadout_contains_anon_management_panel(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("<h3 class=\"font-medium\">Anonymization</h3>", page)
        self.assertIn("fetch('/api/anon/mappings'", page)
        self.assertIn("anonCreated", page)
        self.assertIn("anonCountsByType", page)
        self.assertIn("Map Created", page)
        self.assertIn("No anonymization mappings yet. They will be created during scope intake.", page)
        self.assertIn("Add Manual Mapping", page)
        self.assertIn("body: JSON.stringify({real: anonNewReal.trim(), type: anonNewType})", page)

    def test_settings_contains_anonymization_endpoint_controls(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("Anonymization Endpoints", page)
        self.assertIn("NER Model Endpoint", page)
        self.assertIn("Local Model Endpoint", page)
        self.assertIn("nerEndpointInput: ''", page)
        self.assertIn("localModelEndpointInput: ''", page)
        self.assertIn("anonymization: false", page)
        self.assertIn("this.nerEndpointInput = this.config.ner_endpoint || '';", page)
        self.assertIn("this.localModelEndpointInput = this.config.local_model_endpoint || '';", page)
        self.assertIn("ner_endpoint: (this.nerEndpointInput || '').trim()", page)
        self.assertIn("local_model_endpoint: (this.localModelEndpointInput || '').trim()", page)

    def test_wizard_submit_has_distinct_scope_token_branches(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("syncEngagePrivacyTokens()", page)
        self.assertIn("this.syncEngagePrivacyTokens();", page)
        self.assertIn("if (this.engageAnonScopeToken === 'NO-SCOPE')", page)
        self.assertIn("if (this.engageAnonScopeToken === 'DUMB-SCOPE')", page)
        self.assertIn("if (this.engageAnonScopeToken === 'MICRO-SCOPE')", page)
        self.assertIn("if (this.engageAnonScopeToken === 'LOCAL-SCOPE')", page)
        self.assertIn("if (this.engageAnonScopeToken === 'FRONTIER-SCOPE')", page)
        self.assertIn("mode: 'regex-only'", page)
        self.assertIn("mode: 'regex-plus-local'", page)
        self.assertIn("Local Mask is not available yet", page)
        self.assertIn("requires boots to be started with --ner", page)
        self.assertIn("this.engageTokens[token] = (token === this.engageAnonScopeToken);", page)
        self.assertIn("this.engageTokens[token] = (token === this.engageAnonChatToken);", page)

    def test_scope_intake_can_activate_no_token_tracking(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")
        engage = (REPO_ROOT / "boots" / "engage.py").read_text(encoding="utf-8")

        self.assertIn("['NO-TOKEN-TRACKING', 'Disable Token Tracking'", page)
        self.assertIn("'NO-TOKEN-TRACKING': false", page)
        self.assertIn('"NO-TOKEN-TRACKING"', engage)

    def test_config_contains_disabled_local_mask_section(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("Local Mask", page)
        self.assertIn("Local Mask API URL", page)
        self.assertIn("Local Mask API Key", page)
        self.assertIn("LOCAL-SCOPE / LOCAL-SCAN support", page)
        self.assertIn("x-model=\"localMaskApiUrlInput\"", page)
        self.assertIn("x-model=\"localMaskApiKeyInput\"", page)
        self.assertIn("disabled", page)

    def test_page_contains_anon_highlight_rendering(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("highlightAnon(text, highlights)", page)
        self.assertIn("renderAnonInline(text, highlights)", page)
        self.assertIn("renderEngageMarkdownHighlighted(text, highlights)", page)
        self.assertIn("renderMarkdownHighlighted(md, highlights)", page)
        self.assertIn("report.anon_highlights || []", page)
        self.assertIn("intel.anon_highlights || []", page)
        self.assertIn("leads.anon_highlights || []", page)
        self.assertIn("findings.anon_highlights || []", page)

    def test_page_contains_anon_scan_approval_card_flow(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("approval_anon_map", page)
        self.assertIn("approve_anon_map", page)
        self.assertIn("Mask for Engagement", page)
        self.assertIn("proposal_value", page)

    def test_dashboard_governance_and_roe_show_anon_token_state(self) -> None:
        page = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("Tokens 41", page)
        self.assertIn("Scope Privacy", page)
        self.assertIn("Chat Privacy", page)
        self.assertIn("governance.tokens['FRONTIER-SCOPE']", page)
        self.assertIn("governance.tokens['MAP-SCAN']", page)


if __name__ == "__main__":
    unittest.main()
