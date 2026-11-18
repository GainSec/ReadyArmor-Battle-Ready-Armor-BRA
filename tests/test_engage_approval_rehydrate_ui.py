from __future__ import annotations

import re
import unittest
from pathlib import Path


class EngageApprovalRehydrateUiTests(unittest.TestCase):
    def test_state_handler_does_not_render_pending_approval_into_empty_timeline(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"case 'state':(?P<body>.*?)break;",
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "Could not locate engage state handler")
        state_body = match.group("body")

        self.assertIn("this.engageMessages = []", state_body)
        self.assertIn("const awaitingReplay = this._engageExpectingReplayState", state_body)
        self.assertIn("this.engageAwaitingReplay = awaitingReplay", state_body)
        self.assertIn("this.engagePendingApproval = this.normalizeApprovalEvent(msg.pending_approval)", state_body)
        self.assertIn("if (!awaitingReplay) {", state_body)
        self.assertIn("this.ensurePendingApprovalVisible(this.engagePendingApproval)", state_body)

    def test_live_approval_events_still_render_pending_approval_cards(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"case 'approval_token': case 'approval_scope_add':(?P<body>.*?)break;",
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "Could not locate approval event handler")
        approval_body = match.group("body")

        self.assertIn("this.engagePendingApproval = this.normalizeApprovalEvent(msg)", approval_body)
        self.assertIn("this.ensurePendingApprovalVisible(this.engagePendingApproval)", approval_body)

    def test_engage_websocket_replay_has_completion_signal(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "boots" / "main.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('await websocket.send_json({"type": "history_replayed"})', source)

    def test_approval_events_load_anon_mappings_for_hover_rehydration(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"case 'approval_token': case 'approval_scope_add':(?P<body>.*?)break;",
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "Could not locate approval event handler")
        approval_body = match.group("body")

        self.assertIn("this.ensureApprovalAnonMappings()", approval_body)
        self.assertIn("async ensureApprovalAnonMappings()", page)
        self.assertIn("this.api('/anon/mappings')", page)

    def test_tool_approval_masked_values_render_with_hover_rehydration(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("approvalAnonHighlights(msg)", page)
        self.assertIn("renderApprovalMaskedInline(approvalToolSummary(msg), approvalAnonHighlights(msg))", page)
        self.assertIn("renderApprovalMaskedInline(msg.command, approvalAnonHighlights(msg))", page)
        self.assertIn(
            "renderApprovalMaskedInline(formatApprovalToolInput(msg.tool_input), approvalAnonHighlights(msg))",
            page,
        )
        self.assertIn("title=\"' + title + '\"", page)

    def test_scope_add_approval_uses_add_to_scope_wording(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("ADD TO SCOPE", page)
        self.assertIn("'Add ' + (msg.target || 'target') + ' to scope'", page)
        self.assertIn("Add as Full", page)
        self.assertIn("Add as Limited", page)


if __name__ == "__main__":
    unittest.main()
