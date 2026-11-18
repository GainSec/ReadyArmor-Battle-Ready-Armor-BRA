import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeControlAction,
  parseBraShortcutArgs,
  resolveOperatorAliasArgs,
} from "./operator_aliases.ts";

test("normalizeControlAction maps stale operator tool names", () => {
  assert.equal(normalizeControlAction("operator.write"), "engage_action");
  assert.equal(normalizeControlAction("operator.read"), "summary");
  assert.equal(normalizeControlAction("operator.approvals"), "engage_status");
});

test("parseBraShortcutArgs keeps existing bra shortcuts working", () => {
  assert.deepEqual(parseBraShortcutArgs({ command: "bra log engage 200" }), {
    command: "bra log engage 200",
    action: "log",
    logId: "engage",
    tail: 200,
  });
});

test("resolveOperatorAliasArgs prefers command parsing when present", () => {
  assert.deepEqual(
    resolveOperatorAliasArgs("operator.write", { command: "bra file scope" }),
    {
      command: "bra file scope",
      action: "file",
      fileId: "scope",
    },
  );
});

test("resolveOperatorAliasArgs falls back to operator-specific default action", () => {
  assert.deepEqual(
    resolveOperatorAliasArgs("operator.write", { takeoverLeaseId: "lease-1", payload: { decision: "approve" } }),
    {
      takeoverLeaseId: "lease-1",
      payload: { decision: "approve" },
      action: "engage_action",
    },
  );
});
