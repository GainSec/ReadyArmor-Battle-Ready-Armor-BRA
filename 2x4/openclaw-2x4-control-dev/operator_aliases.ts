const ACTION_ALIASES: Record<string, string> = {
  "bra summary": "summary",
  "bra explain": "explain",
  "bra file": "file",
  "bra log": "log",
  "bra engage status": "engage_status",
  "bra engage action": "engage_action",
  "bra call continue": "call_continue",
  "bra call speak": "call_speak",
  "bra call status": "call_status",
  "bra call stop": "call_stop",
  "bra takeover confirm": "takeover_confirm",
  "bra stand down": "stand_down",
  "operator.read": "summary",
  "operator.admin": "summary",
  "operator.pairing": "summary",
  "operator.write": "engage_action",
  "operator.approvals": "engage_status",
};

export const normalizeControlAction = (value: unknown): string => {
  const raw = String(value || "").trim().toLowerCase();
  const normalized = raw.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
  return ACTION_ALIASES[normalized] || normalized;
};

export const parseBraShortcutArgs = (args: Record<string, unknown>): Record<string, unknown> => {
  const commandRaw = String(args.command || "").trim().toLowerCase();
  const command = commandRaw.replace(/^\/?bra\b/, "").trim();
  const text = command || commandRaw;
  const tokens = text.split(/\s+/).filter(Boolean);

  if (tokens.length === 0) {
    return { ...args, action: "summary" };
  }

  if (tokens[0] === "summary") {
    return { ...args, action: "summary" };
  }
  if (tokens[0] === "explain") {
    const parsedTail = /^\d+$/.test(tokens[1] || "") ? Number(tokens[1]) : undefined;
    return { ...args, action: "explain", tail: typeof args.tail === "number" ? args.tail : parsedTail };
  }
  if (tokens[0] === "file") {
    const fileId =
      typeof args.fileId === "string" && args.fileId.trim() ? args.fileId : String(tokens[1] || "");
    return { ...args, action: "file", fileId };
  }
  if (tokens[0] === "log") {
    const existingLogId = typeof args.logId === "string" && args.logId.trim() ? args.logId : "";
    const token1 = tokens[1] || "";
    const token2 = tokens[2] || "";
    const parsedTailFromToken1 = /^\d+$/.test(token1) ? Number(token1) : undefined;
    const parsedTailFromToken2 = /^\d+$/.test(token2) ? Number(token2) : undefined;
    const logId = existingLogId || (token1 && !parsedTailFromToken1 ? token1 : "engage");
    const tail =
      typeof args.tail === "number"
        ? args.tail
        : parsedTailFromToken2 ?? parsedTailFromToken1 ?? undefined;
    return { ...args, action: "log", logId, tail };
  }
  if (
    tokens[0] === "call" &&
    (tokens[1] === "continue" || tokens[1] === "speak" || tokens[1] === "status" || tokens[1] === "stop")
  ) {
    const existingCallId =
      typeof args.callId === "string" && args.callId.trim()
        ? args.callId
        : typeof args.call_id === "string" && args.call_id.trim()
          ? args.call_id
          : "";
    const callId = existingCallId || String(tokens[2] || "");
    if (tokens[1] === "continue" || tokens[1] === "speak") {
      const existingMessage = typeof args.message === "string" && args.message.trim() ? args.message : "";
      const message = existingMessage || tokens.slice(3).join(" ");
      return {
        ...args,
        action: tokens[1] === "continue" ? "call_continue" : "call_speak",
        callId,
        message,
      };
    }
    if (tokens[1] === "status") {
      return { ...args, action: "call_status", callId };
    }
    return { ...args, action: "call_stop", callId };
  }
  if (tokens[0] === "engage" && tokens[1] === "status") {
    return { ...args, action: "engage_status" };
  }
  if (tokens[0] === "engage" && tokens[1] === "action") {
    return { ...args, action: "engage_action" };
  }
  if (tokens[0] === "takeover" && tokens[1] === "confirm") {
    return { ...args, action: "takeover_confirm" };
  }
  if (tokens[0] === "stand" && tokens[1] === "down") {
    return { ...args, action: "stand_down" };
  }

  return { ...args, action: text };
};

export const resolveOperatorAliasArgs = (
  toolName: string,
  args: Record<string, unknown>,
): Record<string, unknown> => {
  const alias = String(toolName || "").trim().toLowerCase();
  const command = String(args.command || "").trim();
  if (command) {
    const parsed = parseBraShortcutArgs(args);
    return { ...parsed, action: normalizeControlAction(parsed.action) };
  }

  const action = String(args.action || "").trim();
  if (action) {
    return { ...args, action: normalizeControlAction(action) };
  }

  return { ...args, action: normalizeControlAction(alias || "summary") };
};
