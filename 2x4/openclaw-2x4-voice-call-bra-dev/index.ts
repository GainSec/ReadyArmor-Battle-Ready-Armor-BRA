import { Type } from "@sinclair/typebox";
import type { GatewayRequestHandlerOptions, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { registerVoiceCallCli } from "./src/cli.js";
import {
  VoiceCallConfigSchema,
  resolveVoiceCallConfig,
  validateProviderConfig,
  type VoiceCallConfig,
} from "./src/config.js";
import type { CoreConfig } from "./src/core-bridge.js";
import { createVoiceCallRuntime, type VoiceCallRuntime } from "./src/runtime.js";

const voiceCallConfigSchema = {
  parse(value: unknown): VoiceCallConfig {
    const raw =
      value && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};

    const twilio = raw.twilio as Record<string, unknown> | undefined;
    const legacyFrom = typeof twilio?.from === "string" ? twilio.from : undefined;

    const enabled = typeof raw.enabled === "boolean" ? raw.enabled : true;
    const providerRaw = raw.provider === "log" ? "mock" : raw.provider;
    const provider = providerRaw ?? (enabled ? "mock" : undefined);

    return VoiceCallConfigSchema.parse({
      ...raw,
      enabled,
      provider,
      fromNumber: raw.fromNumber ?? legacyFrom,
    });
  },
  uiHints: {
    provider: {
      label: "Provider",
      help: "Use twilio, telnyx, or mock for dev/no-network.",
    },
    fromNumber: { label: "From Number", placeholder: "+15550001234" },
    toNumber: { label: "Default To Number", placeholder: "+15550001234" },
    inboundPolicy: { label: "Inbound Policy" },
    allowFrom: { label: "Inbound Allowlist" },
    inboundGreeting: { label: "Inbound Greeting", advanced: true },
    "telnyx.apiKey": { label: "Telnyx API Key", sensitive: true },
    "telnyx.connectionId": { label: "Telnyx Connection ID" },
    "telnyx.publicKey": { label: "Telnyx Public Key", sensitive: true },
    "twilio.accountSid": { label: "Twilio Account SID" },
    "twilio.authToken": { label: "Twilio Auth Token", sensitive: true },
    "outbound.defaultMode": { label: "Default Call Mode" },
    autoRespondOutboundConversation: {
      label: "Auto-Respond Outbound Conversation Calls",
      advanced: true,
    },
    "outbound.notifyHangupDelaySec": {
      label: "Notify Hangup Delay (sec)",
      advanced: true,
    },
    staleCallReaperSeconds: {
      label: "Stale Call Reaper (sec)",
      advanced: true,
    },
    "serve.port": { label: "Webhook Port" },
    "serve.bind": { label: "Webhook Bind" },
    "serve.path": { label: "Webhook Path" },
    "tailscale.mode": { label: "Tailscale Mode", advanced: true },
    "tailscale.path": { label: "Tailscale Path", advanced: true },
    "tunnel.provider": { label: "Tunnel Provider", advanced: true },
    "tunnel.ngrokAuthToken": {
      label: "ngrok Auth Token",
      sensitive: true,
      advanced: true,
    },
    "tunnel.ngrokDomain": { label: "ngrok Domain", advanced: true },
    "tunnel.allowNgrokFreeTierLoopbackBypass": {
      label: "Allow ngrok Free Tier (Loopback Bypass)",
      advanced: true,
    },
    "streaming.enabled": { label: "Enable Streaming", advanced: true },
    "streaming.openaiApiKey": {
      label: "OpenAI Realtime API Key",
      sensitive: true,
      advanced: true,
    },
    "streaming.sttModel": { label: "Realtime STT Model", advanced: true },
    "streaming.streamPath": { label: "Media Stream Path", advanced: true },
    "tts.provider": {
      label: "TTS Provider Override",
      help: "Deep-merges with messages.tts (Edge is ignored for calls).",
      advanced: true,
    },
    "tts.openai.model": { label: "OpenAI TTS Model", advanced: true },
    "tts.openai.voice": { label: "OpenAI TTS Voice", advanced: true },
    "tts.openai.apiKey": {
      label: "OpenAI API Key",
      sensitive: true,
      advanced: true,
    },
    "tts.elevenlabs.modelId": { label: "ElevenLabs Model ID", advanced: true },
    "tts.elevenlabs.voiceId": { label: "ElevenLabs Voice ID", advanced: true },
    "tts.elevenlabs.apiKey": {
      label: "ElevenLabs API Key",
      sensitive: true,
      advanced: true,
    },
    "tts.elevenlabs.baseUrl": { label: "ElevenLabs Base URL", advanced: true },
    publicUrl: { label: "Public Webhook URL", advanced: true },
    skipSignatureVerification: {
      label: "Skip Signature Verification",
      advanced: true,
    },
    store: { label: "Call Log Store Path", advanced: true },
    responseModel: { label: "Response Model", advanced: true },
    responseSystemPrompt: { label: "Response System Prompt", advanced: true },
    responseTimeoutMs: { label: "Response Timeout (ms)", advanced: true },
    "controlPlane.bootsBaseUrl": {
      label: "Boots Base URL",
      help: "Boots API base URL for /api/2x4 voice relay actions.",
      advanced: true,
    },
    "controlPlane.bootsServiceToken": {
      label: "Boots 2x4 Service Token",
      sensitive: true,
      advanced: true,
    },
    "controlPlane.defaultTakeoverLeaseId": {
      label: "Default Takeover Lease ID",
      advanced: true,
    },
    "controlPlane.timeoutMs": {
      label: "Control Request Timeout (ms)",
      advanced: true,
    },
    "controlPlane.maxVoiceChars": {
      label: "Max Voice Relay Chars",
      advanced: true,
    },
  },
};

const VoiceCallToolSchema = Type.Union([
  Type.Object({
    action: Type.Literal("initiate_call"),
    to: Type.Optional(Type.String({ description: "Call target" })),
    message: Type.String({ description: "Intro message" }),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
    autoRespond: Type.Optional(
      Type.Boolean({
        description: "Override outbound conversation auto-response for this call.",
      }),
    ),
    voice: Type.Optional(
      Type.String({
        description:
          "Telephony voice preset (use fr-Spk2_man for French requests; default en-Carter_man).",
      }),
    ),
  }),
  Type.Object({
    action: Type.Literal("continue_call"),
    callId: Type.String({ description: "Call ID" }),
    message: Type.String({ description: "Follow-up message" }),
  }),
  Type.Object({
    action: Type.Literal("speak_to_user"),
    callId: Type.String({ description: "Call ID" }),
    message: Type.String({ description: "Message to speak" }),
  }),
  Type.Object({
    action: Type.Literal("end_call"),
    callId: Type.String({ description: "Call ID" }),
  }),
  Type.Object({
    action: Type.Literal("kill_calls"),
    callId: Type.Optional(Type.String({ description: "Specific call ID to terminate" })),
    all: Type.Optional(Type.Boolean({ description: "Kill all active calls" })),
    stale: Type.Optional(
      Type.Boolean({ description: "Kill only stale calls (default stale states: initiated/ringing)" }),
    ),
    staleSeconds: Type.Optional(
      Type.Number({ minimum: 1, description: "Stale age threshold in seconds (default 120)" }),
    ),
  }),
  Type.Object({
    action: Type.Literal("get_status"),
    callId: Type.String({ description: "Call ID" }),
    includeHistory: Type.Optional(
      Type.Boolean({
        description: "Fallback to recent call history when active call lookup misses.",
      }),
    ),
  }),
  Type.Object({
    action: Type.Literal("call_summary"),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_explain"),
    tail: Type.Optional(Type.Number({ minimum: 1, maximum: 400 })),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_file"),
    fileId: Type.String({ description: "Allowlisted file ID: scope|stats|report|findings|precheck" }),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_log"),
    logId: Type.Optional(Type.String({ description: "Allowlisted log ID (default engage)" })),
    tail: Type.Optional(Type.Number({ minimum: 1, maximum: 400 })),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_engage_status"),
    takeoverLeaseId: Type.Optional(Type.String({ description: "Active takeover lease ID" })),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_engage_action"),
    takeoverLeaseId: Type.Optional(Type.String({ description: "Active takeover lease ID" })),
    payload: Type.Optional(Type.Any()),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_takeover_confirm"),
    confirmation: Type.Optional(Type.String({ description: "Defaults to Yes" })),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    action: Type.Literal("call_stand_down"),
    callId: Type.Optional(Type.String({ description: "Active call ID to speak into" })),
    to: Type.Optional(Type.String({ description: "Dial target if no active callId is provided" })),
    mode: Type.Optional(Type.Union([Type.Literal("notify"), Type.Literal("conversation")])),
  }),
  Type.Object({
    mode: Type.Optional(Type.Union([Type.Literal("call"), Type.Literal("status")])),
    to: Type.Optional(Type.String({ description: "Call target" })),
    sid: Type.Optional(Type.String({ description: "Call SID" })),
    message: Type.Optional(Type.String({ description: "Optional intro message" })),
    voice: Type.Optional(
      Type.String({
        description:
          "Telephony voice preset (use fr-Spk2_man for French requests; default en-Carter_man).",
      }),
    ),
  }),
]);

const voiceCallPlugin = {
  id: "voice-call-bra",
  name: "Voice Call (BRA)",
  description: "Voice-call BRA development clone (isolated from voice-call-vv)",
  configSchema: voiceCallConfigSchema,
  register(api: OpenClawPluginApi) {
    const config = resolveVoiceCallConfig(voiceCallConfigSchema.parse(api.pluginConfig));
    const validation = validateProviderConfig(config);
    const controlPlane = {
      bootsBaseUrl:
        config.controlPlane?.bootsBaseUrl?.trim().replace(/\/+$/, "") ||
        process.env.BRA_BOOTS_BASE_URL?.trim().replace(/\/+$/, "") ||
        "http://127.0.0.1:7090",
      bootsServiceToken:
        config.controlPlane?.bootsServiceToken?.trim() || process.env.BRA_2X4_SERVICE_TOKEN?.trim(),
      defaultTakeoverLeaseId:
        config.controlPlane?.defaultTakeoverLeaseId?.trim() || process.env.BRA_2X4_LEASE_ID?.trim(),
      timeoutMs:
        typeof config.controlPlane?.timeoutMs === "number" && config.controlPlane.timeoutMs > 0
          ? Math.floor(config.controlPlane.timeoutMs)
          : 12000,
      maxVoiceChars:
        typeof config.controlPlane?.maxVoiceChars === "number" && config.controlPlane.maxVoiceChars > 0
          ? Math.floor(config.controlPlane.maxVoiceChars)
          : 600,
    };

    if (api.pluginConfig && typeof api.pluginConfig === "object") {
      const raw = api.pluginConfig as Record<string, unknown>;
      const twilio = raw.twilio as Record<string, unknown> | undefined;
      if (raw.provider === "log") {
        api.logger.warn('[voice-call] provider "log" is deprecated; use "mock" instead');
      }
      if (typeof twilio?.from === "string") {
        api.logger.warn("[voice-call] twilio.from is deprecated; use fromNumber instead");
      }
    }

    let runtimePromise: Promise<VoiceCallRuntime> | null = null;
    let runtime: VoiceCallRuntime | null = null;

    const ensureRuntime = async () => {
      if (!config.enabled) {
        throw new Error("Voice call disabled in plugin config");
      }
      if (!validation.valid) {
        throw new Error(validation.errors.join("; "));
      }
      if (runtime) {
        return runtime;
      }
      if (!runtimePromise) {
        runtimePromise = createVoiceCallRuntime({
          config,
          coreConfig: api.config as CoreConfig,
          ttsRuntime: api.runtime.tts,
          logger: api.logger,
        });
      }
      runtime = await runtimePromise;
      return runtime;
    };

    const sendError = (respond: (ok: boolean, payload?: unknown) => void, err: unknown) => {
      respond(false, { error: err instanceof Error ? err.message : String(err) });
    };

    const DEFAULT_CALL_VOICE = "en-Carter_man";
    const FRENCH_CALL_VOICE = "fr-Spk2_man";
    const ALLOWLISTED_FILE_IDS = new Set(["scope", "stats", "report", "findings", "precheck"]);
    const ALLOWLISTED_LOG_IDS = new Set(["engage"]);

    const consumeLanguageShortcut = (input: string): { remaining: string; voice?: string } => {
      const trimmed = input.trim();
      if (!trimmed) {
        return { remaining: "" };
      }
      const firstToken = trimmed.split(/\s+/, 1)[0]?.toLowerCase() || "";
      if (firstToken === "fr" || firstToken === "french") {
        return {
          remaining: trimmed.slice(firstToken.length).trim(),
          voice: FRENCH_CALL_VOICE,
        };
      }
      if (firstToken === "en" || firstToken === "english") {
        return {
          remaining: trimmed.slice(firstToken.length).trim(),
          voice: DEFAULT_CALL_VOICE,
        };
      }
      return { remaining: trimmed };
    };

    const resolveCallVoice = (rawVoice: unknown, message?: string): string => {
      if (typeof rawVoice === "string" && rawVoice.trim()) {
        return rawVoice.trim();
      }
      const text = (message || "").toLowerCase();
      if (/\b(fr|french)\b/.test(text)) {
        return FRENCH_CALL_VOICE;
      }
      return DEFAULT_CALL_VOICE;
    };

    const resolveAutoRespond = (raw: unknown): boolean | undefined =>
      typeof raw === "boolean" ? raw : undefined;

    const normalizeIntroMessage = (rawMessage: unknown): string => {
      const message = typeof rawMessage === "string" ? rawMessage.trim() : "";
      if (!message) {
        return "Calling you now.";
      }
      if (/^call me(?:\s+in)?(?:\s+(?:fr|french|en|english))?[.!?]*$/i.test(message)) {
        return "Calling you now.";
      }
      return message;
    };

    const parseCallCommandArgs = (rawArgs: string | undefined) => {
      const normalized = (rawArgs || "").trim();
      let remaining = normalized;
      let mode: "notify" | "conversation" | undefined = "conversation";

      if (remaining === "notify" || remaining.startsWith("notify ")) {
        mode = "notify";
        remaining = remaining.slice("notify".length).trim();
      } else if (remaining === "conversation" || remaining.startsWith("conversation ")) {
        mode = "conversation";
        remaining = remaining.slice("conversation".length).trim();
      }

      let to: string | undefined;
      const firstToken = remaining.split(/\s+/, 1)[0] || "";
      if (/^\+[1-9]\d{1,14}$/.test(firstToken)) {
        to = firstToken;
        remaining = remaining.slice(firstToken.length).trim();
      }

      const language = consumeLanguageShortcut(remaining);
      remaining = language.remaining;

      return {
        mode,
        to,
        voice: language.voice ?? DEFAULT_CALL_VOICE,
        message: normalizeIntroMessage(remaining),
      };
    };

    const resolveInitiateMode = (mode: unknown): "notify" | "conversation" | undefined => {
      if (mode === "notify" || mode === "conversation") {
        return mode;
      }
      // Compatibility: some model/tool paths send generic "call" mode.
      if (mode === "call") {
        return "conversation";
      }
      return undefined;
    };

    type ControlVoiceAction =
      | "call_summary"
      | "call_explain"
      | "call_file"
      | "call_log"
      | "call_engage_status"
      | "call_engage_action"
      | "call_takeover_confirm"
      | "call_stand_down";

    const serializeForVoice = (value: unknown): string => {
      const raw =
        typeof value === "string"
          ? value
          : JSON.stringify(value, null, 0) || "No data returned.";
      const singleLine = raw.replace(/\s+/g, " ").trim();
      if (singleLine.length <= controlPlane.maxVoiceChars) {
        return singleLine;
      }
      return `${singleLine.slice(0, Math.max(1, controlPlane.maxVoiceChars - 3))}...`;
    };

    const summarizeControlPayload = (action: ControlVoiceAction, payload: unknown): string => {
      switch (action) {
        case "call_summary":
          return `BRA summary: ${serializeForVoice(payload)}`;
        case "call_explain":
          return `BRA explain: ${serializeForVoice(payload)}`;
        case "call_file":
          return `BRA file result: ${serializeForVoice(payload)}`;
        case "call_log":
          return `BRA log result: ${serializeForVoice(payload)}`;
        case "call_engage_status":
          return `BRA engage status: ${serializeForVoice(payload)}`;
        case "call_engage_action":
          return `BRA engage action result: ${serializeForVoice(payload)}`;
        case "call_takeover_confirm":
          return `BRA takeover confirm result: ${serializeForVoice(payload)}`;
        case "call_stand_down":
          return `BRA stand down result: ${serializeForVoice(payload)}`;
        default:
          return serializeForVoice(payload);
      }
    };

    const callBootsControl = async (
      path: string,
      init: RequestInit = {},
      takeoverLeaseId?: string,
    ): Promise<unknown> => {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        ...(init.headers as Record<string, string> | undefined),
      };
      if (controlPlane.bootsServiceToken) {
        headers.authorization = `Bearer ${controlPlane.bootsServiceToken}`;
      }
      const resolvedLease = (takeoverLeaseId || controlPlane.defaultTakeoverLeaseId || "").trim();
      if (resolvedLease) {
        headers["x-2x4-lease-id"] = resolvedLease;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), controlPlane.timeoutMs);
      try {
        const response = await fetch(`${controlPlane.bootsBaseUrl}${path}`, {
          ...init,
          headers,
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(String((payload as Record<string, unknown>)?.detail || response.statusText));
        }
        return payload;
      } finally {
        clearTimeout(timeout);
      }
    };

    const relayVoiceText = async (
      rt: VoiceCallRuntime,
      text: string,
      options: { callId?: string; to?: string; mode?: unknown; voice?: unknown },
    ): Promise<{ via: "speak" | "initiate"; callId: string }> => {
      const callId = String(options.callId || "").trim();
      if (callId) {
        const spoke = await rt.manager.speak(callId, text);
        if (!spoke.success) {
          throw new Error(spoke.error || "speak failed");
        }
        return { via: "speak", callId };
      }
      const to = String(options.to || rt.config.toNumber || "").trim();
      if (!to) {
        throw new Error("to required");
      }
      const result = await rt.manager.initiateCall(to, undefined, {
        message: text,
        mode: resolveInitiateMode(options.mode) || "conversation",
        autoRespond: false,
        voice: resolveCallVoice(options.voice, text),
      });
      if (!result.success) {
        throw new Error(result.error || "initiate failed");
      }
      return { via: "initiate", callId: result.callId };
    };

    const executeControlVoiceAction = async (
      rt: VoiceCallRuntime,
      action: ControlVoiceAction,
      params: Record<string, unknown>,
    ): Promise<{ action: ControlVoiceAction; data: unknown; spokenText: string; callId: string; via: string }> => {
      let data: unknown;
      const takeoverLeaseId = String(params.takeoverLeaseId || "").trim() || undefined;
      switch (action) {
        case "call_summary":
          data = await callBootsControl("/api/2x4/summary");
          break;
        case "call_explain": {
          const rawTail = Number(params.tail || 200);
          const tail = Number.isFinite(rawTail) ? Math.max(1, Math.min(400, rawTail)) : 200;
          const [summary, log] = await Promise.all([
            callBootsControl("/api/2x4/summary"),
            callBootsControl(`/api/2x4/log?name=engage&tail=${tail}`),
          ]);
          data = { summary, log };
          break;
        }
        case "call_file": {
          const fileId = String(params.fileId || "").trim().toLowerCase();
          if (!ALLOWLISTED_FILE_IDS.has(fileId)) {
            throw new Error("fileId not allowlisted");
          }
          data = await callBootsControl(`/api/2x4/file?name=${encodeURIComponent(fileId)}`);
          break;
        }
        case "call_log": {
          const logId = String(params.logId || "engage").trim().toLowerCase();
          if (!ALLOWLISTED_LOG_IDS.has(logId)) {
            throw new Error("logId not allowlisted");
          }
          const rawTail = Number(params.tail || 120);
          const tail = Number.isFinite(rawTail) ? Math.max(1, Math.min(400, rawTail)) : 120;
          data = await callBootsControl(
            `/api/2x4/log?name=${encodeURIComponent(logId)}&tail=${tail}`,
          );
          break;
        }
        case "call_engage_status":
          data = await callBootsControl("/api/2x4/engage-status", {}, takeoverLeaseId);
          break;
        case "call_engage_action":
          data = await callBootsControl(
            "/api/2x4/engage-action",
            { method: "POST", body: JSON.stringify(params.payload || {}) },
            takeoverLeaseId,
          );
          break;
        case "call_takeover_confirm":
          data = await callBootsControl("/api/2x4/takeover-confirm", {
            method: "POST",
            body: JSON.stringify({ confirmation: String(params.confirmation || "Yes") }),
          });
          break;
        case "call_stand_down":
          data = await callBootsControl("/api/2x4/stand-down", {
            method: "POST",
            body: JSON.stringify({}),
          });
          break;
      }

      const spokenText = summarizeControlPayload(action, data);
      const delivery = await relayVoiceText(rt, spokenText, {
        callId: String(params.callId || params.call_id || "").trim(),
        to: typeof params.to === "string" ? params.to : undefined,
        mode: params.mode,
        voice: params.voice,
      });
      return {
        action,
        data,
        spokenText,
        callId: delivery.callId,
        via: delivery.via,
      };
    };

    const parseControlVoiceCommandArgs = (
      rawArgs: string | undefined,
    ): { action: ControlVoiceAction; params: Record<string, unknown> } | null => {
      const text = String(rawArgs || "").trim();
      let tokens = text.split(/\s+/).filter(Boolean);
      if (tokens[0]?.toLowerCase() === "bra" && tokens[1]?.toLowerCase() === "call") {
        tokens = tokens.slice(2);
      } else if (tokens[0]?.toLowerCase() === "call") {
        tokens = tokens.slice(1);
      }
      if (!tokens.length) {
        return null;
      }
      if (tokens[0] === "summary") {
        return { action: "call_summary", params: {} };
      }
      if (tokens[0] === "explain") {
        const tail = /^\d+$/.test(tokens[1] || "") ? Number(tokens[1]) : undefined;
        return { action: "call_explain", params: { tail } };
      }
      if (tokens[0] === "file") {
        return { action: "call_file", params: { fileId: tokens[1] || "" } };
      }
      if (tokens[0] === "log") {
        const token1 = tokens[1] || "";
        const token2 = tokens[2] || "";
        const parsedTail1 = /^\d+$/.test(token1) ? Number(token1) : undefined;
        const parsedTail2 = /^\d+$/.test(token2) ? Number(token2) : undefined;
        return {
          action: "call_log",
          params: {
            logId: token1 && !parsedTail1 ? token1 : "engage",
            tail: parsedTail2 ?? parsedTail1,
          },
        };
      }
      if (tokens[0] === "engage" && tokens[1] === "status") {
        return {
          action: "call_engage_status",
          params: { takeoverLeaseId: tokens[2] || undefined },
        };
      }
      if (tokens[0] === "engage" && tokens[1] === "action") {
        return {
          action: "call_engage_action",
          params: {
            takeoverLeaseId: tokens[2] || undefined,
            payload: {},
          },
        };
      }
      if (tokens[0] === "takeover" && tokens[1] === "confirm") {
        return {
          action: "call_takeover_confirm",
          params: { confirmation: tokens.slice(2).join(" ") || "Yes" },
        };
      }
      if (tokens[0] === "stand" && tokens[1] === "down") {
        return { action: "call_stand_down", params: {} };
      }
      return null;
    };

    const parseBooleanFlag = (value: unknown): boolean =>
      value === true ||
      value === "true" ||
      value === "1" ||
      value === 1 ||
      value === "yes" ||
      value === "on";

    const resolveStaleSeconds = (value: unknown, fallback = 120): number => {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) {
        return fallback;
      }
      return Math.max(1, Math.floor(numeric));
    };

    const killCalls = async (
      rt: VoiceCallRuntime,
      rawParams: Record<string, unknown>,
    ): Promise<{
      killed: string[];
      failed: Array<{ callId: string; error: string }>;
      inspected: number;
      mode: "callId" | "all" | "stale";
      staleSeconds?: number;
    }> => {
      const callId = String(rawParams.callId || rawParams.call_id || "").trim();
      const staleRequested = parseBooleanFlag(rawParams.stale);
      const allRequested = parseBooleanFlag(rawParams.all);
      const staleSeconds = resolveStaleSeconds(rawParams.staleSeconds ?? rawParams.stale_seconds);
      const now = Date.now();
      const active = rt.manager.getActiveCalls();
      let targets = active;
      let mode: "callId" | "all" | "stale" = "all";

      if (callId) {
        mode = "callId";
        targets = active.filter((call) => call.callId === callId || call.providerCallId === callId);
      } else if (staleRequested && !allRequested) {
        mode = "stale";
        targets = active.filter((call) => {
          if (!(call.state === "initiated" || call.state === "ringing")) {
            return false;
          }
          return now - call.startedAt >= staleSeconds * 1000;
        });
      }

      const killed: string[] = [];
      const failed: Array<{ callId: string; error: string }> = [];
      for (const call of targets) {
        const result = await rt.manager.endCall(call.callId);
        if (result.success) {
          killed.push(call.callId);
        } else {
          failed.push({ callId: call.callId, error: result.error || "end failed" });
        }
      }

      return {
        killed,
        failed,
        inspected: active.length,
        mode,
        ...(mode === "stale" && { staleSeconds }),
      };
    };

    api.registerGatewayMethod(
      "voicecall_bra.initiate",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rawMessage = typeof params?.message === "string" ? params.message : "";
          const message = normalizeIntroMessage(rawMessage);
          if (!message) {
            respond(false, { error: "message required" });
            return;
          }
          const rt = await ensureRuntime();
          const to =
            typeof params?.to === "string" && params.to.trim()
              ? params.to.trim()
              : rt.config.toNumber;
          if (!to) {
            respond(false, { error: "to required" });
            return;
          }
          const mode = resolveInitiateMode(params?.mode);
          const voice = resolveCallVoice(params?.voice, rawMessage);
          const result = await rt.manager.initiateCall(to, undefined, {
            message,
            mode,
            autoRespond: resolveAutoRespond(params?.autoRespond),
            voice,
          });
          if (!result.success) {
            respond(false, { error: result.error || "initiate failed" });
            return;
          }
          respond(true, { callId: result.callId, initiated: true });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.continue",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const callId =
            typeof params?.callId === "string"
              ? params.callId.trim()
              : typeof params?.call_id === "string"
                ? params.call_id.trim()
                : "";
          const message = typeof params?.message === "string" ? params.message.trim() : "";
          if (!callId || !message) {
            respond(false, { error: "callId and message required" });
            return;
          }
          const rt = await ensureRuntime();
          const result = await rt.manager.continueCall(callId, message);
          if (!result.success) {
            respond(false, { error: result.error || "continue failed" });
            return;
          }
          respond(true, { success: true, transcript: result.transcript });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.speak",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const callId =
            typeof params?.callId === "string"
              ? params.callId.trim()
              : typeof params?.call_id === "string"
                ? params.call_id.trim()
                : "";
          const message = typeof params?.message === "string" ? params.message.trim() : "";
          if (!callId || !message) {
            respond(false, { error: "callId and message required" });
            return;
          }
          const rt = await ensureRuntime();
          const result = await rt.manager.speak(callId, message);
          if (!result.success) {
            respond(false, { error: result.error || "speak failed" });
            return;
          }
          respond(true, { success: true });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.end",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const callId =
            typeof params?.callId === "string"
              ? params.callId.trim()
              : typeof params?.call_id === "string"
                ? params.call_id.trim()
                : "";
          if (!callId) {
            respond(false, { error: "callId required" });
            return;
          }
          const rt = await ensureRuntime();
          const result = await rt.manager.endCall(callId);
          if (!result.success) {
            respond(false, { error: result.error || "end failed" });
            return;
          }
          respond(true, { success: true });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.kill",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await killCalls(rt, (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.status",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const includeHistory =
            params?.includeHistory === true || params?.include_history === true;
          const raw =
            typeof params?.callId === "string"
              ? params.callId.trim()
              : typeof params?.call_id === "string"
                ? params.call_id.trim()
              : typeof params?.sid === "string"
                ? params.sid.trim()
                : "";
          if (!raw) {
            respond(false, { error: "callId required" });
            return;
          }
          const rt = await ensureRuntime();
          let call = rt.manager.getCall(raw) || rt.manager.getCallByProviderCallId(raw);
          if (!call && includeHistory) {
            const history = await rt.manager.getCallHistory(200);
            call =
              history
                .slice()
                .reverse()
                .find((item) => item.callId === raw || item.providerCallId === raw) ?? undefined;
            if (call) {
              respond(true, { found: true, call, "source": "history" });
              return;
            }
          }
          if (!call) {
            respond(true, { found: false });
            return;
          }
          respond(true, { found: true, call, "source": "active" });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.start",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const to = typeof params?.to === "string" ? params.to.trim() : "";
          const message = typeof params?.message === "string" ? params.message.trim() : "";
          if (!to) {
            respond(false, { error: "to required" });
            return;
          }
          const normalizedMessage = normalizeIntroMessage(message || undefined);
          const voice = resolveCallVoice(params?.voice, message);
          const rt = await ensureRuntime();
          const result = await rt.manager.initiateCall(to, undefined, {
            message: normalizedMessage || undefined,
            autoRespond: resolveAutoRespond(params?.autoRespond),
            voice,
          });
          if (!result.success) {
            respond(false, { error: result.error || "initiate failed" });
            return;
          }
          respond(true, { callId: result.callId, initiated: true });
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_summary",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(rt, "call_summary", (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_explain",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(rt, "call_explain", (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_file",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(rt, "call_file", (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_log",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(rt, "call_log", (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_engage_status",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(
            rt,
            "call_engage_status",
            (params || {}) as Record<string, unknown>,
          );
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_engage_action",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(
            rt,
            "call_engage_action",
            (params || {}) as Record<string, unknown>,
          );
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_takeover_confirm",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(
            rt,
            "call_takeover_confirm",
            (params || {}) as Record<string, unknown>,
          );
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "voicecall_bra.call_stand_down",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const rt = await ensureRuntime();
          const result = await executeControlVoiceAction(rt, "call_stand_down", (params || {}) as Record<string, unknown>);
          respond(true, result);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    const commandApi = api as OpenClawPluginApi & {
      registerCommand?: (definition: {
        name: string;
        description: string;
        acceptsArgs?: boolean;
        requireAuth?: boolean;
        handler: (ctx: {
          args?: string;
        }) => Promise<{ text: string }> | { text: string };
      }) => void;
    };

    if (typeof commandApi.registerCommand === "function") {
      const handleCallCommand = async (args: string | undefined) => {
        try {
          const rt = await ensureRuntime();
          const argText = String(args || "").trim();
          const argTokens = argText.split(/\s+/).filter(Boolean);
          if (argTokens[0] === "kill") {
            const killParams: Record<string, unknown> = {};
            if (argTokens[1] === "stale") {
              killParams.stale = true;
              if (/^\d+$/.test(argTokens[2] || "")) {
                killParams.staleSeconds = Number(argTokens[2]);
              }
            } else if (argTokens[1]) {
              killParams.callId = argTokens[1];
            } else {
              killParams.all = true;
            }
            const result = await killCalls(rt, killParams);
            return {
              text:
                `Kill mode=${result.mode} killed=${result.killed.length} failed=${result.failed.length}` +
                (result.staleSeconds ? ` staleSeconds=${result.staleSeconds}` : "") +
                (result.killed.length ? ` callIds=${result.killed.join(",")}` : ""),
            };
          }
          const controlCommand = parseControlVoiceCommandArgs(args);
          if (controlCommand) {
            const result = await executeControlVoiceAction(rt, controlCommand.action, controlCommand.params);
            return { text: `${controlCommand.action} delivered via ${result.via}. callId: ${result.callId}` };
          }
          const parsed = parseCallCommandArgs(args);
          const to = parsed.to || rt.config.toNumber;
          if (!to) {
            return { text: "Call failed: no target number set. Configure toNumber or pass +E164." };
          }
          const result = await rt.manager.initiateCall(to, undefined, {
            message: parsed.message,
            mode: parsed.mode,
            voice: parsed.voice,
          });
          if (!result.success) {
            return { text: `Call failed: ${result.error || "initiate failed"}` };
          }
          return { text: `Calling now. callId: ${result.callId}` };
        } catch (err) {
          return { text: `Call failed: ${err instanceof Error ? err.message : String(err)}` };
        }
      };

      commandApi.registerCommand({
        name: "call-bra",
        description:
          "BRA clone: /call-bra kill [callId]|kill stale [sec]|summary|explain|file|log|engage status|stand down, or /call-bra [notify|conversation] [+E164] [message]",
        acceptsArgs: true,
        requireAuth: true,
        handler: (ctx) => handleCallCommand(ctx.args),
      });

      commandApi.registerCommand({
        name: "callme-bra",
        description: "BRA clone alias for /call-bra",
        acceptsArgs: true,
        requireAuth: true,
        handler: (ctx) => handleCallCommand(ctx.args),
      });
    }

    const executeVoiceCallTool = async (_toolCallId: string, params: Record<string, unknown>) => {
      const json = (payload: unknown) => ({
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        details: payload,
      });

      try {
        const rt = await ensureRuntime();

        if (typeof params?.action === "string") {
          switch (params.action) {
            case "initiate_call": {
              const rawMessage = String(params.message || "");
              const message = normalizeIntroMessage(rawMessage);
              if (!message) {
                throw new Error("message required");
              }
              const to =
                typeof params.to === "string" && params.to.trim()
                  ? params.to.trim()
                  : rt.config.toNumber;
              if (!to) {
                throw new Error("to required");
              }
              const voice = resolveCallVoice(params.voice, rawMessage);
              const result = await rt.manager.initiateCall(to, undefined, {
                message,
                mode: resolveInitiateMode(params.mode),
                autoRespond: resolveAutoRespond(params.autoRespond),
                voice,
              });
              if (!result.success) {
                throw new Error(result.error || "initiate failed");
              }
              return json({ callId: result.callId, initiated: true });
            }
            case "continue_call": {
              const callId = String(params.callId || params.call_id || "").trim();
              const message = String(params.message || "").trim();
              if (!callId || !message) {
                throw new Error("callId and message required");
              }
              const result = await rt.manager.continueCall(callId, message);
              if (!result.success) {
                throw new Error(result.error || "continue failed");
              }
              return json({ success: true, transcript: result.transcript });
            }
            case "speak_to_user": {
              const callId = String(params.callId || params.call_id || "").trim();
              const message = String(params.message || "").trim();
              if (!callId || !message) {
                throw new Error("callId and message required");
              }
              const result = await rt.manager.speak(callId, message);
              if (!result.success) {
                throw new Error(result.error || "speak failed");
              }
              return json({ success: true });
            }
            case "end_call": {
              const callId = String(params.callId || params.call_id || "").trim();
              if (!callId) {
                throw new Error("callId required");
              }
              const result = await rt.manager.endCall(callId);
              if (!result.success) {
                throw new Error(result.error || "end failed");
              }
              return json({ success: true });
            }
            case "kill_calls": {
              const result = await killCalls(rt, params);
              return json(result);
            }
            case "get_status": {
              const callId = String(params.callId || params.call_id || "").trim();
              const includeHistory =
                params.includeHistory === true || params.include_history === true;
              if (!callId) {
                throw new Error("callId required");
              }
              let call = rt.manager.getCall(callId) || rt.manager.getCallByProviderCallId(callId);
              if (!call && includeHistory) {
                const history = await rt.manager.getCallHistory(200);
                call =
                  history
                    .slice()
                    .reverse()
                    .find((item) => item.callId === callId || item.providerCallId === callId) ??
                  undefined;
                return json(call ? { found: true, call, source: "history" } : { found: false });
              }
              return json(call ? { found: true, call, source: "active" } : { found: false });
            }
            case "call_summary":
            case "call_explain":
            case "call_file":
            case "call_log":
            case "call_engage_status":
            case "call_engage_action":
            case "call_takeover_confirm":
            case "call_stand_down": {
              const result = await executeControlVoiceAction(
                rt,
                params.action as ControlVoiceAction,
                params,
              );
              return json(result);
            }
          }
        }

        const mode = params?.mode ?? "call";
        if (mode === "status") {
          const sid = typeof params.sid === "string" ? params.sid.trim() : "";
          if (!sid) {
            throw new Error("sid required for status");
          }
          const call = rt.manager.getCall(sid) || rt.manager.getCallByProviderCallId(sid);
          return json(call ? { found: true, call } : { found: false });
        }

        const to =
          typeof params.to === "string" && params.to.trim()
            ? params.to.trim()
            : rt.config.toNumber;
        if (!to) {
          throw new Error("to required for call");
        }
        const result = await rt.manager.initiateCall(to, undefined, {
          message: normalizeIntroMessage(params.message),
          autoRespond: resolveAutoRespond(params.autoRespond),
          voice: resolveCallVoice(params.voice, String(params.message || "")),
        });
        if (!result.success) {
          throw new Error(result.error || "initiate failed");
        }
        return json({ callId: result.callId, initiated: true });
      } catch (err) {
        return json({
          error: err instanceof Error ? err.message : String(err),
        });
      }
    };

    api.registerTool({
      name: "voice_call_bra",
      label: "Voice Call BRA",
      description: "Make phone calls and have voice conversations via the voice-call plugin.",
      parameters: VoiceCallToolSchema,
      execute: executeVoiceCallTool,
    });

    api.registerTool({
      name: "voice_call_bra_alias",
      label: "Voice Call BRA Alias",
      description: "Alias of voice_call_bra for BRA clone compatibility.",
      parameters: VoiceCallToolSchema,
      execute: executeVoiceCallTool,
    });

    api.registerCli(
      ({ program }) =>
        registerVoiceCallCli({
          program,
          config,
          ensureRuntime,
          logger: api.logger,
        }),
      { commands: ["voicecall-bra"] },
    );

    api.registerService({
      id: "voicecall-bra",
      start: async () => {
        if (!config.enabled) {
          return;
        }
        try {
          await ensureRuntime();
        } catch (err) {
          api.logger.error(
            `[voice-call] Failed to start runtime: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      },
      stop: async () => {
        if (!runtimePromise) {
          return;
        }
        try {
          const rt = await runtimePromise;
          await rt.stop();
        } finally {
          runtimePromise = null;
          runtime = null;
        }
      },
    });
  },
};

export default voiceCallPlugin;
