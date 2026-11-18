import { Type } from "@sinclair/typebox";
import type { GatewayRequestHandlerOptions, OpenClawPluginApi } from "openclaw/plugin-sdk";
import {
  normalizeControlAction,
  parseBraShortcutArgs,
  resolveOperatorAliasArgs,
} from "./operator_aliases.ts";

const ALLOWLISTED_FILE_IDS = new Set(["scope", "stats", "report", "findings", "precheck"]);
const ALLOWLISTED_LOG_IDS = new Set(["engage"]);

type PluginConfig = {
  bootsBaseUrl: string;
  bootsServiceToken?: string;
  timeoutMs: number;
};

const configSchema = {
  parse(value: unknown): PluginConfig {
    const raw =
      value && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    const bootsBaseUrl =
      typeof raw.bootsBaseUrl === "string" && raw.bootsBaseUrl.trim()
        ? raw.bootsBaseUrl.trim().replace(/\/+$/, "")
        : "http://127.0.0.1:7090";
    const bootsServiceToken =
      typeof raw.bootsServiceToken === "string" && raw.bootsServiceToken.trim()
        ? raw.bootsServiceToken.trim()
        : undefined;
    const timeoutMs =
      typeof raw.timeoutMs === "number" && raw.timeoutMs > 0 ? Math.floor(raw.timeoutMs) : 12000;
    return { bootsBaseUrl, bootsServiceToken, timeoutMs };
  },
};

const ControlToolSchema = Type.Object({
  action: Type.Union([
    Type.Literal("summary"),
    Type.Literal("bra summary"),
    Type.Literal("explain"),
    Type.Literal("bra explain"),
    Type.Literal("file"),
    Type.Literal("bra file"),
    Type.Literal("log"),
    Type.Literal("bra log"),
    Type.Literal("engage_status"),
    Type.Literal("bra engage status"),
    Type.Literal("engage_action"),
    Type.Literal("bra engage action"),
    Type.Literal("call_continue"),
    Type.Literal("bra call continue"),
    Type.Literal("call_speak"),
    Type.Literal("bra call speak"),
    Type.Literal("call_status"),
    Type.Literal("bra call status"),
    Type.Literal("call_stop"),
    Type.Literal("bra call stop"),
    Type.Literal("takeover_confirm"),
    Type.Literal("bra takeover confirm"),
    Type.Literal("stand_down"),
    Type.Literal("bra stand down"),
  ]),
  fileId: Type.Optional(Type.String()),
  logId: Type.Optional(Type.String()),
  tail: Type.Optional(Type.Number({ minimum: 1, maximum: 400 })),
  takeoverLeaseId: Type.Optional(Type.String()),
  callId: Type.Optional(Type.String()),
  call_id: Type.Optional(Type.String()),
  message: Type.Optional(Type.String()),
  includeHistory: Type.Optional(Type.Boolean()),
  include_history: Type.Optional(Type.Boolean()),
  payload: Type.Optional(Type.Any()),
});

const OperatorAliasToolSchema = Type.Object({
  action: Type.Optional(Type.String()),
  command: Type.Optional(Type.String()),
  fileId: Type.Optional(Type.String()),
  logId: Type.Optional(Type.String()),
  tail: Type.Optional(Type.Number({ minimum: 1, maximum: 400 })),
  takeoverLeaseId: Type.Optional(Type.String()),
  callId: Type.Optional(Type.String()),
  call_id: Type.Optional(Type.String()),
  message: Type.Optional(Type.String()),
  includeHistory: Type.Optional(Type.Boolean()),
  include_history: Type.Optional(Type.Boolean()),
  payload: Type.Optional(Type.Any()),
});

const BraShortcutToolSchema = Type.Object({
  command: Type.String({
    description:
      "Shortcut command like 'bra summary', 'bra explain', 'bra file scope', 'bra log engage 200', or 'bra call status call-123'.",
  }),
  fileId: Type.Optional(Type.String()),
  logId: Type.Optional(Type.String()),
  tail: Type.Optional(Type.Number({ minimum: 1, maximum: 400 })),
  takeoverLeaseId: Type.Optional(Type.String()),
  callId: Type.Optional(Type.String()),
  call_id: Type.Optional(Type.String()),
  message: Type.Optional(Type.String()),
  includeHistory: Type.Optional(Type.Boolean()),
  include_history: Type.Optional(Type.Boolean()),
  payload: Type.Optional(Type.Any()),
});

const controlPlugin = {
  id: "openclaw-2x4-control",
  name: "2x4 Control Plane (Dev)",
  description: "Bounded plugin surface for 2x4 readonly context and takeover control.",
  configSchema,
  register(api: OpenClawPluginApi) {
    const config = configSchema.parse(api.pluginConfig);

    const callBoots = async (
      path: string,
      init: RequestInit = {},
      takeoverLeaseId?: string,
    ): Promise<unknown> => {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        ...(init.headers as Record<string, string> | undefined),
      };
      if (config.bootsServiceToken) {
        headers.authorization = `Bearer ${config.bootsServiceToken}`;
      }
      if (takeoverLeaseId) {
        headers["x-2x4-lease-id"] = takeoverLeaseId;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
      try {
        const response = await fetch(`${config.bootsBaseUrl}${path}`, {
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

    const sendError = (respond: (ok: boolean, payload?: unknown) => void, err: unknown) => {
      respond(false, { error: err instanceof Error ? err.message : String(err) });
    };

    api.registerGatewayMethod(
      "bra2x4.summary",
      async ({ respond }: GatewayRequestHandlerOptions) => {
        try {
          const data = await callBoots("/api/2x4/summary");
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.file",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const fileId = typeof params?.fileId === "string" ? params.fileId.trim().toLowerCase() : "";
          if (!ALLOWLISTED_FILE_IDS.has(fileId)) {
            respond(false, { error: "fileId not allowlisted" });
            return;
          }
          const data = await callBoots(`/api/2x4/file?name=${encodeURIComponent(fileId)}`);
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.log",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const logId = typeof params?.logId === "string" ? params.logId.trim().toLowerCase() : "";
          if (!ALLOWLISTED_LOG_IDS.has(logId)) {
            respond(false, { error: "logId not allowlisted" });
            return;
          }
          const tail = typeof params?.tail === "number" ? Math.max(1, Math.min(400, params.tail)) : 120;
          const data = await callBoots(
            `/api/2x4/log?name=${encodeURIComponent(logId)}&tail=${tail}`,
          );
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.engage_status",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
          const data = await callBoots("/api/2x4/engage-status", {}, takeoverLeaseId);
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.engage_action",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
          const payload =
            params && typeof params === "object" && !Array.isArray(params) ? params : {};
          const data = await callBoots(
            "/api/2x4/engage-action",
            { method: "POST", body: JSON.stringify(payload) },
            takeoverLeaseId,
          );
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.call_continue",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
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
          const data = await callBoots(
            "/api/2x4/call/continue",
            { method: "POST", body: JSON.stringify({ call_id: callId, message }) },
            takeoverLeaseId,
          );
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.call_speak",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
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
          const data = await callBoots(
            "/api/2x4/call/speak",
            { method: "POST", body: JSON.stringify({ call_id: callId, message }) },
            takeoverLeaseId,
          );
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.call_status",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
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
          const includeHistory =
            params?.includeHistory === true || params?.include_history === true;
          const query = new URLSearchParams({ call_id: callId });
          if (includeHistory) {
            query.set("includeHistory", "true");
          }
          const data = await callBoots(`/api/2x4/call/status?${query.toString()}`, {}, takeoverLeaseId);
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.call_stop",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const takeoverLeaseId =
            typeof params?.takeoverLeaseId === "string" ? params.takeoverLeaseId.trim() : "";
          if (!takeoverLeaseId) {
            respond(false, { error: "takeoverLeaseId required" });
            return;
          }
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
          const data = await callBoots(
            "/api/2x4/call/stop",
            { method: "POST", body: JSON.stringify({ call_id: callId }) },
            takeoverLeaseId,
          );
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.takeover_confirm",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const payload =
            params && typeof params === "object" && !Array.isArray(params) ? params : {};
          const data = await callBoots("/api/2x4/takeover-confirm", {
            method: "POST",
            body: JSON.stringify(payload),
          });
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    api.registerGatewayMethod(
      "bra2x4.stand_down",
      async ({ params, respond }: GatewayRequestHandlerOptions) => {
        try {
          const payload =
            params && typeof params === "object" && !Array.isArray(params) ? params : {};
          const data = await callBoots("/api/2x4/stand-down", {
            method: "POST",
            body: JSON.stringify(payload),
          });
          respond(true, data);
        } catch (err) {
          sendError(respond, err);
        }
      },
    );

    const executeControlTool = async (args: Record<string, unknown>) => {
      const action = normalizeControlAction(args.action);
      switch (action) {
        case "summary":
          return await callBoots("/api/2x4/summary");
        case "explain": {
          const rawTail = Number(args.tail || 200);
          const tail = Number.isFinite(rawTail) ? Math.max(1, Math.min(400, rawTail)) : 200;
          const [summary, log] = await Promise.all([
            callBoots("/api/2x4/summary"),
            callBoots(`/api/2x4/log?name=engage&tail=${tail}`),
          ]);
          return {
            summary,
            log,
            hint: "Use summary.engage.options and recent engage log lines to explain the current operator choice.",
          };
        }
        case "file": {
          const fileId = String(args.fileId || "").trim().toLowerCase();
          if (!ALLOWLISTED_FILE_IDS.has(fileId)) {
            return { error: "fileId not allowlisted" };
          }
          return await callBoots(`/api/2x4/file?name=${encodeURIComponent(fileId)}`);
        }
        case "log": {
          const logId = String(args.logId || "").trim().toLowerCase();
          if (!ALLOWLISTED_LOG_IDS.has(logId)) {
            return { error: "logId not allowlisted" };
          }
          const rawTail = Number(args.tail || 120);
          const tail = Number.isFinite(rawTail) ? Math.max(1, Math.min(400, rawTail)) : 120;
          return await callBoots(`/api/2x4/log?name=${encodeURIComponent(logId)}&tail=${tail}`);
        }
        case "engage_status": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          return await callBoots("/api/2x4/engage-status", {}, takeoverLeaseId);
        }
        case "engage_action": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          return await callBoots(
            "/api/2x4/engage-action",
            { method: "POST", body: JSON.stringify(args.payload || {}) },
            takeoverLeaseId,
          );
        }
        case "call_continue": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          const callId = String(args.callId || args.call_id || "").trim();
          const message = String(args.message || "").trim();
          if (!callId || !message) {
            return { error: "callId and message required" };
          }
          return await callBoots(
            "/api/2x4/call/continue",
            { method: "POST", body: JSON.stringify({ call_id: callId, message }) },
            takeoverLeaseId,
          );
        }
        case "call_speak": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          const callId = String(args.callId || args.call_id || "").trim();
          const message = String(args.message || "").trim();
          if (!callId || !message) {
            return { error: "callId and message required" };
          }
          return await callBoots(
            "/api/2x4/call/speak",
            { method: "POST", body: JSON.stringify({ call_id: callId, message }) },
            takeoverLeaseId,
          );
        }
        case "call_status": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          const callId = String(args.callId || args.call_id || "").trim();
          if (!callId) {
            return { error: "callId required" };
          }
          const includeHistory = args.includeHistory === true || args.include_history === true;
          const query = new URLSearchParams({ call_id: callId });
          if (includeHistory) {
            query.set("includeHistory", "true");
          }
          return await callBoots(`/api/2x4/call/status?${query.toString()}`, {}, takeoverLeaseId);
        }
        case "call_stop": {
          const takeoverLeaseId = String(args.takeoverLeaseId || "").trim();
          if (!takeoverLeaseId) {
            return { error: "takeoverLeaseId required" };
          }
          const callId = String(args.callId || args.call_id || "").trim();
          if (!callId) {
            return { error: "callId required" };
          }
          return await callBoots(
            "/api/2x4/call/stop",
            { method: "POST", body: JSON.stringify({ call_id: callId }) },
            takeoverLeaseId,
          );
        }
        case "takeover_confirm":
          return await callBoots("/api/2x4/takeover-confirm", {
            method: "POST",
            body: JSON.stringify(args.payload || {}),
          });
        case "stand_down":
          return await callBoots("/api/2x4/stand-down", {
            method: "POST",
            body: JSON.stringify(args.payload || {}),
          });
        default:
          return { error: "unsupported action" };
      }
    };

    const executeBraShortcutTool = async (args: Record<string, unknown>) => {
      const parsed = parseBraShortcutArgs(args);
      return await executeControlTool(parsed);
    };

    const executeOperatorAliasTool = async (toolName: string, args: Record<string, unknown>) => {
      const parsed = resolveOperatorAliasArgs(toolName, args);
      return await executeControlTool(parsed);
    };

    api.registerTool({
      name: "bra_2x4_control",
      label: "BRA 2x4 Control",
      description: "Read-only 2x4 control-plane operations with takeover lease gates.",
      parameters: ControlToolSchema,
      execute: executeControlTool,
    });

    api.registerTool({
      name: "bra",
      label: "BRA Shortcut",
      description:
        "Shortcut wrapper for phrases like 'bra summary', 'bra explain', 'bra file scope', and 'bra log engage 200'.",
      parameters: BraShortcutToolSchema,
      execute: executeBraShortcutTool,
    });

    for (const toolName of [
      "operator.read",
      "operator.write",
      "operator.admin",
      "operator.pairing",
      "operator.approvals",
    ]) {
      api.registerTool({
        name: toolName,
        label: `${toolName} Alias`,
        description: "Compatibility alias for stale 2x4 operator tool names.",
        parameters: OperatorAliasToolSchema,
        execute: async (args: Record<string, unknown>) => await executeOperatorAliasTool(toolName, args),
      });
    }

    const commandApi = api as OpenClawPluginApi & {
      registerCommand?: (definition: {
        name: string;
        description: string;
        acceptsArgs?: boolean;
        requireAuth?: boolean;
        handler: (ctx: { args?: string }) => Promise<{ text: string }> | { text: string };
      }) => void;
    };

    if (typeof commandApi.registerCommand === "function") {
      commandApi.registerCommand({
        name: "bra",
        description:
          "BRA shortcuts. Usage: /bra summary | /bra explain [tail] | /bra file <id> | /bra log [id] [tail] | /bra engage status | /bra call status <callId>",
        acceptsArgs: true,
        requireAuth: true,
        handler: async (ctx) => {
          try {
            const data = await executeBraShortcutTool({ command: ctx.args || "summary" });
            const text = JSON.stringify(data);
            return { text: text.length > 1800 ? `${text.slice(0, 1800)}...` : text };
          } catch (err) {
            return { text: `bra failed: ${err instanceof Error ? err.message : String(err)}` };
          }
        },
      });
    }

    api.registerService({
      id: "openclaw-2x4-control",
      start: async () => {
        api.logger.info("[2x4-control] service started");
      },
      stop: async () => {
        api.logger.info("[2x4-control] service stopped");
      },
    });
  },
};

export default controlPlugin;
