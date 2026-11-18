import { WebSocket } from "ws";
import { convertPcmToMulaw8k } from "./telephony-audio.js";
import { VibeVoiceConfigSchema, type VibeVoiceConfig } from "./config.js";
import type { TelephonyTtsProvider } from "./telephony-tts.js";

type Logger = {
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
};

function wsToHttpUrl(url: string): string {
  if (url.startsWith("ws://")) {
    return `http://${url.slice(5)}`;
  }
  if (url.startsWith("wss://")) {
    return `https://${url.slice(6)}`;
  }
  return url;
}

function buildStreamUrl(
  baseUrl: string,
  text: string,
  options: VibeVoiceConfig,
  voiceOverride?: string,
): string {
  const url = new URL(baseUrl);
  url.searchParams.set("text", text);
  url.searchParams.set("voice", voiceOverride || options.voice);
  if (options.cfg) {
    url.searchParams.set("cfg", options.cfg);
  }
  if (options.steps) {
    url.searchParams.set("steps", options.steps);
  }
  return url.toString();
}

export function createVibeVoiceTelephonyTtsProvider(params: {
  config: VibeVoiceConfig;
  logger?: Logger;
}): TelephonyTtsProvider {
  const log = params.logger ?? {
    info: console.log,
    warn: console.warn,
    error: console.error,
  };

  const validated = VibeVoiceConfigSchema.parse(params.config);
  const streamBase = wsToHttpUrl(validated.wsBaseUrl);

  return {
    synthesizeForTelephony: async (text: string, options?: { voice?: string }): Promise<Buffer> => {
      if (!text?.trim()) {
        throw new Error("No text provided for VibeVoice synthesis");
      }

      const streamUrl = buildStreamUrl(
        streamBase,
        text,
        validated,
        options?.voice,
      );
      const chunks: Buffer[] = [];
      let completed = false;

      const payload = await new Promise<Buffer>((resolve, reject) => {
        const ws = new WebSocket(streamUrl);
        const timer = setTimeout(() => {
          ws.terminate();
          reject(new Error(`VibeVoice request timed out after ${validated.timeoutMs}ms`));
        }, validated.timeoutMs);

        const finish = (err?: unknown) => {
          clearTimeout(timer);
          ws.removeAllListeners();
          if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) {
            ws.close();
          }
          if (err) {
            reject(err);
          } else {
            resolve(Buffer.concat(chunks));
          }
        };

        ws.on("open", () => {
          log.info(`[voice-call-bra] VibeVoice stream opened (${streamBase})`);
        });

        ws.on("message", (data, isBinary) => {
          if (isBinary) {
            chunks.push(Buffer.from(data as Buffer));
            return;
          }

          if (typeof data === "string") {
            try {
              const evt = JSON.parse(data);
              if (evt?.event === "backend_stream_complete") {
                completed = true;
                if (chunks.length === 0) {
                  finish(new Error("VibeVoice stream completed with no audio"));
                  return;
                }
                finish(undefined);
              }
            } catch {
              // ignore non-JSON control events
            }
          }
        });

        ws.on("close", () => {
          if (!completed && chunks.length === 0) {
            finish(new Error("VibeVoice stream closed before completion"));
            return;
          }
          if (!completed) {
            // Treat close as completion when audio exists, to avoid flakiness from servers that close after final chunk.
            finish(undefined);
            return;
          }
        });

        ws.on("error", (error) => {
          finish(error);
        });
      });

      const sampleRate = 24000;
      return convertPcmToMulaw8k(payload, sampleRate);
    },
  };
}
