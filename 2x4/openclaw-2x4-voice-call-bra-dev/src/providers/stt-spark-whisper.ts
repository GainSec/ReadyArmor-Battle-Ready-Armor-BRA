import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { type RealtimeSTTSession, type RealtimeSTTConfig } from "./stt-openai-realtime.js";

/**
 * Configuration for local Spark Whisper STT provider.
 */
export interface SparkWhisperSTTConfig extends Omit<RealtimeSTTConfig, "apiKey" | "model"> {
  /** Command to run Python */
  pythonPath?: string;
  /** Whisper model name (default: tiny.en) */
  model?: string;
  /** Optional language hint */
  language?: string;
  /** Seconds of silence (at 20ms frames) before finalizing transcript */
  silenceDurationMs?: number;
  /** Minimum speaking duration in ms before running STT */
  minSpeechDurationMs?: number;
  /** Max wall time for one transcription command */
  timeoutMs?: number;
  /** Optional custom script path */
  scriptPath?: string;
}

/**
 * Provider factory for on-host/local Whisper STT sessions.
 */
export class SparkWhisperSTTProvider {
  readonly name = "spark-whisper";

  constructor(private readonly config: SparkWhisperSTTConfig) {
    if (!this.config.pythonPath) {
      this.config.pythonPath = "python3";
    }
    if (!this.config.scriptPath) {
      const dir = path.dirname(fileURLToPath(import.meta.url));
      this.config.scriptPath = path.join(dir, "../../scripts/stt-spark-whisper.py");
    }
    if (!this.config.language) {
      this.config.language = "en";
    }
  }

  createSession(): RealtimeSTTSession {
    return new SparkWhisperSTTSessionImpl({
      pythonPath: this.config.pythonPath || "python3",
      model: this.config.model || "tiny.en",
      language: this.config.language || "en",
      silenceDurationMs: this.config.silenceDurationMs || 800,
      minSpeechDurationMs: this.config.minSpeechDurationMs || 250,
      timeoutMs: this.config.timeoutMs || 120000,
      scriptPath: this.config.scriptPath,
    });
  }
}

class SparkWhisperSTTSessionImpl implements RealtimeSTTSession {
  private readonly frameMs = 20;
  private buffer: Buffer[] = [];
  private lastTranscript = "";
  private lastPartial = "";

  private inSpeech = false;
  private voicedFrames = 0;
  private silentFrames = 0;
  private finalizing = false;
  private partialInFlight = false;
  private lastPartialAt = 0;

  private readonly silenceFramesThreshold: number;
  private readonly minSpeechFrames: number;
  private readonly partialIntervalMs: number;
  private readonly partialMinFrames: number;

  private onTranscriptCallback: ((transcript: string) => void) | null = null;
  private onPartialCallback: ((partial: string) => void) | null = null;
  private onSpeechStartCallback: (() => void) | null = null;

  private closed = false;

  constructor(private readonly cfg: {
    pythonPath: string;
    model: string;
    language: string;
    silenceDurationMs: number;
    minSpeechDurationMs: number;
    timeoutMs: number;
    scriptPath: string;
  }) {
    this.silenceFramesThreshold = Math.max(1, Math.ceil(cfg.silenceDurationMs / this.frameMs));
    this.minSpeechFrames = Math.max(1, Math.ceil(cfg.minSpeechDurationMs / this.frameMs));
    // Rolling partial STT: keep this conservative to avoid overloading local inference.
    this.partialIntervalMs = 350;
    this.partialMinFrames = Math.max(1, Math.ceil(500 / this.frameMs));
  }

  async connect(): Promise<void> {
    this.closed = false;
  }

  sendAudio(muLawData: Buffer): void {
    if (this.closed) {
      return;
    }

    this.buffer.push(muLawData);
    const silent = this.isSilence(muLawData);

    if (!this.inSpeech) {
      if (!silent) {
        this.voicedFrames += 1;
      } else {
        this.voicedFrames = 0;
      }

      // Require contiguous voiced frames before declaring speech start.
      if (this.voicedFrames >= this.minSpeechFrames) {
        this.inSpeech = true;
        this.voicedFrames = 0;
        this.onSpeechStartCallback?.();
      }
    }

    if (this.inSpeech) {
      if (silent) {
        this.silentFrames += 1;
      } else {
        this.silentFrames = 0;
      }

      void this.maybeEmitPartial();

      if (this.silentFrames >= this.silenceFramesThreshold) {
        void this.finalizeUtterance("vad");
      }
    }
  }

  private async finalizeUtterance(_source: string): Promise<void> {
    if (this.finalizing || !this.inSpeech) {
      return;
    }

    const payload = this.consumeBuffer();
    this.finalizing = true;
    this.inSpeech = false;
    this.voicedFrames = 0;
    this.silentFrames = 0;

    try {
      const transcript = (await this.transcribe(payload)).trim();
      if (transcript) {
        this.lastTranscript = transcript;
        this.onTranscriptCallback?.(transcript);
      }
    } catch (err) {
      console.error(
        "[spark-whisper] transcription failed:",
        err instanceof Error ? err.message : String(err),
      );
    } finally {
      this.finalizing = false;
    }
  }

  onPartial(callback: (partial: string) => void): void {
    this.onPartialCallback = callback;
  }

  onTranscript(callback: (transcript: string) => void): void {
    this.onTranscriptCallback = callback;
  }

  onSpeechStart(callback: () => void): void {
    this.onSpeechStartCallback = callback;
  }

  async waitForTranscript(timeoutMs = 30000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.lastTranscript) {
        const t = this.lastTranscript;
        this.lastTranscript = "";
        return t;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error("Transcript timeout");
  }

  close(): void {
    this.closed = true;
    void this.finalizeUtterance("close");
    this.buffer = [];
    this.inSpeech = false;
    this.voicedFrames = 0;
    this.lastPartial = "";
    this.partialInFlight = false;
    this.lastPartialAt = 0;
  }

  isConnected(): boolean {
    return !this.closed;
  }

  private consumeBuffer(): Buffer {
    const data = Buffer.concat(this.buffer);
    this.buffer = [];
    return data;
  }

  private isSilence(audio: Buffer): boolean {
    if (!audio.length) {
      return true;
    }

    const len = Math.min(audio.length, 160);
    if (!len) {
      return true;
    }

    let sumSq = 0;
    for (let i = 0; i < len; i++) {
      const sample = mulawToPcmSample(audio[i]);
      sumSq += sample * sample;
    }

    const rms = Math.sqrt(sumSq / len);
    const threshold = 400;
    return rms < threshold;
  }

  private async transcribe(audio: Buffer): Promise<string> {
    if (!audio.length) {
      return "";
    }

    const tmpDir = await mkdtemp(path.join(tmpdir(), "spark-whisper-"));
    const inPath = path.join(tmpDir, `${randomUUID()}.mulaw`);
    await writeFile(inPath, audio);

    try {
      const transcript = await runCommand(
        this.cfg.pythonPath,
        [
          this.cfg.scriptPath,
          "--input",
          inPath,
          "--model",
          this.cfg.model,
          "--language",
          this.cfg.language,
        ],
        this.cfg.timeoutMs,
      );
      return transcript;
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  }

  private async maybeEmitPartial(): Promise<void> {
    if (!this.onPartialCallback || this.finalizing || this.closed) {
      return;
    }

    if (this.partialInFlight) {
      return;
    }

    if (this.buffer.length < this.partialMinFrames) {
      return;
    }

    const now = Date.now();
    if (now - this.lastPartialAt < this.partialIntervalMs) {
      return;
    }

    const snapshot = Buffer.concat(this.buffer);
    if (!snapshot.length) {
      return;
    }

    this.partialInFlight = true;
    this.lastPartialAt = now;
    try {
      const partial = (await this.transcribe(snapshot)).trim();
      if (!partial || partial === this.lastPartial) {
        return;
      }
      this.lastPartial = partial;
      this.onPartialCallback?.(partial);
    } catch {
      // Keep partial STT best-effort. Final transcript path remains authoritative.
    } finally {
      this.partialInFlight = false;
    }
  }
}

function mulawToPcmSample(uVal: number): number {
  let u = (~uVal) & 0xff;
  const sign = u & 0x80;
  u &= 0x7f;

  const exponent = (u >> 4) & 0x07;
  const mantissa = u & 0x0f;
  let sample = (((mantissa << 4) + 0x08) << exponent) - 0x84;

  if (sign) {
    sample = -sample;
  }

  return sample;
}

function runCommand(command: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`STT command timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || `whisper command exited with code ${code}`));
      }
    });
  });
}
