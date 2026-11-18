#!/usr/bin/env python3
"""Transcribe mu-law (G.711 u-law) audio chunks with local Whisper backends.

Default behavior prefers whisper.cpp CLI for low latency on Spark. If whisper.cpp
is unavailable, it falls back to the Python openai-whisper package.
"""

from __future__ import annotations

import argparse
try:
    import audioop  # type: ignore
except Exception:  # pragma: no cover - Python builds without audioop (e.g. 3.13+)
    audioop = None
import os
import shutil
import subprocess
import tempfile
import uuid
import wave
from pathlib import Path
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


_PYTHON_MODELS: dict[str, object] = {}


def _candidate_whisper_cli(user_cli: str | None) -> list[Path]:
    candidates: list[Path] = []
    if user_cli:
        candidates.append(Path(user_cli).expanduser())
    env_cli = os.environ.get("WHISPER_CPP_CLI", "")
    if env_cli:
        candidates.append(Path(env_cli).expanduser())
    candidates.extend(
        [
            Path("~/work/whisper.cpp/build/bin/whisper-cli").expanduser(),
            Path("~/whisper.cpp/build/bin/whisper-cli").expanduser(),
        ]
    )
    which_cli = shutil.which("whisper-cli")
    if which_cli:
        candidates.append(Path(which_cli))
    return candidates


def _resolve_whisper_cli(user_cli: str | None) -> Path | None:
    for candidate in _candidate_whisper_cli(user_cli):
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _resolve_whisper_model(model: str, model_dir: str | None) -> Path | None:
    model_path = Path(model).expanduser()
    if model_path.exists():
        return model_path

    base_dirs: list[Path] = []
    if model_dir:
        base_dirs.append(Path(model_dir).expanduser())
    base_dirs.extend(
        [
            Path("~/work/whisper.cpp/models").expanduser(),
            Path("~/whisper.cpp/models").expanduser(),
        ]
    )

    names = [model]
    if not model.endswith(".bin"):
        names.append(f"ggml-{model}.bin")
    if model.startswith("ggml-") and not model.endswith(".bin"):
        names.append(f"{model}.bin")

    for directory in base_dirs:
        for name in names:
            candidate = directory / name
            if candidate.exists():
                return candidate

    return None


def _run_whisper_cpp(
    cli_path: Path,
    model_path: Path,
    wav_path: Path,
    language: str,
) -> str:
    cmd = [
        str(cli_path),
        "-m",
        str(model_path),
        "-f",
        str(wav_path),
        "-l",
        language,
        "-nt",
        "-np",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"whisper.cpp exited with code {proc.returncode}")
    return proc.stdout.strip()


def _resolve_server_url(user_url: str | None) -> str | None:
    value = (user_url or "").strip() or os.environ.get("WHISPER_CPP_SERVER_URL", "").strip()
    if not value:
        return None
    parsed = urllib_parse.urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError(f"invalid whisper server URL scheme: {value}")
    if not parsed.path:
        parsed = parsed._replace(path="/inference")
    return urllib_parse.urlunparse(parsed)


def _multipart_body(fields: list[tuple[str, str]], file_field: str, file_path: Path) -> tuple[bytes, str]:
    boundary = f"----openclaw-{uuid.uuid4().hex}"
    chunks: list[bytes] = []

    for key, value in fields:
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        chunks.append(value.encode("utf-8"))
        chunks.append(b"\r\n")

    payload = file_path.read_bytes()
    chunks.append(f"--{boundary}\r\n".encode("utf-8"))
    chunks.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="audio.wav"\r\n'.encode("utf-8")
    )
    chunks.append(b"Content-Type: audio/wav\r\n\r\n")
    chunks.append(payload)
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(chunks)
    return body, boundary


def _run_whisper_server(server_url: str, wav_path: Path, language: str) -> str:
    body, boundary = _multipart_body(
        fields=[
            ("language", language),
            ("temperature", "0.0"),
            ("temperature_inc", "0.0"),
            ("response_format", "text"),
        ],
        file_field="file",
        file_path=wav_path,
    )

    req = urllib_request.Request(
        server_url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return text.strip()
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"whisper-server HTTP {exc.code}: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"whisper-server request failed: {exc}") from exc


def _load_python_model(name: str, device: str):
    key = f"{name}:{device}"
    if key in _PYTHON_MODELS:
        return _PYTHON_MODELS[key]
    import whisper  # lazy import for fallback-only path

    model = whisper.load_model(name, device=device)
    _PYTHON_MODELS[key] = model
    return model


def _run_python_whisper(
    wav_path: Path,
    model_name: str,
    language: str,
    device: str,
    fp16: bool,
) -> str:
    import torch  # lazy import for fallback-only path

    if device == "cuda" and not torch.cuda.is_available():
        device = "cpu"
    model = _load_python_model(model_name, device)
    result = model.transcribe(
        str(wav_path),
        language=language,
        fp16=bool(fp16 and device == "cuda"),
        task="transcribe",
        condition_on_previous_text=False,
    )
    return (result.get("text") or "").strip()


def _mulaw_to_pcm16_fallback(mulaw_bytes: bytes) -> bytes:
    out = bytearray(len(mulaw_bytes) * 2)
    j = 0
    for b in mulaw_bytes:
        u = (~b) & 0xFF
        sign = u & 0x80
        u &= 0x7F
        exponent = (u >> 4) & 0x07
        mantissa = u & 0x0F
        sample = (((mantissa << 4) + 0x08) << exponent) - 0x84
        if sign:
            sample = -sample
        out[j : j + 2] = int(sample).to_bytes(2, "little", signed=True)
        j += 2
    return bytes(out)


def _write_mulaw_to_wav(mulaw_bytes: bytes, wav_path: Path) -> None:
    if audioop is not None:
        pcm = audioop.ulaw2lin(mulaw_bytes, 2)
    else:
        pcm = _mulaw_to_pcm16_fallback(mulaw_bytes)
    with wave.open(str(wav_path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(pcm)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to raw 8kHz mu-law payload")
    parser.add_argument("--model", default="tiny.en", help="Model name or model file path")
    parser.add_argument("--language", default="en")
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--fp16", action="store_true")
    parser.add_argument(
        "--backend",
        choices=("auto", "whispercpp", "python"),
        default="auto",
        help="auto prefers whisper.cpp, then falls back to python-whisper",
    )
    parser.add_argument("--whisper-cli", default="", help="Path to whisper.cpp CLI binary")
    parser.add_argument("--model-dir", default="", help="Directory containing ggml model files")
    parser.add_argument(
        "--server-url",
        default="",
        help="Optional whisper-server URL (defaults from WHISPER_CPP_SERVER_URL)",
    )
    args = parser.parse_args()

    inp = Path(args.input)
    data = inp.read_bytes()
    if not data:
        print("", end="")
        return 0

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        wav_path = Path(tmp.name)

    try:
        _write_mulaw_to_wav(data, wav_path)

        first_error: Exception | None = None

        if args.backend in ("auto", "whispercpp"):
            server_url = _resolve_server_url(args.server_url or None)
            if server_url:
                try:
                    text = _run_whisper_server(server_url, wav_path, args.language)
                    print(text, end="")
                    return 0
                except Exception as exc:
                    first_error = exc

            cli = _resolve_whisper_cli(args.whisper_cli or None)
            model_path = _resolve_whisper_model(args.model, args.model_dir or None)
            if cli and model_path:
                try:
                    text = _run_whisper_cpp(cli, model_path, wav_path, args.language)
                    print(text, end="")
                    return 0
                except Exception as exc:
                    if first_error is None:
                        first_error = exc
            elif first_error is None:
                first_error = RuntimeError(
                    "whisper.cpp unavailable: missing CLI or model "
                    f"(cli={cli}, model={model_path}, model_arg={args.model})"
                )

            if args.backend == "whispercpp" and first_error is not None:
                raise first_error

        if args.backend in ("auto", "python"):
            text = _run_python_whisper(
                wav_path=wav_path,
                model_name=args.model,
                language=args.language,
                device=args.device,
                fp16=args.fp16,
            )
            print(text, end="")
            return 0

        if first_error is not None:
            raise first_error
        raise RuntimeError("no backend selected")
    except Exception as exc:
        print(f"[stt-spark-whisper] error: {exc}", file=os.sys.stderr)
        return 1
    finally:
        try:
            wav_path.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
