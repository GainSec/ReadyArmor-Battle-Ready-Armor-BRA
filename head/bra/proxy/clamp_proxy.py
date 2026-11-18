"""Small local proxy that clamps Anthropic token budgets before LiteLLM."""

from __future__ import annotations

import argparse
import os
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from bra.proxy.token_budget import clamp_anthropic_messages_payload


UPSTREAM_BASE_URL = os.environ.get("BRA_PROXY_UPSTREAM_BASE_URL", "http://127.0.0.1:4001")
MAX_COMPLETION_TOKENS = int(os.environ.get("BRA_PROXY_MAX_COMPLETION_TOKENS", "8192"))

app = FastAPI(title="BRA Proxy Clamp", version="0.1.0")


def _upstream_url(path: str, query: str) -> str:
    base = UPSTREAM_BASE_URL.rstrip("/")
    suffix = f"/{path}" if path else ""
    if query:
        return f"{base}{suffix}?{query}"
    return f"{base}{suffix}"


def _forward_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length"}
    }


async def _stream_response(
    response: httpx.Response,
    client: httpx.AsyncClient,
) -> AsyncIterator[bytes]:
    try:
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        except (httpx.ReadError, httpx.RemoteProtocolError):
            # Downstream disconnects or prematurely closed upstream streams
            # should not crash the wrapper process.
            return
    finally:
        await response.aclose()
        await client.aclose()


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "ok": True,
        "upstream": UPSTREAM_BASE_URL,
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(path: str, request: Request):
    body = await request.body()
    headers = _forward_headers(request)

    if path == "v1/messages" and "application/json" in request.headers.get("content-type", "").lower():
        try:
            payload = await request.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            payload = clamp_anthropic_messages_payload(
                payload,
                max_completion_tokens=MAX_COMPLETION_TOKENS,
            )
            body = JSONResponse(content=payload).body

    client = httpx.AsyncClient(timeout=None)
    upstream = client.build_request(
        request.method,
        _upstream_url(path, request.url.query),
        headers=headers,
        content=body,
    )
    response = await client.send(upstream, stream=True)

    response_headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in {"content-length", "transfer-encoding", "connection", "content-encoding"}
    }
    media_type = response.headers.get("content-type")

    return StreamingResponse(
        _stream_response(response, client),
        status_code=response.status_code,
        headers=response_headers,
        media_type=media_type,
    )


def main() -> None:
    global UPSTREAM_BASE_URL, MAX_COMPLETION_TOKENS
    parser = argparse.ArgumentParser(description="BRA Anthropic clamp proxy")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-base-url", required=True)
    parser.add_argument("--max-completion-tokens", type=int, required=True)
    args = parser.parse_args()

    UPSTREAM_BASE_URL = args.upstream_base_url
    MAX_COMPLETION_TOKENS = args.max_completion_tokens
    os.environ["BRA_PROXY_UPSTREAM_BASE_URL"] = UPSTREAM_BASE_URL
    os.environ["BRA_PROXY_MAX_COMPLETION_TOKENS"] = str(MAX_COMPLETION_TOKENS)

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.listen_port, log_level="info")


if __name__ == "__main__":
    main()
