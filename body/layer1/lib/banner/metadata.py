#!/usr/bin/env python3
"""Banner frame metadata helpers."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class BannerMetadata:
    """Metadata describing banner animation frames."""

    frame_count: int
    frame_delay: float


DEFAULT_FRAME_DELAY = 0.05


def _frames_dir() -> Path:
    return Path(__file__).resolve().parent


def _metadata_json_file() -> Path:
    return _frames_dir() / "metadata.json"


def _parse_metadata_file(path: Path) -> BannerMetadata | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None

    frame_count = raw.get("frame_count")
    frame_delay = raw.get("frame_delay")
    if not isinstance(frame_count, int):
        return None
    try:
        delay = float(frame_delay)
    except (TypeError, ValueError):
        return None
    return BannerMetadata(frame_count=frame_count, frame_delay=delay)


def _count_frames(path: Path) -> int:
    return sum(1 for file in path.glob("frame_*.txt") if file.is_file())


def load_metadata() -> BannerMetadata:
    """Load metadata from `metadata.json`, falling back to frame discovery."""
    parsed = _parse_metadata_file(_metadata_json_file())
    if parsed is not None:
        return parsed

    frame_count = _count_frames(_frames_dir())
    return BannerMetadata(frame_count=frame_count, frame_delay=DEFAULT_FRAME_DELAY if frame_count else 0.25)


def banner_frame_count() -> int:
    """Return number of animation frames."""
    return load_metadata().frame_count


def banner_frame_delay() -> float:
    """Return per-frame delay in seconds."""
    return load_metadata().frame_delay


def main(argv: list[str] | None = None) -> int:
    _ = argv
    print(json.dumps(asdict(load_metadata()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
