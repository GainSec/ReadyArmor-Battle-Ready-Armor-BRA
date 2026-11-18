#!/usr/bin/env python3
"""Animated ASCII banner playback helpers."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import TextIO


_BANNER_COLOR = "\033[0;32m"
_BANNER_BOLD = "\033[1m"
_BANNER_NC = "\033[0m"


def _banner_dir() -> Path:
    return Path(__file__).resolve().parent / "banner"


def _load_metadata() -> tuple[int, float]:
    frames = _frame_paths()
    frame_count = len(frames)
    frame_delay = 0.05 if frame_count else 0.25
    return frame_count, frame_delay


def _frame_paths() -> list[Path]:
    return sorted(path for path in _banner_dir().glob("frame_*.txt") if path.is_file())


def _load_frames() -> list[str]:
    frames: list[str] = []
    for frame in _frame_paths():
        try:
            frames.append(frame.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return frames


def _banner_hide_cursor(stream: TextIO | None = None) -> None:
    """Write ANSI sequence to hide cursor."""
    out = stream or sys.stdout
    out.write("\033[?25l")
    out.flush()


def _banner_show_cursor(stream: TextIO | None = None) -> None:
    """Write ANSI sequence to show cursor."""
    out = stream or sys.stdout
    out.write("\033[?25h")
    out.flush()


def _banner_home(stream: TextIO | None = None) -> None:
    """Move cursor to top-left corner."""
    out = stream or sys.stdout
    out.write("\033[H")
    out.flush()


def _banner_clear(stream: TextIO | None = None) -> None:
    """Clear terminal viewport and move cursor home."""
    out = stream or sys.stdout
    out.write("\033[2J\033[H")
    out.flush()


def _render_frame(frame: str, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"{_BANNER_COLOR}{_BANNER_BOLD}{frame}{_BANNER_NC}")
    if not frame.endswith("\n"):
        out.write("\n")
    out.flush()


def play_animated_banner(max_loops: int = 0, *, stream: TextIO | None = None, clear_screen: bool = True) -> int:
    """Play banner animation; ``max_loops=0`` means one loop over all frames."""
    out = stream or sys.stdout
    frames = _load_frames()
    frame_count, frame_delay = _load_metadata()

    if not frames:
        out.write(f"No banner frames found in {_banner_dir()}\n")
        return 1

    loops = 1 if max_loops <= 0 else max_loops
    if frame_count and frame_count < len(frames):
        frames = frames[:frame_count]

    try:
        _banner_hide_cursor(out)
        if clear_screen:
            _banner_clear(out)

        for _ in range(loops):
            for frame in frames:
                _banner_home(out)
                _render_frame(frame, out)
                time.sleep(max(frame_delay, 0.0))
    finally:
        _banner_show_cursor(out)
        if clear_screen:
            _banner_clear(out)

    return 0


def show_static_banner(stream: TextIO | None = None) -> str:
    """Render and return first available banner frame."""
    out = stream or sys.stdout
    frames = _load_frames()
    if not frames:
        return ""
    frame = frames[0]
    _render_frame(frame, out)
    return frame


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASCII banner renderer")
    parser.add_argument("--animate", action="store_true", help="Play animated frames")
    parser.add_argument("--loops", type=int, default=1, help="Number of animation loops")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear screen during rendering")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.animate:
        return play_animated_banner(args.loops, clear_screen=not args.no_clear)

    show_static_banner()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
