#!/usr/bin/env python3
"""BRA Verbose Log Viewer — curses TUI for live-tailing verbose.log.

Usage:
    python3 boots/logview.py [--log PATH]

Controls:
    space       Pause / resume auto-scroll
    1-9         Toggle category filters (shown in header)
    a           Show all categories (clear filters)
    /           Search (type pattern, Enter to confirm, n/N for next/prev)
    Esc         Cancel search / clear search highlight
    c           Clear screen buffer
    g / Home    Jump to top
    G / End     Jump to bottom (and resume auto-scroll)
    Up/Down     Scroll line by line
    PgUp/PgDn   Scroll by page
    q           Quit
"""

from __future__ import annotations

import argparse
import curses
import os
import re
import sys
import time
from collections import deque
from pathlib import Path
from threading import Thread, Event

# ──────────────────────────────────────────────────────────────────────
# Categories and their display config
# ──────────────────────────────────────────────────────────────────────

CATEGORIES = [
    ("HTTP", "1"),
    ("WS", "2"),
    ("ENGAGE", "3"),
    ("RUNNER", "4"),
    ("SCRIPT", "5"),
    ("HARNESS", "6"),
    ("GOV", "7"),
    ("BCAST", "8"),
    ("LOG", "9"),
    ("SUBAGENT", "0"),
    ("AGENT", "-"),
    ("PROXY", "="),
]

CAT_NAMES = [c[0] for c in CATEGORIES]

# Map category to curses color pair index
CAT_COLORS = {
    "HTTP": 1,
    "WS": 2,
    "ENGAGE": 3,
    "RUNNER": 4,
    "SCRIPT": 5,
    "HARNESS": 6,
    "GOV": 7,
    "BCAST": 8,
    "LOG": 9,
    "SUBAGENT": 10,
    "AGENT": 11,
    "PROXY": 12,
}

_CAT_RE = re.compile(r"\[(\w+)\]")

MAX_BUFFER = 50000


def _extract_category(line: str) -> str | None:
    """Extract category tag from a log line like [HH:MM:SS.mmm] [ENGAGE] ..."""
    matches = _CAT_RE.findall(line)
    for m in matches:
        if m in CAT_COLORS:
            return m
    return None


# ──────────────────────────────────────────────────────────────────────
# File tailer thread
# ──────────────────────────────────────────────────────────────────────

class LogTailer:
    def __init__(self, path: Path):
        self.path = path
        self.lines: deque[str] = deque(maxlen=MAX_BUFFER)
        self._stop = Event()
        self._new_data = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def wait_for_data(self, timeout: float = 0.1) -> bool:
        result = self._new_data.wait(timeout)
        self._new_data.clear()
        return result

    def _run(self) -> None:
        # Wait for file to exist
        while not self._stop.is_set():
            if self.path.exists():
                break
            time.sleep(0.5)

        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                # Read existing content
                for raw_line in f:
                    self.lines.append(raw_line.rstrip("\n"))
                self._new_data.set()

                # Tail new content
                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        self.lines.append(line.rstrip("\n"))
                        self._new_data.set()
                    else:
                        time.sleep(0.05)
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────
# TUI
# ──────────────────────────────────────────────────────────────────────

def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    # Category colors: pair index -> (fg, bg)
    curses.init_pair(1, curses.COLOR_CYAN, -1)       # HTTP
    curses.init_pair(2, curses.COLOR_MAGENTA, -1)     # WS
    curses.init_pair(3, curses.COLOR_YELLOW, -1)      # ENGAGE
    curses.init_pair(4, curses.COLOR_GREEN, -1)       # RUNNER
    curses.init_pair(5, curses.COLOR_RED, -1)          # SCRIPT
    curses.init_pair(6, curses.COLOR_BLUE, -1)         # HARNESS
    curses.init_pair(7, curses.COLOR_RED, -1)           # GOV (bright via bold)
    curses.init_pair(8, curses.COLOR_MAGENTA, -1)      # BCAST (bright via bold)
    curses.init_pair(9, 8, -1)                          # LOG (gray = color 8)
    curses.init_pair(10, curses.COLOR_CYAN, -1)          # SUBAGENT (bright cyan via bold)
    curses.init_pair(11, curses.COLOR_GREEN, -1)         # AGENT (bright green via bold)
    curses.init_pair(12, curses.COLOR_CYAN, -1)           # PROXY (cyan, bold via cat check)
    # Search highlight
    curses.init_pair(20, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    # Status bar
    curses.init_pair(21, curses.COLOR_BLACK, curses.COLOR_WHITE)
    # Filter active indicator
    curses.init_pair(22, curses.COLOR_BLACK, curses.COLOR_GREEN)
    # Filter inactive
    curses.init_pair(23, curses.COLOR_WHITE, -1)


def _run_tui(stdscr, log_path: Path) -> None:
    _init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    tailer = LogTailer(log_path)
    tailer.start()

    # State
    paused = False
    auto_scroll = True
    scroll_offset = 0  # offset from bottom (0 = at bottom)
    active_filters: set[str] = set()  # empty = show all
    search_pattern = ""
    search_re: re.Pattern | None = None
    search_mode = False
    search_input = ""
    search_matches: list[int] = []
    search_current = -1
    word_wrap = True

    def _filtered_lines() -> list[tuple[int, str]]:
        """Return (original_index, line) pairs that pass the filter."""
        result = []
        snapshot = list(tailer.lines)
        for i, line in enumerate(snapshot):
            if line.startswith("[FILE-ONLY]"):
                continue
            cat = _extract_category(line)
            if active_filters and cat and cat not in active_filters:
                continue
            if cat is None and active_filters:
                # Continuation lines (indented fields) — show if previous visible
                if result:
                    result.append((i, line))
                continue
            result.append((i, line))
        return result

    def _update_search_matches(filtered: list[tuple[int, str]]) -> None:
        nonlocal search_matches, search_current
        if not search_re:
            search_matches = []
            search_current = -1
            return
        search_matches = [
            idx for idx, (_, line) in enumerate(filtered)
            if search_re.search(line)
        ]
        if search_matches and search_current < 0:
            search_current = 0

    try:
        while True:
            tailer.wait_for_data(0.05)
            height, width = stdscr.getmaxyx()
            if height < 4 or width < 20:
                time.sleep(0.1)
                continue

            header_h = 2
            status_h = 1
            view_h = height - header_h - status_h

            filtered = _filtered_lines()

            if search_re:
                _update_search_matches(filtered)

            # Build visual rows: each filtered line may wrap into multiple rows
            # visual_rows = list of (filtered_index, line_text, cat, attr)
            # When word_wrap is off, each filtered line = 1 visual row (truncated)
            usable_w = max(1, width - 1)
            visual_rows: list[tuple[int, str, str | None, int]] = []
            for fidx, (_, line) in enumerate(filtered):
                cat = _extract_category(line)
                color_pair = CAT_COLORS.get(cat, 0) if cat else 0
                row_attr = curses.color_pair(color_pair)
                if cat in ("GOV", "BCAST", "SUBAGENT", "AGENT", "PROXY"):
                    row_attr |= curses.A_BOLD

                if word_wrap and len(line) > usable_w:
                    # Wrap into chunks
                    pos = 0
                    while pos < len(line):
                        visual_rows.append((fidx, line[pos:pos + usable_w], cat, row_attr))
                        pos += usable_w
                else:
                    visual_rows.append((fidx, line, cat, row_attr))

            total = len(visual_rows)

            # Auto-scroll
            if auto_scroll and not paused:
                scroll_offset = 0

            # Compute visible window
            if scroll_offset > max(0, total - view_h):
                scroll_offset = max(0, total - view_h)
            start_line = max(0, total - view_h - scroll_offset)
            end_line = min(total, start_line + view_h)

            stdscr.erase()

            # ── Header ──
            wrap_indicator = " [W]rap:ON " if word_wrap else " [W]rap:OFF"
            header = " BRA VERBOSE LOG VIEWER " + wrap_indicator
            stdscr.attron(curses.color_pair(21) | curses.A_BOLD)
            stdscr.addnstr(0, 0, header.center(width), width)
            stdscr.attroff(curses.color_pair(21) | curses.A_BOLD)

            # Filter indicators row
            x = 0
            for cat_name, key_str in CATEGORIES:
                is_active = not active_filters or cat_name in active_filters
                label = f" {key_str}:{cat_name} "
                pair = 22 if (cat_name in active_filters) else 23
                row_attr = curses.color_pair(pair)
                if not active_filters:
                    row_attr = curses.color_pair(CAT_COLORS[cat_name])
                if x + len(label) < width:
                    try:
                        stdscr.addnstr(1, x, label, width - x, row_attr)
                    except curses.error:
                        pass
                x += len(label)

            # ── Log lines ──
            for row_idx, vrow_idx in enumerate(range(start_line, end_line)):
                if row_idx >= view_h:
                    break
                fidx, display, cat, row_attr = visual_rows[vrow_idx]
                y = header_h + row_idx

                # Check if this line's parent filtered index is a search match
                is_match = search_re and fidx in search_matches

                display = display[:usable_w]

                try:
                    if is_match and search_re:
                        # Render with search highlights
                        col = 0
                        for m in search_re.finditer(display):
                            if m.start() > col:
                                stdscr.addnstr(y, col, display[col:m.start()], width - col, row_attr)
                            hl_attr = curses.color_pair(20) | curses.A_BOLD
                            if m.start() < width:
                                stdscr.addnstr(y, m.start(), display[m.start():m.end()], width - m.start(), hl_attr)
                            col = m.end()
                        if col < len(display):
                            stdscr.addnstr(y, col, display[col:], width - col, row_attr)
                    else:
                        stdscr.addnstr(y, 0, display, usable_w, row_attr)
                except curses.error:
                    pass

            # ── Status bar ──
            status_y = height - 1
            if search_mode:
                status_text = f" /{search_input}█"
            else:
                parts = []
                parts.append("PAUSED" if paused else "LIVE")
                parts.append(f"Lines: {len(filtered)}")
                if active_filters:
                    parts.append(f"Filter: {','.join(sorted(active_filters))}")
                if search_pattern:
                    match_info = f"{search_current + 1}/{len(search_matches)}" if search_matches else "0/0"
                    parts.append(f"Search: '{search_pattern}' [{match_info}]")
                if scroll_offset > 0:
                    parts.append(f"Scroll: +{scroll_offset}")
                status_text = " | ".join(parts)
                status_text += "  [q]uit [space]pause [w]rap [0-9,-]filter [a]ll [/]search [g/G]top/bottom"

            try:
                stdscr.attron(curses.color_pair(21))
                stdscr.addnstr(status_y, 0, status_text.ljust(width), width, curses.color_pair(21))
                stdscr.attroff(curses.color_pair(21))
            except curses.error:
                pass

            stdscr.refresh()

            # ── Input handling ──
            try:
                key = stdscr.getch()
            except Exception:
                key = -1

            if key == -1:
                continue

            if search_mode:
                if key == 27:  # Escape
                    search_mode = False
                    search_input = ""
                elif key in (curses.KEY_ENTER, 10, 13):
                    search_mode = False
                    search_pattern = search_input
                    search_input = ""
                    try:
                        search_re = re.compile(search_pattern, re.IGNORECASE) if search_pattern else None
                    except re.error:
                        search_re = re.compile(re.escape(search_pattern), re.IGNORECASE)
                    search_current = -1
                    _update_search_matches(filtered)
                    # Jump to first match
                    if search_matches:
                        search_current = 0
                        target = search_matches[0]
                        scroll_offset = max(0, total - target - view_h // 2)
                        auto_scroll = False
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    search_input = search_input[:-1]
                elif 32 <= key <= 126:
                    search_input += chr(key)
                continue

            if key == ord("q"):
                break
            elif key == ord(" "):
                paused = not paused
                if not paused:
                    auto_scroll = True
                    scroll_offset = 0
            elif key == ord("w"):
                word_wrap = not word_wrap
                scroll_offset = 0
            elif key == ord("a"):
                active_filters.clear()
            elif key == ord("c"):
                tailer.lines.clear()
                scroll_offset = 0
            elif key == ord("/"):
                search_mode = True
                search_input = ""
            elif key == 27:  # Escape — clear search
                search_pattern = ""
                search_re = None
                search_matches = []
                search_current = -1
            elif key == ord("n") and search_matches:
                search_current = (search_current + 1) % len(search_matches)
                target = search_matches[search_current]
                scroll_offset = max(0, total - target - view_h // 2)
                auto_scroll = False
            elif key == ord("N") and search_matches:
                search_current = (search_current - 1) % len(search_matches)
                target = search_matches[search_current]
                scroll_offset = max(0, total - target - view_h // 2)
                auto_scroll = False
            elif key == ord("g") or key == curses.KEY_HOME:
                scroll_offset = max(0, total - view_h)
                auto_scroll = False
            elif key == ord("G") or key == curses.KEY_END:
                scroll_offset = 0
                auto_scroll = True
            elif key == curses.KEY_UP:
                scroll_offset = min(scroll_offset + 1, max(0, total - view_h))
                auto_scroll = False
            elif key == curses.KEY_DOWN:
                scroll_offset = max(0, scroll_offset - 1)
                if scroll_offset == 0:
                    auto_scroll = True
            elif key == curses.KEY_PPAGE:
                scroll_offset = min(scroll_offset + view_h, max(0, total - view_h))
                auto_scroll = False
            elif key == curses.KEY_NPAGE:
                scroll_offset = max(0, scroll_offset - view_h)
                if scroll_offset == 0:
                    auto_scroll = True
            else:
                # Category toggle keys (1-9, 0, -)
                for cat_name, key_str in CATEGORIES:
                    if key == ord(key_str):
                        if cat_name in active_filters:
                            active_filters.discard(cat_name)
                        else:
                            active_filters.add(cat_name)
                        break

    finally:
        tailer.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="BRA Verbose Log Viewer")
    parser.add_argument(
        "--log",
        default=None,
        help="Path to verbose.log (default: auto-detect from .bra/logs/verbose.log)",
    )
    args = parser.parse_args()

    if args.log:
        log_path = Path(args.log)
    else:
        # Search relative to both the script's parent dir and CWD
        script_root = Path(__file__).parent.parent
        candidates = [
            script_root / ".bra" / "logs" / "verbose.log",
            script_root / "body" / ".bra" / "logs" / "verbose.log",
            Path(".bra") / "logs" / "verbose.log",
            Path("body") / ".bra" / "logs" / "verbose.log",
        ]
        # Pick the existing file with the newest mtime
        found = [(c, c.stat().st_mtime) for c in candidates if c.exists()]
        if found:
            found.sort(key=lambda x: x[1], reverse=True)
            log_path = found[0][0]
        else:
            log_path = candidates[0]
            print(f"Waiting for log file: {log_path}")
            print("Start the server with: python3 boots/gui-debug.py")

    try:
        curses.wrapper(lambda stdscr: _run_tui(stdscr, log_path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
