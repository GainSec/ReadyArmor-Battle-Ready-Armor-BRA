#!/usr/bin/env python3
"""Static agentic-mode banner renderer."""

from __future__ import annotations

import random
import sys

_QUOTES: tuple[str, ...] = (
    "Weapons decide what is possible. Armor decides what endures.",
    "New eras don't come about because of swords. They're created by the people who wield them.",
)

_ART = r"""
 ____        _   _   _        ____                _         _
| __ )  __ _| |_| |_| | ___  |  _ \ ___  __ _  __| |_   _  / \   _ __ _ __ ___   ___  _ __
|  _ \ / _` | __| __| |/ _ \ | |_) / _ \/ _` |/ _` | | | |/ _ \ | '__| '_ ` _ \ / _ \| '__|
| |_) | (_| | |_| |_| |  __/ |  _ <  __/ (_| | (_| | |_| / ___ \| |  | | | | | | (_) | |
|____/ \__,_|\__|\__|_|\___| |_| \_\___|\__,_|\__,_|\__, /_/   \_\_|  |_| |_| |_|\___/|_|
                                                    |___/
""".strip("\n")


def _get_random_quote() -> str:
    """Return one random banner quote."""
    return random.choice(_QUOTES)


def show_agentic_banner() -> str:
    """Return the static banner text with quote and version block."""
    quote = _get_random_quote()
    lines = [
        "",
        _ART,
        "",
        "                    B.R.A. v0.9",
        "",
        "                    Created by GainSec",
        "",
        f'  "{quote}"',
        "",
    ]
    banner = "\n".join(lines)
    print(banner)
    return banner


def main(argv: list[str] | None = None) -> int:
    _ = argv
    show_agentic_banner()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
