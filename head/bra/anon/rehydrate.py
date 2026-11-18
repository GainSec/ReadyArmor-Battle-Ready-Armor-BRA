"""Report re-hydration: replace anon words with real values.

Standalone utility -- runs outside agent context. Used for
generating final deliverable reports with real data.

Usage:
    python -m bra.anon.rehydrate --map .bra/anon_map.json --input REPORT.md --output REPORT-FINAL.md
"""
from __future__ import annotations

import argparse
from pathlib import Path

from bra.anon.mapping import AnonMap


def rehydrate_file(input_path: Path, map_path: Path, output_path: Path) -> None:
    """Read input file, unmask all anon words, write to output."""
    amap = AnonMap(map_path)
    text = input_path.read_text()
    result = amap.unmask(text)
    output_path.write_text(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-hydrate anonymized BRA reports")
    parser.add_argument("--map", required=True, help="Path to anon_map.json")
    parser.add_argument("--input", required=True, help="Input file (anonymized)")
    parser.add_argument("--output", required=True, help="Output file (re-hydrated)")
    args = parser.parse_args()

    rehydrate_file(Path(args.input), Path(args.map), Path(args.output))
    print(f"Re-hydrated: {args.input} -> {args.output}")


if __name__ == "__main__":
    main()
