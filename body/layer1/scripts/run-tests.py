#!/usr/bin/env python3
"""Native test runner for Python test suites in this repository."""

from __future__ import annotations

import argparse
from fnmatch import fnmatch
from pathlib import Path
import re
import subprocess
import sys
import time


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _find_tests_root(body_root: Path) -> Path | None:
    candidates = (body_root / "tests", body_root.parent / "tests")
    for path in candidates:
        if path.is_dir():
            return path
    return None


def _discover_tests(tests_root: Path) -> list[Path]:
    return sorted(p for p in tests_root.rglob("test*.py") if p.is_file())


def _count_test_cases(files: list[Path]) -> int:
    """Count individual test methods/functions in test files."""
    count = 0
    pattern = re.compile(r"^\s+def (test_\w+|test \w+)\s*\(", re.MULTILINE)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            count += len(pattern.findall(text))
        except OSError:
            pass
    return count


def _count_tests_in_dir(directory: Path) -> int:
    """Count test files in a directory."""
    if not directory.is_dir():
        return 0
    return sum(1 for _ in directory.rglob("test*.py") if _.is_file())


def _apply_filters(paths: list[Path], args: argparse.Namespace) -> list[Path]:
    result = list(paths)

    if args.unit:
        result = [p for p in result if "unit" in p.as_posix().lower()]

    if args.smoke:
        result = [p for p in result if "smoke" in p.as_posix().lower()]

    if args.integration:
        result = [p for p in result if "integration" in p.as_posix().lower()]

    if args.category:
        needle = args.category.lower()
        result = [p for p in result if needle in p.as_posix().lower()]

    if args.file:
        patterns = args.file

        def matches(path: Path) -> bool:
            rel = path.as_posix()
            name = path.name
            return any(fnmatch(rel, f"*{pat}*") or fnmatch(name, f"*{pat}*") for pat in patterns)

        result = [p for p in result if matches(p)]

    if args.filter:
        pattern = re.compile(args.filter)
        result = [p for p in result if pattern.search(p.as_posix())]

    return result


def _parse_unittest_output(output: str) -> tuple[int, int, int]:
    """Parse unittest output to extract pass/fail/error counts.

    Returns (total, passed, failed).
    """
    # Look for the summary line: "Ran N test(s) in X.XXXs"
    ran_match = re.search(r"Ran (\d+) test", output)
    total = int(ran_match.group(1)) if ran_match else 0

    # Check for failures/errors: "FAILED (failures=N, errors=M)"
    failed = 0
    fail_match = re.search(r"failures=(\d+)", output)
    if fail_match:
        failed += int(fail_match.group(1))
    err_match = re.search(r"errors=(\d+)", output)
    if err_match:
        failed += int(err_match.group(1))

    passed = max(0, total - failed)
    return total, passed, failed


def _run_unittest(repo_root: Path, files: list[Path], verbose: bool) -> tuple[int, int, int, int]:
    """Run unittest and return (exit_code, total, passed, failed)."""
    command = [sys.executable, "-m", "unittest"]
    if verbose:
        command.append("-v")
    command.extend(str(path.relative_to(repo_root)) for path in files)

    completed = subprocess.run(
        command, cwd=repo_root,
        capture_output=True, text=True,
    )

    # Print the actual output
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="")

    total, passed, failed = _parse_unittest_output(
        completed.stdout + completed.stderr
    )

    return completed.returncode, total, passed, failed


def _print_header() -> None:
    print("")
    print("═" * 64)
    print("                    B.R.A. Test Runner")
    print("═" * 64)
    print("")


def _print_summary(total: int, passed: int, failed: int, duration: float) -> None:
    print("")
    print("═" * 64)
    if failed == 0:
        print(f"  {passed}/{total} tests passed ({duration:.1f}s)")
    else:
        print(f"  {passed}/{total} tests passed, {failed} failed ({duration:.1f}s)")
    print("═" * 64)
    print("")


def _show_help() -> None:
    print(
        "Usage: ./layer1/scripts/run-tests.py [OPTIONS] [TEST_FILE]\n\n"
        "Options:\n"
        "  --all             Run all tests (default)\n"
        "  --unit            Run unit tests only\n"
        "  --integration     Run integration tests only\n"
        "  --category=NAME   Run tests tagged with @category NAME\n"
        "  --file=PATTERN    Run test files matching PATTERN\n"
        "  --verbose, -v     Show verbose output\n"
        "  --tap             Output in TAP-compatible format\n"
        "  --filter REGEX    Only run tests matching REGEX\n"
        "  --help, -h        Show this help\n\n"
        "Examples:\n"
        "  ./layer1/scripts/run-tests.py                        # Run all tests\n"
        "  ./layer1/scripts/run-tests.py --unit                 # Run unit tests\n"
        "  ./layer1/scripts/run-tests.py --category=governance  # Run governance tests\n"
        "  ./layer1/scripts/run-tests.py --file=killswitch      # Run files matching \"killswitch\"\n"
        "  ./layer1/scripts/run-tests.py --verbose              # Verbose output\n"
        "  ./layer1/scripts/run-tests.py tests/test_file.py     # Single file\n"
        "  ./layer1/scripts/run-tests.py --filter \"STOP\"        # Tests matching \"STOP\"\n\n"
        "Requirements:\n"
        "  brew install bats-core\n"
        "  brew tap kaos/shell\n"
        "  brew install bats-support bats-assert bats-file"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run repository tests with practical filters.", add_help=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="Run all discovered tests (default)")
    mode.add_argument("--unit", action="store_true", help="Run only tests with 'unit' in path")
    mode.add_argument("--smoke", action="store_true", help="Run only tests with 'smoke' in path")
    mode.add_argument("--integration", action="store_true", help="Run only tests with 'integration' in path")
    parser.add_argument("--category", metavar="NAME", help="Filter tests whose path contains NAME")
    parser.add_argument("--file", action="append", metavar="PATTERN", help="Filter tests by filename/path pattern")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose unittest output")
    parser.add_argument("--tap", action="store_true", help="Accepted for compatibility; unittest output is used")
    parser.add_argument("--filter", metavar="REGEX", help="Regex filter against file paths")
    parser.add_argument("--help", "-h", action="store_true", help="Show this help")
    parser.add_argument("tests", nargs="*", help="Explicit test files to run")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.help:
        _show_help()
        return 0

    body_root = _find_body_root(Path(__file__))
    tests_root = _find_tests_root(body_root)
    repo_root = body_root if (body_root / "tests").is_dir() else body_root.parent

    _print_header()

    if args.tap:
        print("--tap requested; using unittest output for native Python port.")

    selected: list[Path]
    if args.tests:
        selected = []
        for value in args.tests:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = repo_root / path
            if path.is_file():
                selected.append(path.resolve())
            else:
                print(f"Skipping missing test file: {path}")
    else:
        if tests_root is None:
            print("No tests directory found.", file=sys.stderr)
            return 1
        discovered = _discover_tests(tests_root)
        selected = _apply_filters(discovered, args)

    if not selected:
        print("No tests matched the selection.", file=sys.stderr)
        return 1

    # Show test file counts
    if tests_root and not args.tests:
        mode_label = "all"
        if args.unit:
            mode_label = "unit"
        elif args.smoke:
            mode_label = "smoke"
        elif args.integration:
            mode_label = "integration"
        elif args.category:
            mode_label = f"category:{args.category}"

        print(f"Running {mode_label} tests")
        print("")
        print("Test file counts:")
        unit_dir = tests_root / "unit"
        smoke_dir = tests_root / "smoke"
        integration_dir = tests_root / "integration"
        print(f"  - Unit tests: {_count_tests_in_dir(unit_dir)}")
        print(f"  - Smoke tests: {_count_tests_in_dir(smoke_dir)}")
        print(f"  - Integration tests: {_count_tests_in_dir(integration_dir)}")
        print("")

    # Count test cases before running
    case_count = _count_test_cases(selected)
    print(f"Test files: {len(selected)}")
    print(f"Test cases: {case_count}")
    print("")

    # Run tests with timing
    start_time = time.monotonic()
    exit_code, total, passed, failed = _run_unittest(
        repo_root.resolve(), selected, verbose=args.verbose,
    )
    duration = time.monotonic() - start_time

    # Use parsed counts if available, otherwise fall back to case_count
    if total == 0:
        total = case_count

    _print_summary(total, passed, failed, duration)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
