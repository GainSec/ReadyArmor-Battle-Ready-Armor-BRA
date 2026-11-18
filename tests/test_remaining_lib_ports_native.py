from __future__ import annotations

import unittest
from pathlib import Path


class RemainingLibNativePortTests(unittest.TestCase):
    def test_no_lib_python_file_is_shell_passthrough_wrapper(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        lib_root = repo_root / "body" / "layer1" / "lib"

        offenders: list[str] = []
        for path in sorted(lib_root.rglob("*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "Compatibility wrapper for" in text and ".sh" in text:
                offenders.append(str(path.relative_to(repo_root)))

        self.assertEqual(offenders, [], msg="Remaining shell passthrough lib wrappers:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
