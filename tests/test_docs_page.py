from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

from starlette.requests import Request


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

boots_main = importlib.import_module("boots.main")


def _request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/docs",
        "headers": [],
    }
    return Request(scope)


def test_docs_tree_hides_ingest_script_reference_pages(tmp_path):
    body_root = tmp_path / "body"
    scripts_dir = body_root / "layer2-templates" / "reference" / "scripts"
    scripts_dir.mkdir(parents=True)
    (body_root / ".bra").mkdir()
    (scripts_dir / "integrate-ingest.md").write_text("# Integrate Ingest\n", encoding="utf-8")
    (scripts_dir / "remote-ingest.md").write_text("# Remote Ingest\n", encoding="utf-8")
    (scripts_dir / "operator-guide.md").write_text("# Operator Guide\n", encoding="utf-8")

    original_bra_dir = boots_main.BRA_DIR
    try:
        boots_main.BRA_DIR = str(tmp_path)
        docs = asyncio.run(boots_main.get_docs(_request(), True))
    finally:
        boots_main.BRA_DIR = original_bra_dir

    scripts = next(category for category in docs["categories"] if category["name"] == "scripts")
    filenames = {doc["filename"] for doc in scripts["docs"]}

    assert filenames == {"operator-guide.md"}


def test_docs_page_marks_docs_as_coming_soon():
    docs_html = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

    assert "COMING SOON" in docs_html
