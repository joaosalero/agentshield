#!/usr/bin/env python3
"""Validate repository-facing portfolio documentation without network access."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:")
REQUIRED_README_SECTIONS = {
    "why it matters",
    "product experience",
    "try the demo lab",
    "technical depth",
    "security boundaries",
    "project evidence",
}
REQUIRED_FILES = {
    Path("CHANGELOG.md"),
    Path("SUPPORT.md"),
    Path("docs/PORTFOLIO_CASE_STUDY.md"),
    Path("docs/ROADMAP.md"),
    Path("docs/OPERATIONS.md"),
    Path("docs/assets/architecture.svg"),
    Path(".github/PULL_REQUEST_TEMPLATE.md"),
    Path(".github/ISSUE_TEMPLATE/bug_report.yml"),
    Path(".github/ISSUE_TEMPLATE/feature_request.yml"),
    Path(".github/ISSUE_TEMPLATE/config.yml"),
}


def markdown_files() -> list[Path]:
    files = [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "CHANGELOG.md")]
    files.extend(sorted((ROOT / "docs").glob("*.md")))
    return [path for path in files if path.is_file()]


def validate_local_links(path: Path, errors: list[str]) -> int:
    checked = 0
    for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
        raw_target = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
        if not raw_target or raw_target.startswith("#") or raw_target.startswith(EXTERNAL_SCHEMES):
            continue
        relative_target = unquote(raw_target.split("#", 1)[0])
        candidate = (path.parent / relative_target).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            errors.append(f"{path.relative_to(ROOT)}: link escapes repository: {raw_target}")
            continue
        checked += 1
        if not candidate.exists():
            errors.append(f"{path.relative_to(ROOT)}: missing link target: {raw_target}")
    return checked


def main() -> int:
    errors: list[str] = []
    for required in sorted(REQUIRED_FILES):
        if not (ROOT / required).is_file():
            errors.append(f"missing required portfolio file: {required}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    headings = {
        match.group(1).strip().lower()
        for match in re.finditer(r"^##\s+(.+?)\s*$", readme, re.MULTILINE)
    }
    for section in sorted(REQUIRED_README_SECTIONS - headings):
        errors.append(f"README.md: missing required section: {section}")

    checked_links = sum(validate_local_links(path, errors) for path in markdown_files())

    architecture = ROOT / "docs/assets/architecture.svg"
    if architecture.is_file():
        try:
            root = ET.parse(architecture).getroot()
            if not root.tag.endswith("svg"):
                errors.append("docs/assets/architecture.svg: root element is not SVG")
            if not root.get("viewBox"):
                errors.append("docs/assets/architecture.svg: missing responsive viewBox")
        except ET.ParseError as exc:
            errors.append(f"docs/assets/architecture.svg: invalid XML: {exc}")

    if errors:
        print("portfolio documentation: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"portfolio documentation: OK ({len(markdown_files())} documents, {checked_links} local links)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
