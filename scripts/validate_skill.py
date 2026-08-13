#!/usr/bin/env python3
"""Validate this repository's Agent Skill package without external dependencies."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LOCAL_LINK_RE = re.compile(r"\]\(([^)]+)\)")
REQUIRED_PATHS = (
    "SKILL.md",
    "cmd/ednsdiag/main.go",
    "references/contracts.md",
    "references/providers.md",
    "references/security.md",
    "references/standards.md",
    "schemas/result-v1.schema.json",
)


def scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill_file = root / "SKILL.md"
    if not skill_file.is_file():
        return ["missing required SKILL.md"]

    text = skill_file.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ["SKILL.md must start with YAML frontmatter"]
    try:
        closing = next(index for index, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration:
        return ["SKILL.md frontmatter is not closed"]

    metadata: dict[str, str] = {}
    for line in lines[1:closing]:
        if not line.strip() or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        key, separator, value = line.partition(":")
        if separator:
            metadata[key.strip()] = scalar(value)

    name = metadata.get("name", "")
    description = metadata.get("description", "")
    if not NAME_RE.fullmatch(name) or len(name) > 64:
        errors.append("frontmatter name must be 1-64 lowercase letters, digits, or single hyphens")
    if name != root.resolve().name:
        errors.append(f"frontmatter name {name!r} must match skill directory {root.resolve().name!r}")
    if not description or len(description) > 1024:
        errors.append("frontmatter description must contain 1-1024 characters")
    if not "\n".join(lines[closing + 1 :]).strip():
        errors.append("SKILL.md instruction body is empty")

    for relative in REQUIRED_PATHS:
        if not (root / relative).is_file():
            errors.append(f"missing required package file: {relative}")

    for target in LOCAL_LINK_RE.findall(text):
        target = target.split("#", 1)[0].strip()
        if not target or "://" in target or target.startswith(("#", "mailto:")):
            continue
        if target.startswith("/") or ".." in Path(target).parts:
            errors.append(f"unsafe local SKILL.md link: {target}")
        elif not (root / target).exists():
            errors.append(f"broken local SKILL.md link: {target}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("Agent Skill package is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
