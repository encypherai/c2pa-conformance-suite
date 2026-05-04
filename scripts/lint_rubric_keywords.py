#!/usr/bin/env python3
"""Lint rubric YAML files for bare json-formula keywords.

In json-formula, ``true``, ``false``, and ``null`` are zero-argument
functions.  Bare usage (e.g. ``!= null``) is a field reference, not a
literal.  The correct form is ``null()``, ``true()``, ``false()``.

Exits non-zero if any expression field contains a bare keyword.

Usage:
    python scripts/lint_rubric_keywords.py [RUBRIC_DIR]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BARE_KW_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(true|false|null)(?![A-Za-z0-9_(])"
)

QUOTED_SPLIT_RE = re.compile(r"""("[^"]*"|'[^']*'|`[^`]*`)""")


def check_expression(text: str) -> list[str]:
    """Return bare keywords found in an expression string."""
    parts = QUOTED_SPLIT_RE.split(text)
    found: list[str] = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            found.extend(m.group(1) for m in BARE_KW_RE.finditer(part))
    return found


def _is_expression_context(stripped: str) -> bool:
    return stripped.startswith("_") and ":" in stripped


def lint_file(path: Path) -> list[str]:
    """Return error messages for bare keywords in a rubric file."""
    errors: list[str] = []
    lines = path.read_text().splitlines()
    in_expression = False
    indent_level = 0

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        current_indent = len(line) - len(line.lstrip())

        if stripped.startswith("expression:"):
            in_expression = True
            indent_level = current_indent
            after_key = stripped[len("expression:") :].strip()
            if after_key and after_key not in ("|", "|-", ">", ">-"):
                for kw in check_expression(after_key):
                    errors.append(
                        f"{path}:{i + 1}: bare `{kw}` should be `{kw}()`"
                    )
                in_expression = False
            continue

        if in_expression:
            if stripped and current_indent <= indent_level:
                in_expression = False
            else:
                for kw in check_expression(line):
                    errors.append(
                        f"{path}:{i + 1}: bare `{kw}` should be `{kw}()`"
                    )
                continue

        if _is_expression_context(stripped):
            for kw in check_expression(stripped):
                errors.append(
                    f"{path}:{i + 1}: bare `{kw}` should be `{kw}()`"
                )

    return errors


def main() -> None:
    rubric_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    if not rubric_dir.is_dir():
        print(f"Error: {rubric_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    all_errors: list[str] = []
    for f in sorted(rubric_dir.rglob("*.yml")):
        all_errors.extend(lint_file(f))

    for err in all_errors:
        print(err)

    if all_errors:
        print(
            f"\n{len(all_errors)} bare keyword(s) found. "
            "Use null()/true()/false() in json-formula expressions."
        )
        sys.exit(1)
    else:
        print("All rubric expressions use correct function-call form.")


if __name__ == "__main__":
    main()
