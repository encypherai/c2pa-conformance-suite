#!/usr/bin/env python3
"""Fix bare json-formula keywords in rubric YAML files.

Rewrites bare ``null``, ``true``, ``false`` to ``null()``, ``true()``,
``false()`` inside json-formula expression contexts only.  Leaves YAML
booleans, reportText keys, and already-correct function-call forms
untouched.

Usage:
    python scripts/fix_rubric_keywords.py [RUBRIC_DIR] [--dry-run]

Examples:
    # Preview changes without writing
    python scripts/fix_rubric_keywords.py src/c2pa_conformance/data/rubrics --dry-run

    # Apply fixes
    python scripts/fix_rubric_keywords.py src/c2pa_conformance/data/rubrics
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Match bare keyword at a word boundary that is NOT already followed by
# optional whitespace + '(' (function-call form).
BARE_KW_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(true|false|null)(?![A-Za-z0-9_(])"
)

# Split on quoted regions so we never rewrite inside strings.
QUOTED_SPLIT_RE = re.compile(r"""("[^"]*"|'[^']*'|`[^`]*`)""")


def fix_expression(text: str) -> str:
    """Rewrite bare keywords in a single expression string."""
    parts = QUOTED_SPLIT_RE.split(text)
    result: list[str] = []
    for i, part in enumerate(parts):
        if i % 2 == 0:  # outside quotes
            part = BARE_KW_RE.sub(lambda m: f"{m.group(1)}()", part)
        result.append(part)
    return "".join(result)


def _is_expression_context(stripped: str) -> bool:
    """Return True if the line is a named-expression definition."""
    return stripped.startswith("_") and ":" in stripped


def process_file(
    path: Path, *, dry_run: bool = False
) -> list[tuple[int, str, str]]:
    """Process a single YAML rubric file.

    Returns a list of (line_number, old_text, new_text) for every changed line.
    """
    lines = path.read_text().splitlines(keepends=True)
    changes: list[tuple[int, str, str]] = []
    in_expression = False
    indent_level = 0

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        current_indent = len(line) - len(line.lstrip())

        # Detect ``expression:`` fields.
        if stripped.startswith("expression:"):
            in_expression = True
            indent_level = current_indent
            after_key = stripped[len("expression:") :].strip()
            if after_key and after_key not in ("|", "|-", ">", ">-"):
                # Single-line expression value.
                fixed = fix_expression(line)
                if fixed != line:
                    changes.append((i + 1, line.rstrip(), fixed.rstrip()))
                    lines[i] = fixed
                in_expression = False
            continue

        # Multi-line expression continuation.
        if in_expression:
            if stripped and current_indent <= indent_level:
                in_expression = False
            else:
                fixed = fix_expression(line)
                if fixed != line:
                    changes.append((i + 1, line.rstrip(), fixed.rstrip()))
                    lines[i] = fixed
                continue

        # Named expressions in the ``expressions:`` mapping section.
        if _is_expression_context(stripped):
            fixed = fix_expression(line)
            if fixed != line:
                changes.append((i + 1, line.rstrip(), fixed.rstrip()))
                lines[i] = fixed

    if not dry_run and changes:
        path.write_text("".join(lines))

    return changes


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    dry_run = "--dry-run" in sys.argv

    rubric_dir = Path(args[0]) if args else Path(".")
    if not rubric_dir.is_dir():
        print(f"Error: {rubric_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = sorted(rubric_dir.rglob("*.yml"))
    total = 0
    for f in files:
        file_changes = process_file(f, dry_run=dry_run)
        if file_changes:
            print(f"\n{f}:")
            for line_no, old, new in file_changes:
                print(f"  L{line_no}: {old.strip()}")
                print(f"      -> {new.strip()}")
            total += len(file_changes)

    action = "Would fix" if dry_run else "Fixed"
    print(f"\n{action} {total} bare keyword(s) across {len(files)} file(s).")


if __name__ == "__main__":
    main()
