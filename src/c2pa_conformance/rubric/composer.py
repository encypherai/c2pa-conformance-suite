"""Composable rubric loader with include resolution.

Reads multi-document YAML rubric files and resolves ``include:`` directives
to produce a fully flattened :class:`ComposedRubric`. Supports the composable
rubric format used by the C2PA conformance program, where globals (variables
and named expressions) are defined in shared files and included by multiple
rubric variants.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from c2pa_conformance.rubric.types import ComposedRubric


def compose(rubric_path: Path) -> ComposedRubric:
    """Load and compose a rubric file, resolving all includes.

    Args:
        rubric_path: Path to the top-level rubric YAML file.

    Returns:
        A :class:`ComposedRubric` with merged globals and flattened statements.

    Raises:
        FileNotFoundError: If rubric_path or an included file does not exist.
        ValueError: If a circular include is detected.
    """
    seen: set[str] = set()
    return _compose_recursive(rubric_path, seen)


def _compose_recursive(rubric_path: Path, seen: set[str]) -> ComposedRubric:
    """Recursively load a rubric and its includes."""
    canonical = str(rubric_path.resolve())
    if canonical in seen:
        raise ValueError(f"Circular include detected: {rubric_path}")
    seen.add(canonical)

    text = rubric_path.read_text(encoding="utf-8")
    docs = list(yaml.safe_load_all(text))

    metadata: dict[str, Any] = {}
    statements: list[dict[str, Any]] = []
    variables: dict[str, Any] = {}
    expressions: dict[str, str] = {}
    includes: list[str] = []

    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, dict):
            if "rubric_metadata" in doc:
                metadata = doc
                # Extract globals from metadata
                variables.update(doc.get("variables") or {})
                expressions.update(doc.get("expressions") or {})
                includes.extend(doc.get("include") or [])
            elif "block" in doc:
                # Block directives are skipped (used for rubric builder instructions)
                continue
            else:
                statements.append(doc)
        elif isinstance(doc, list):
            statements.extend(doc)

    # Resolve includes depth-first: included globals come first,
    # then the current file's globals can override them.
    merged_variables: dict[str, Any] = {}
    merged_expressions: dict[str, str] = {}
    merged_statements: list[dict[str, Any]] = []

    for include_ref in includes:
        include_path = (rubric_path.parent / include_ref).resolve()
        if not include_path.exists():
            raise FileNotFoundError(
                f"Included rubric not found: {include_ref} "
                f"(resolved to {include_path})"
            )
        child = _compose_recursive(Path(include_path), seen)
        merged_variables.update(child.variables)
        merged_expressions.update(child.expressions)
        merged_statements.extend(child.statements)

    # Current file overrides included globals
    merged_variables.update(variables)
    merged_expressions.update(expressions)
    merged_statements.extend(statements)

    return ComposedRubric(
        metadata=metadata,
        statements=merged_statements,
        variables=merged_variables,
        expressions=merged_expressions,
    )


def parse_simple_rubric(
    rubric_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a simple (non-composable) rubric YAML file.

    This is the legacy parse path for rubrics without includes.

    Returns:
        Tuple of (metadata dict, list of statement dicts).
    """
    text = rubric_path.read_text(encoding="utf-8")
    docs = list(yaml.safe_load_all(text))

    metadata: dict[str, Any] = {}
    statements: list[dict[str, Any]] = []

    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, dict) and "rubric_metadata" in doc:
            metadata = doc
        elif isinstance(doc, list):
            statements.extend(doc)

    return metadata, statements
