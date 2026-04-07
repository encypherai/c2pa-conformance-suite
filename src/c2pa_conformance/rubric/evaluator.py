"""Rubric evaluator for C2PA conformance.

Parses multi-document YAML rubric files and evaluates jmespath expressions
against crJSON (JSON-LD serialization of a C2PA manifest store).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jmespath
import yaml


@dataclass
class RubricResult:
    """Result of evaluating a single rubric statement."""

    id: str
    description: str
    value: bool  # True = check passed, False = check failed
    report_text: str
    matches: list[str] | None = None  # For fail_if_matched: the matched items
    error: str | None = None  # If expression evaluation failed

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "description": self.description,
            "value": self.value,
            "report_text": self.report_text,
        }
        if self.matches is not None:
            d["matches"] = self.matches
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class RubricReport:
    """Complete rubric evaluation report."""

    rubric_name: str
    rubric_version: str
    results: list[RubricResult] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.value)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rubric_name": self.rubric_name,
            "rubric_version": self.rubric_version,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "results": [r.to_dict() for r in self.results],
        }


def parse_rubric(rubric_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a rubric YAML file into (metadata, statements).

    Returns:
        Tuple of (metadata dict, list of statement dicts).
        Metadata contains rubric_metadata with name, version, etc.
        Statements are the evaluation rules.
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


def _resolve_text(
    report_text: Any,
    value: bool,
    matches: list[str] | None,
    language: str,
) -> str:
    """Resolve report_text to a plain string for the given value and language."""
    key = "true" if value else "false"

    if not isinstance(report_text, dict):
        return str(report_text) if report_text is not None else key

    raw = report_text.get(key)
    if raw is None:
        return key

    if isinstance(raw, dict):
        # Language-tagged dict: pick the requested language, fall back to "en".
        text = raw.get(language) or raw.get("en") or next(iter(raw.values()), key)
    else:
        text = str(raw)

    if matches is not None:
        text = text.replace("{{matches}}", ", ".join(str(m) for m in matches))

    return text


def _coerce_bool(result: Any, fail_if_matched: bool) -> tuple[bool, list[str] | None]:
    """Convert a jmespath result to (value, matches).

    For fail_if_matched statements the expression is expected to return a list
    of offending items. A non-empty list means the check failed (value=False).

    For ordinary statements the result is coerced to bool directly.
    """
    if fail_if_matched:
        if isinstance(result, list) and len(result) > 0:
            return False, [str(m) for m in result]
        return True, None

    if isinstance(result, bool):
        return result, None
    if isinstance(result, list):
        return len(result) > 0, None
    if isinstance(result, (int, float)):
        return result > 0, None
    return result is not None, None


def evaluate_rubric(
    crjson_data: dict[str, Any],
    rubric_path: Path | None = None,
    statements: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    language: str = "en",
) -> RubricReport:
    """Evaluate a rubric against crJSON data.

    Either rubric_path or (statements + metadata) must be provided.
    Uses jmespath to evaluate expressions.
    """
    if rubric_path is not None:
        metadata, statements = parse_rubric(rubric_path)

    if statements is None:
        statements = []
    if metadata is None:
        metadata = {}

    rubric_meta: dict[str, Any] = metadata.get("rubric_metadata", {})
    rubric_name: str = rubric_meta.get("name", "")
    rubric_version: str = rubric_meta.get("version", "")

    results: list[RubricResult] = []

    for stmt in statements:
        stmt_id: str = stmt.get("id", "")
        description: str = stmt.get("description", "")
        expression: str = stmt.get("expression", "")
        fail_if_matched: bool = bool(stmt.get("fail_if_matched", False))
        report_text_raw: Any = stmt.get("report_text", {})

        try:
            raw_result = jmespath.search(expression, crjson_data)
        except Exception as exc:  # noqa: BLE001
            results.append(
                RubricResult(
                    id=stmt_id,
                    description=description,
                    value=False,
                    report_text="",
                    error=str(exc),
                )
            )
            continue

        value, matches = _coerce_bool(raw_result, fail_if_matched)
        report_text = _resolve_text(report_text_raw, value, matches, language)

        results.append(
            RubricResult(
                id=stmt_id,
                description=description,
                value=value,
                report_text=report_text,
                matches=matches,
            )
        )

    return RubricReport(
        rubric_name=rubric_name,
        rubric_version=rubric_version,
        results=results,
    )
