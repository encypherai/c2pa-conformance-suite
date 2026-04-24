"""JMESPath rubric evaluation engine (legacy).

Evaluates rubric statements using jmespath expressions against crJSON data.
This is the original evaluation engine from v1.1.0, preserved for backward
compatibility with rubrics that use plain JMESPath syntax.
"""

from __future__ import annotations

from typing import Any

import jmespath

from c2pa_conformance.rubric.types import RubricReport, RubricResult


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
        text = raw.get(language) or raw.get("en") or next(iter(raw.values()), key)
    else:
        text = str(raw)

    if matches is not None:
        text = text.replace("{{matches}}", ", ".join(str(m) for m in matches))

    return text


def _coerce_bool(result: Any, fail_if_matched: bool) -> tuple[bool, list[str] | None]:
    """Convert a jmespath result to (value, matches).

    For fail_if_matched statements the expression returns a list of offending
    items. A non-empty list means the check failed (value=False).
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


def evaluate_jmespath_rubric(
    crjson_data: dict[str, Any],
    statements: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
    language: str = "en",
) -> RubricReport:
    """Evaluate rubric statements using the JMESPath engine.

    Args:
        crjson_data: The crJSON dict to evaluate against.
        statements: List of rubric statement dicts.
        metadata: Rubric metadata dict (contains rubric_metadata key).
        language: Language code for report text resolution.

    Returns:
        A :class:`RubricReport` with evaluation results.
    """
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
