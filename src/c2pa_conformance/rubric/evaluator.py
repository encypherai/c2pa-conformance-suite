"""Rubric evaluator dispatcher.

Routes rubric evaluation to the appropriate engine (JMESPath or json-formula)
based on rubric metadata and structure. Maintains backward compatibility with
v1.1.0 JMESPath rubrics while supporting the v0.2 conformance program's
json-formula rubrics.

Public API:
    - ``evaluate_rubric`` - auto-detects engine and evaluates
    - ``parse_rubric`` - legacy parse (for backward compatibility)
    - ``RubricResult``, ``RubricReport`` - re-exported from types module
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from c2pa_conformance.rubric.types import RubricReport, RubricResult

# Re-export for backward compatibility
__all__ = ["RubricReport", "RubricResult", "evaluate_rubric", "parse_rubric"]


def parse_rubric(rubric_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a rubric YAML file into (metadata, statements).

    This is the legacy parse function preserved for backward compatibility.
    For composable rubrics, use ``c2pa_conformance.rubric.composer.compose``.
    """
    from c2pa_conformance.rubric.composer import parse_simple_rubric

    return parse_simple_rubric(rubric_path)


def _detect_engine(
    rubric_path: Path | None,
    metadata: dict[str, Any] | None,
    statements: list[dict[str, Any]] | None,
) -> str:
    """Detect which evaluation engine a rubric requires.

    Returns:
        ``"json-formula"`` if the rubric uses json-formula syntax,
        ``"jmespath"`` otherwise.
    """
    if metadata is None:
        metadata = {}

    # Explicit engine declaration in metadata
    engine_field = metadata.get("engine") or metadata.get("rubric_metadata", {}).get("engine")
    if engine_field:
        return engine_field

    # Composable rubric indicators: includes or named expressions
    if metadata.get("include"):
        return "json-formula"
    if metadata.get("expressions"):
        return "json-formula"

    # Check statement syntax: camelCase keys (reportText, failIfMatched)
    # are a json-formula indicator; snake_case (report_text, fail_if_matched)
    # are JMESPath legacy.
    if statements:
        for stmt in statements:
            if "reportText" in stmt or "failIfMatched" in stmt:
                return "json-formula"

    # Check if rubric_path points into vendored upstream rubrics
    if rubric_path and "composables" in str(rubric_path):
        return "json-formula"

    return "jmespath"


def evaluate_rubric(
    crjson_data: dict[str, Any],
    rubric_path: Path | None = None,
    statements: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    language: str = "en",
    engine: str | None = None,
) -> RubricReport:
    """Evaluate a rubric against crJSON data.

    Auto-detects the evaluation engine unless ``engine`` is explicitly set.
    Supports both legacy JMESPath rubrics and the C2PA conformance program's
    json-formula rubrics (including composable rubrics with includes).

    Args:
        crjson_data: The crJSON dict to evaluate against.
        rubric_path: Path to the rubric YAML file.
        statements: Pre-parsed list of statement dicts (alternative to rubric_path).
        metadata: Pre-parsed metadata dict (alternative to rubric_path).
        language: Language code for report text.
        engine: Force a specific engine: ``"jmespath"``, ``"json-formula"``,
            or ``None`` for auto-detection.

    Returns:
        A :class:`RubricReport` with evaluation results.
    """
    # Parse once before engine detection. Root composable rubrics carry their
    # `include` directive in the file, so detecting against empty metadata
    # silently misclassifies them as legacy JMESPath and drops every included
    # statement.
    if rubric_path is not None and statements is None:
        from c2pa_conformance.rubric.composer import compose

        composed = compose(rubric_path)
        detected = engine or _detect_engine(rubric_path, composed.metadata, composed.statements)
        if detected == "json-formula":
            from c2pa_conformance.rubric.jsonformula_engine import evaluate_composed_rubric

            return evaluate_composed_rubric(crjson_data, composed, language=language)
        metadata = composed.metadata
        statements = composed.statements

    if statements is None:
        statements = []
    if metadata is None:
        metadata = {}

    # Detect engine from parsed content
    detected = engine or _detect_engine(rubric_path, metadata, statements)

    if detected == "json-formula":
        from c2pa_conformance.rubric.jsonformula_engine import evaluate_jsonformula_rubric

        return evaluate_jsonformula_rubric(
            crjson_data=crjson_data,
            statements=statements,
            metadata=metadata,
            language=language,
        )
    else:
        from c2pa_conformance.rubric.jmespath_engine import evaluate_jmespath_rubric

        return evaluate_jmespath_rubric(
            crjson_data=crjson_data,
            statements=statements,
            metadata=metadata,
            language=language,
        )
