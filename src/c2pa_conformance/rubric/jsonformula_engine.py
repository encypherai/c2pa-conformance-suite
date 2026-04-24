"""json-formula rubric evaluation engine.

Evaluates rubric statements using the Adobe json-formula expression language,
which the C2PA conformance program adopted in v0.2. Supports named expressions
with positional parameters ($arg0, $arg1, ...), composable globals, and the
failIfMatched/reportText semantics from the upstream evaluator.

Depends on ``json-formula`` (``lrosenthol/json-formula-py``).
"""

from __future__ import annotations

import re
from typing import Any

from json_formula import JsonFormula
from json_formula.data_types import TYPE_ANY

from c2pa_conformance.rubric.types import ComposedRubric, RubricReport, RubricResult


def _arg_count(expr_str: str | None) -> int:
    """Return the number of $argN parameters referenced in an expression string."""
    indices = [int(m) for m in re.findall(r"\$arg(\d+)", expr_str or "")]
    return max(indices) + 1 if indices else 0


def _build_engine(
    variables: dict[str, Any],
    expressions: dict[str, str],
) -> tuple[Any, dict[str, Any]]:
    """Build a JsonFormula engine with custom functions for named expressions.

    Mirrors the upstream ``create_json_formula_engine`` logic: named
    expressions (prefixed with ``_``) are registered as custom functions.
    Expressions referencing ``$arg0``, ``$arg1``, ... accept positional
    parameters injected into the interpreter's globals at call time.

    Returns:
        Tuple of (JsonFormula engine, variables dict).
    """
    debug_list: list[Any] = []

    # Determine max $argN index across all expressions
    max_args = max((_arg_count(e) for e in expressions.values()), default=0)
    arg_names = [f"$arg{i}" for i in range(max_args)]

    # Compile all expression ASTs
    compile_helper = JsonFormula(debug=[])
    allowed_names = list(variables.keys()) + list(expressions.keys()) + arg_names

    compiled_asts: dict[str, Any] = {}
    expr_arities: dict[str, int] = {}
    for name, expr_str in expressions.items():
        arity = _arg_count(expr_str)
        expr_arities[name] = arity
        try:
            compiled_asts[name] = compile_helper.compile(expr_str, allowed_names)
        except Exception:  # noqa: BLE001
            compiled_asts[name] = None

    def _make_expr_fn(ast: Any, name: str, arity: int) -> Any:
        if arity == 0:

            def fn(args: list[Any], data: Any, interpreter: Any) -> Any:
                if ast is None:
                    raise RuntimeError(f"Expression '{name}' failed to compile")
                return interpreter.search(ast, data)

            return fn
        else:

            def fn_param(args: list[Any], data: Any, interpreter: Any) -> Any:
                if ast is None:
                    raise RuntimeError(f"Expression '{name}' failed to compile")
                injected = {f"$arg{i}": v for i, v in enumerate(args)}
                saved = {k: interpreter.globals.get(k) for k in injected}
                interpreter.globals.update(injected)
                try:
                    return interpreter.search(ast, data)
                finally:
                    for k, prev in saved.items():
                        if prev is None:
                            interpreter.globals.pop(k, None)
                        else:
                            interpreter.globals[k] = prev

            return fn_param

    def _make_signature(arity: int) -> list[dict[str, Any]]:
        if arity == 0:
            return []
        return [{"types": [TYPE_ANY]} for _ in range(arity)]

    custom_functions = {
        name: {
            "func": _make_expr_fn(compiled_asts[name], name, expr_arities[name]),
            "signature": _make_signature(expr_arities[name]),
        }
        for name in compiled_asts
    }

    engine = JsonFormula(debug=debug_list, custom_functions=custom_functions)
    return engine, dict(variables)


def _coerce_bool(
    result: Any, fail_if_matched: bool
) -> tuple[bool, list[str] | None]:
    """Convert a json-formula result to (value, matches).

    For failIfMatched statements, a non-empty list means failure.
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


def _resolve_text(
    report_text: Any,
    value: bool,
    matches: list[str] | None,
    language: str,
) -> str:
    """Resolve reportText to a plain string.

    Handles the upstream format where keys are ``'true'``/``'false'`` strings
    (camelCase ``reportText``) as well as the legacy ``report_text`` format.
    """
    key = "true" if value else "false"

    if not isinstance(report_text, dict):
        return str(report_text) if report_text is not None else key

    raw = report_text.get(key)
    if raw is None:
        raw = report_text.get("default")
    if raw is None:
        return key

    if isinstance(raw, dict):
        text = raw.get(language) or raw.get("en") or next(iter(raw.values()), key)
    else:
        text = str(raw)

    if matches is not None:
        text = text.replace("{{matches}}", ", ".join(str(m) for m in matches))

    return text


def evaluate_jsonformula_rubric(
    crjson_data: dict[str, Any],
    statements: list[dict[str, Any]],
    variables: dict[str, Any] | None = None,
    expressions: dict[str, str] | None = None,
    metadata: dict[str, Any] | None = None,
    language: str = "en",
) -> RubricReport:
    """Evaluate rubric statements using the json-formula engine.

    Args:
        crjson_data: The crJSON dict to evaluate against.
        statements: List of rubric statement dicts.
        variables: Global variables dict (from composed rubric or metadata).
        expressions: Named expressions dict (from composed rubric or metadata).
        metadata: Rubric metadata dict. Variables/expressions here are used
            as fallback if not provided directly.
        language: Language code for report text resolution.

    Returns:
        A :class:`RubricReport` with evaluation results.
    """
    if metadata is None:
        metadata = {}
    if variables is None:
        variables = dict(metadata.get("variables") or {})
    if expressions is None:
        expressions = dict(metadata.get("expressions") or {})

    rubric_meta: dict[str, Any] = metadata.get("rubric_metadata", {})
    rubric_name: str = rubric_meta.get("name", "")
    rubric_version: str = rubric_meta.get("version", "")

    engine, var_scope = _build_engine(variables, expressions)

    results: list[RubricResult] = []

    for stmt in statements:
        stmt_id: str = stmt.get("id", "")
        description: str = stmt.get("description", "")
        # Support both camelCase (upstream) and snake_case (our legacy) keys
        expression: str = stmt.get("expression", "")
        fail_if_matched: bool = bool(
            stmt.get("failIfMatched", stmt.get("fail_if_matched", False))
        )
        report_text_raw: Any = stmt.get("reportText", stmt.get("report_text", {}))

        if not expression:
            continue

        try:
            raw_result = engine.search(expression.strip(), crjson_data, globals=var_scope)
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


def evaluate_composed_rubric(
    crjson_data: dict[str, Any],
    composed: ComposedRubric,
    language: str = "en",
) -> RubricReport:
    """Evaluate a fully composed rubric against crJSON data.

    Convenience wrapper that unpacks the :class:`ComposedRubric` fields.
    """
    return evaluate_jsonformula_rubric(
        crjson_data=crjson_data,
        statements=composed.statements,
        variables=composed.variables,
        expressions=composed.expressions,
        metadata=composed.metadata,
        language=language,
    )
