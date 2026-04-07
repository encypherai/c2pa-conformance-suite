"""Comparison report generator."""

from __future__ import annotations

from typing import Any

from c2pa_conformance.compare.diff import ComparisonResult


def generate_report(comparison: ComparisonResult) -> dict[str, Any]:
    """Generate a JSON-serializable comparison report."""
    return {
        "asset_path": comparison.asset_path,
        "summary": {
            "total_codes": comparison.total_codes,
            "agreements": comparison.agreements,
            "divergences": comparison.divergences,
            "suite_only": comparison.suite_only,
            "tool_only": comparison.tool_only,
            "agreement_percentage": round(comparison.agreement_pct, 1),
        },
        "entries": [
            {
                "status_code": e.status_code,
                "suite_result": e.suite_result,
                "tool_result": e.tool_result,
                "category": e.category,
                "message": e.message,
            }
            for e in comparison.entries
        ],
    }


def format_report_text(comparison: ComparisonResult) -> str:
    """Format a human-readable comparison report."""
    lines = [
        f"Comparison Report: {comparison.asset_path}",
        f"Total status codes: {comparison.total_codes}",
        f"Agreements: {comparison.agreements} ({comparison.agreement_pct:.1f}%)",
        f"Divergences: {comparison.divergences}",
        f"Suite-only: {comparison.suite_only}",
        f"Tool-only: {comparison.tool_only}",
    ]

    divergences = [e for e in comparison.entries if e.category == "divergence"]
    if divergences:
        lines.append("")
        lines.append("Divergences:")
        for e in divergences:
            lines.append(f"  {e.status_code}: suite={e.suite_result} tool={e.tool_result}")

    return "\n".join(lines)
