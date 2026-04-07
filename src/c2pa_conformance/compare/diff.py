"""Diff engine for comparing conformance suite results against c2pa-tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from c2pa_conformance.compare.normalizer import NormalizedReport


@dataclass
class DiffEntry:
    """A single difference between suite and c2pa-tool results."""

    status_code: str
    suite_result: str  # "pass", "fail", "informational", "not_evaluated"
    tool_result: str  # "pass", "fail", "informational", "not_reported"
    category: str = ""  # "agreement", "suite_only_fail", "tool_only_fail", "divergence"
    message: str = ""


@dataclass
class ComparisonResult:
    """Complete comparison between suite and c2pa-tool."""

    asset_path: str = ""
    total_codes: int = 0
    agreements: int = 0
    divergences: int = 0
    suite_only: int = 0
    tool_only: int = 0
    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def agreement_pct(self) -> float:
        if self.total_codes == 0:
            return 100.0
        return (self.agreements / self.total_codes) * 100.0


def compare_results(
    suite_results: list[dict[str, Any]],
    tool_report: NormalizedReport,
) -> ComparisonResult:
    """Compare conformance suite results against c2pa-tool results.

    Args:
        suite_results: List of EvalResult dicts from the conformance suite.
        tool_report: Normalized report from c2pa-tool.

    Returns:
        ComparisonResult with detailed diff entries.
    """
    comparison = ComparisonResult(asset_path=tool_report.asset_path)

    # Index suite results by status_code
    suite_by_code: dict[str, str] = {}
    for r in suite_results:
        code = r.get("status_code", "")
        result = r.get("result", "")
        if code:
            suite_by_code[code] = result

    # Index tool results by status_code
    tool_by_code: dict[str, str] = {}
    for r in tool_report.results:
        if r.status_code:
            tool_by_code[r.status_code] = r.result

    # All unique codes
    all_codes = set(suite_by_code.keys()) | set(tool_by_code.keys())
    comparison.total_codes = len(all_codes)

    for code in sorted(all_codes):
        suite_result = suite_by_code.get(code, "not_evaluated")
        tool_result = tool_by_code.get(code, "not_reported")

        if suite_result == tool_result:
            category = "agreement"
            comparison.agreements += 1
        elif tool_result == "not_reported":
            category = "suite_only"
            comparison.suite_only += 1
        elif suite_result == "not_evaluated":
            category = "tool_only"
            comparison.tool_only += 1
        else:
            category = "divergence"
            comparison.divergences += 1

        comparison.entries.append(
            DiffEntry(
                status_code=code,
                suite_result=suite_result,
                tool_result=tool_result,
                category=category,
            )
        )

    return comparison
