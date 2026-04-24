"""Shared types for the rubric evaluation system.

Defines the data structures used by both the jmespath and json-formula
evaluation engines, as well as the rubric composer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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


@dataclass
class SignalResult:
    """Result of evaluating a signal rubric trait on a single manifest."""

    trait: str
    report_text: str
    multiple: bool = False  # True if multiple matches found


@dataclass
class ManifestSignals:
    """Signal rubric results for a single manifest in the provenance DAG."""

    asserted_by: dict[str, str]
    mime_type: str | None = None
    local_inceptions: list[SignalResult] = field(default_factory=list)
    local_transformations: list[SignalResult] = field(default_factory=list)
    all_actions_included: bool = False
    ingredients: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertedBy": self.asserted_by,
            "mimeType": self.mime_type,
            "localInceptions": [
                {"trait": s.trait, "reportText": s.report_text, "multiple": s.multiple}
                for s in self.local_inceptions
            ],
            "localTransformations": [
                {"trait": s.trait, "reportText": s.report_text, "multiple": s.multiple}
                for s in self.local_transformations
            ],
            "allActionsIncluded": self.all_actions_included,
            "ingredients": self.ingredients,
        }


@dataclass
class SignalRubricReport:
    """Complete signal rubric evaluation report."""

    rubric_name: str
    rubric_version: str
    manifests: list[ManifestSignals] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rubricName": self.rubric_name,
            "rubricVersion": self.rubric_version,
            "manifests": [m.to_dict() for m in self.manifests],
        }


@dataclass
class ComposedRubric:
    """A fully resolved rubric with merged globals and flattened statements."""

    metadata: dict[str, Any]
    statements: list[dict[str, Any]]
    variables: dict[str, Any] = field(default_factory=dict)
    expressions: dict[str, str] = field(default_factory=dict)

    @property
    def rubric_name(self) -> str:
        return self.metadata.get("rubric_metadata", {}).get("name", "")

    @property
    def rubric_version(self) -> str:
        return self.metadata.get("rubric_metadata", {}).get("version", "")
