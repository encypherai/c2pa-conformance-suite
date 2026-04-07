"""Tests for engine INFORMATIONAL result type and MAY decision logic.

Verifies that:
1. Predicates with result_type="informational" produce INFORMATIONAL, not PASS
2. Predicates with severity="may" produce INFORMATIONAL on both pass and fail
3. ConformanceReport correctly counts informational results
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2pa_conformance.evaluator.engine import (
    EvalResult,
    PredicateEngine,
    ResultType,
)


@pytest.fixture()
def predicates_with_may(tmp_path: Path) -> Path:
    """Create a predicates.json with MAY-level and informational predicates."""
    predicates = {
        "spec_version": "2.4",
        "format_families": {
            "test": {
                "binding_mechanism": "c2pa.hash.data",
                "predicates": [
                    {
                        "predicate_id": "PRED-TEST-001",
                        "description": "Normal MUST predicate",
                        "severity": "must",
                        "condition": {
                            "op": "field_present",
                            "field": "claim_generator",
                        },
                    },
                    {
                        "predicate_id": "PRED-TEST-002",
                        "description": "MAY predicate (iat validation)",
                        "severity": "may",
                        "condition": {
                            "op": "field_present",
                            "field": "iat_timestamp",
                        },
                    },
                    {
                        "predicate_id": "PRED-TEST-003",
                        "description": "Informational result predicate",
                        "severity": "must",
                        "condition": {
                            "op": "field_present",
                            "field": "additional_exclusions",
                            "on_match": {
                                "status": "assertion.dataHash.additionalExclusionsPresent",
                                "result": "informational",
                            },
                        },
                    },
                    {
                        "predicate_id": "PRED-TEST-004",
                        "description": "MAY predicate that passes",
                        "severity": "may",
                        "condition": {
                            "op": "field_present",
                            "field": "always_present",
                        },
                    },
                ],
            },
        },
        "cross_cutting": {"predicates": []},
    }
    path = tmp_path / "predicates.json"
    path.write_text(json.dumps(predicates))
    return path


class TestInformationalResult:
    def test_informational_on_match(self, predicates_with_may: Path) -> None:
        """Predicate with on_match result='informational' produces INFORMATIONAL."""
        engine = PredicateEngine(predicates_with_may)
        context = {"additional_exclusions": [{"start": 0, "length": 50}]}
        result = engine.evaluate_predicate("PRED-TEST-003", context)
        assert result.result == ResultType.INFORMATIONAL
        assert result.status_code == "assertion.dataHash.additionalExclusionsPresent"

    def test_normal_predicate_still_passes(self, predicates_with_may: Path) -> None:
        """Normal MUST predicate produces PASS when condition is met."""
        engine = PredicateEngine(predicates_with_may)
        context = {"claim_generator": "test/1.0"}
        result = engine.evaluate_predicate("PRED-TEST-001", context)
        assert result.result == ResultType.PASS

    def test_normal_predicate_still_fails(self, predicates_with_may: Path) -> None:
        """Normal MUST predicate produces FAIL when condition is not met."""
        engine = PredicateEngine(predicates_with_may)
        result = engine.evaluate_predicate("PRED-TEST-001", {})
        assert result.result == ResultType.FAIL


class TestMAYDecisionLogic:
    def test_may_predicate_pass_is_informational(self, predicates_with_may: Path) -> None:
        """MAY predicate produces INFORMATIONAL when condition passes."""
        engine = PredicateEngine(predicates_with_may)
        context = {"always_present": True}
        result = engine.evaluate_predicate("PRED-TEST-004", context)
        assert result.result == ResultType.INFORMATIONAL

    def test_may_predicate_fail_is_informational(self, predicates_with_may: Path) -> None:
        """MAY predicate produces INFORMATIONAL when condition fails."""
        engine = PredicateEngine(predicates_with_may)
        result = engine.evaluate_predicate("PRED-TEST-002", {})
        assert result.result == ResultType.INFORMATIONAL
        assert "MAY-level" in result.message

    def test_may_predicate_never_produces_fail(self, predicates_with_may: Path) -> None:
        """MAY predicates should never produce FAIL result type."""
        engine = PredicateEngine(predicates_with_may)
        # Evaluate all MAY predicates with empty context (all conditions fail)
        for pred_id in ("PRED-TEST-002", "PRED-TEST-004"):
            result = engine.evaluate_predicate(pred_id, {})
            assert result.result != ResultType.FAIL, (
                f"{pred_id} produced FAIL, should be INFORMATIONAL"
            )


class TestConformanceReportInformational:
    def test_informational_count(self, predicates_with_may: Path) -> None:
        """ConformanceReport correctly counts informational results."""
        engine = PredicateEngine(predicates_with_may)
        context = {
            "claim_generator": "test/1.0",
            "always_present": True,
            "additional_exclusions": [{"start": 0, "length": 50}],
        }
        report = engine.evaluate_all(context)

        # PRED-TEST-001: PASS (MUST, condition met)
        # PRED-TEST-002: INFORMATIONAL (MAY, condition fails)
        # PRED-TEST-003: INFORMATIONAL (on_match result=informational)
        # PRED-TEST-004: INFORMATIONAL (MAY, condition passes)
        assert report.pass_count == 1
        assert report.informational_count == 3
        assert report.fail_count == 0
        assert report.total_count == 4

    def test_informational_in_report_dict(self, predicates_with_may: Path) -> None:
        """to_dict() includes informational count in summary."""
        engine = PredicateEngine(predicates_with_may)
        context = {"claim_generator": "test/1.0", "always_present": True}
        report = engine.evaluate_all(context)
        d = report.to_dict()
        assert "informational" in d["summary"]
        assert d["summary"]["informational"] >= 0

    def test_result_type_in_eval_result_dict(self) -> None:
        """EvalResult.to_dict() correctly serializes informational."""
        result = EvalResult(
            predicate_id="TEST",
            result=ResultType.INFORMATIONAL,
            status_code="test.informational",
        )
        d = result.to_dict()
        assert d["result"] == "informational"
