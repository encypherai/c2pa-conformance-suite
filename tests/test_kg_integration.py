"""Integration tests that load real KG predicates through the evaluator engine.

Validates that all predicates from predicates.json can be loaded,
parsed, and evaluated by the engine without errors. Also verifies
that all condition operators used in predicates.json are implemented.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from c2pa_conformance.evaluator.engine import _OPERATORS, PredicateEngine, ResultType

PREDICATES_PATH = (
    Path(__file__).parent.parent / "src" / "c2pa_conformance" / "data" / "predicates.json"
)


@pytest.fixture(scope="module")
def engine() -> PredicateEngine:
    """Load the real KG predicates into the engine."""
    assert PREDICATES_PATH.exists(), f"predicates.json not found at {PREDICATES_PATH}"
    return PredicateEngine(PREDICATES_PATH)


@pytest.fixture(scope="module")
def predicates_data() -> dict:
    """Load raw predicates JSON."""
    return json.loads(PREDICATES_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def all_predicates(predicates_data: dict) -> list[dict]:
    """Collect every predicate from all sections."""
    preds: list[dict] = []
    for family in predicates_data["format_families"].values():
        preds.extend(family["predicates"])
    preds.extend(predicates_data["cross_cutting"]["predicates"])
    return preds


def _collect_ops(obj: dict | list | str | int | float | bool | None) -> set[str]:
    """Recursively collect all 'op' values from a nested structure."""
    ops: set[str] = set()
    if isinstance(obj, dict):
        if "op" in obj:
            ops.add(obj["op"])
        for v in obj.values():
            ops.update(_collect_ops(v))
    elif isinstance(obj, list):
        for item in obj:
            ops.update(_collect_ops(item))
    return ops


class TestPredicateLoading:
    """Verify the engine can load and index all KG predicates."""

    def test_engine_loads_all_predicates(self, engine: PredicateEngine) -> None:
        assert engine.predicate_count >= 100

    def test_spec_version_is_24(self, engine: PredicateEngine) -> None:
        assert engine.spec_version == "2.4"

    def test_all_predicates_indexed(
        self, engine: PredicateEngine, all_predicates: list[dict]
    ) -> None:
        for pred in all_predicates:
            pid = pred["predicate_id"]
            assert engine.get_predicate(pid) is not None, f"predicate {pid} not indexed"


class TestOperatorCoverage:
    """Verify all operators used in predicates.json are implemented."""

    def test_all_ops_implemented(self, all_predicates: list[dict]) -> None:
        """Every op used in any predicate condition must exist in _OPERATORS."""
        all_ops: set[str] = set()
        for pred in all_predicates:
            all_ops.update(_collect_ops(pred.get("condition", {})))

        # 'add' is handled inline in _eval_expression, not in _OPERATORS
        all_ops.discard("add")

        missing = all_ops - set(_OPERATORS.keys())
        assert not missing, (
            f"{len(missing)} operators used in predicates.json but not in engine: "
            f"{sorted(missing)}"
        )

    def test_operator_count(self) -> None:
        """Engine should have at least 70 operators."""
        # 50 original + 22 new = 72 minimum
        assert len(_OPERATORS) >= 70


class TestPredicateEvaluation:
    """Verify predicates can be evaluated without runtime errors."""

    def test_evaluate_all_with_empty_context(
        self, engine: PredicateEngine, all_predicates: list[dict]
    ) -> None:
        """Evaluating with an empty context should not raise exceptions.

        Results will be pass/fail/skip but the engine must not crash.
        """
        context: dict = {}
        for pred in all_predicates:
            pid = pred["predicate_id"]
            result = engine.evaluate_predicate(pid, context)
            assert result.result in (
                ResultType.PASS,
                ResultType.FAIL,
                ResultType.INFORMATIONAL,
                ResultType.SKIP,
                ResultType.ERROR,
            ), f"{pid} returned unexpected result type: {result.result}"

    def test_evaluate_crypto_predicates_no_crash(
        self, engine: PredicateEngine, all_predicates: list[dict]
    ) -> None:
        """All crypto predicates evaluate without crashing against a rich context."""
        context = {
            "claim_signature": {"valid": True},
            "signature_verified": True,
            "cert_chain": {"valid": True},
            "signing_credential": {"trusted": True},
            "timestamp": {"valid": True, "gen_time": "2026-01-01T00:00:00Z"},
            "timestamp_validated": True,
            "alg": "sha256",
            "certificates": {"signer": {"revocation_status": "not_revoked"}},
            "x5chain": [b"cert1", b"cert2"],
            "_emitted_statuses": {"claimSignature.validated", "timeStamp.validated"},
        }
        crypto_preds = [p for p in all_predicates if p["predicate_id"].startswith("PRED-CRYP")]
        for pred in crypto_preds:
            result = engine.evaluate_predicate(pred["predicate_id"], context)
            assert result.result != ResultType.ERROR, (
                f"{pred['predicate_id']} raised error: {result.message}"
            )

    def test_evaluate_with_structural_context(self, engine: PredicateEngine) -> None:
        """Evaluate structural predicates with claim field data."""
        context = {
            "claim": {
                "claim_generator": "test/1.0",
                "claim_generator_info": {"name": "test"},
                "signature": "self#jumbf=/c2pa/urn:uuid:test/c2pa.signature",
            },
        }
        result = engine.evaluate_predicate("PRED-STRU-008", context)
        assert result.result in (
            ResultType.PASS, ResultType.INFORMATIONAL, ResultType.FAIL
        )


class TestPredicateIdConsistency:
    """Verify predicate IDs and source rules are valid."""

    def test_all_ids_match_pattern(self, all_predicates: list[dict]) -> None:
        pattern = re.compile(r"^PRED-[A-Z]+-\d{3}$")
        for pred in all_predicates:
            assert pattern.match(pred["predicate_id"]), (
                f"bad ID format: {pred['predicate_id']}"
            )

    def test_all_source_rules_match_pattern(self, all_predicates: list[dict]) -> None:
        pattern = re.compile(r"^VAL-[A-Z]+-\d{4}$")
        for pred in all_predicates:
            for rule_id in pred["source_rules"]:
                assert pattern.match(rule_id), (
                    f"{pred['predicate_id']} has bad rule ID: {rule_id}"
                )

    def test_full_rule_coverage(self, all_predicates: list[dict]) -> None:
        """All 237 v2.4 rules should be covered."""
        all_rules: set[str] = set()
        for pred in all_predicates:
            all_rules.update(pred["source_rules"])
        assert len(all_rules) == 237, f"expected 237 rules, got {len(all_rules)}"
