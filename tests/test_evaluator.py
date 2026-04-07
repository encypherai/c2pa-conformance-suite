"""Tests for the predicate evaluation engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2pa_conformance.evaluator.engine import (
    PredicateEngine,
    ResultType,
    _eval_condition,
    _resolve_field,
)

# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------


class TestResolveField:
    def test_simple_key(self) -> None:
        assert _resolve_field({"name": "test"}, "name") == "test"

    def test_dotted_path(self) -> None:
        ctx = {"a": {"b": {"c": 42}}}
        assert _resolve_field(ctx, "a.b.c") == 42

    def test_missing_returns_none(self) -> None:
        assert _resolve_field({"x": 1}, "y") is None

    def test_array_length(self) -> None:
        ctx = {"items": [1, 2, 3]}
        assert _resolve_field(ctx, "items.length") == 3

    def test_empty_path(self) -> None:
        assert _resolve_field({"x": 1}, "") is None


# ---------------------------------------------------------------------------
# Condition operators
# ---------------------------------------------------------------------------


class TestFieldPresent:
    def test_present(self) -> None:
        ok, _ = _eval_condition(
            {"exclusions": [1, 2]},
            {"op": "field_present", "field": "exclusions"},
        )
        assert ok

    def test_absent(self) -> None:
        ok, status = _eval_condition(
            {},
            {
                "op": "field_present",
                "field": "exclusions",
                "on_absent": {"status": "assertion.dataHash.malformed"},
            },
        )
        assert not ok
        assert status == "assertion.dataHash.malformed"


class TestAllOf:
    def test_all_pass(self) -> None:
        ok, _ = _eval_condition(
            {"a": 5, "b": 10},
            {
                "op": "all_of",
                "checks": [
                    {"op": "gte", "field": "a", "value": 0},
                    {"op": "gte", "field": "b", "value": 0},
                ],
            },
        )
        assert ok

    def test_one_fails(self) -> None:
        ok, _ = _eval_condition(
            {"a": -1, "b": 10},
            {
                "op": "all_of",
                "checks": [
                    {"op": "gte", "field": "a", "value": 0},
                    {"op": "gte", "field": "b", "value": 0},
                ],
            },
        )
        assert not ok


class TestForEach:
    def test_all_items_pass(self) -> None:
        ok, _ = _eval_condition(
            {"items": [{"start": 0}, {"start": 5}, {"start": 10}]},
            {
                "op": "for_each",
                "over": "items",
                "check": {"op": "gte", "field": "start", "value": 0},
            },
        )
        assert ok

    def test_one_item_fails(self) -> None:
        ok, status = _eval_condition(
            {"items": [{"start": 0}, {"start": -1}]},
            {
                "op": "for_each",
                "over": "items",
                "check": {"op": "gte", "field": "start", "value": 0},
                "on_violation": {"status": "malformed"},
            },
        )
        assert not ok
        assert status == "malformed"


class TestForConsecutivePairs:
    def test_ordered_pairs(self) -> None:
        ctx = {"ranges": [{"end": 10}, {"end": 20}, {"end": 30}]}
        ok, _ = _eval_condition(
            ctx,
            {
                "op": "for_consecutive_pairs",
                "over": "ranges",
                "check": {
                    "op": "lte",
                    "left": "prev.end",
                    "right": "next.end",
                },
            },
        )
        assert ok

    def test_single_item_passes(self) -> None:
        ok, _ = _eval_condition(
            {"ranges": [{"end": 10}]},
            {
                "op": "for_consecutive_pairs",
                "over": "ranges",
                "check": {"op": "lte", "left": "prev.end", "right": "next.end"},
            },
        )
        assert ok


class TestOneOf:
    def test_allowed_value(self) -> None:
        ok, _ = _eval_condition(
            {"alg": "sha256"},
            {
                "op": "one_of",
                "field": "alg",
                "allowed": ["sha256", "sha384", "sha512"],
                "deprecated": ["sha1"],
            },
        )
        assert ok

    def test_deprecated_value(self) -> None:
        ok, _ = _eval_condition(
            {"alg": "sha1"},
            {
                "op": "one_of",
                "field": "alg",
                "allowed": ["sha256"],
                "deprecated": ["sha1"],
            },
        )
        assert ok

    def test_unknown_value(self) -> None:
        ok, status = _eval_condition(
            {"alg": "md5"},
            {
                "op": "one_of",
                "field": "alg",
                "allowed": ["sha256"],
                "deprecated": ["sha1"],
                "on_not_found": {"status": "algorithm.unsupported"},
            },
        )
        assert not ok
        assert status == "algorithm.unsupported"


class TestOr:
    def test_first_passes(self) -> None:
        ok, _ = _eval_condition(
            {"hash_matches": True, "excluded": False},
            {
                "op": "or",
                "checks": [
                    {"op": "eq", "field": "hash_matches", "value": True},
                    {"op": "eq", "field": "excluded", "value": True},
                ],
            },
        )
        assert ok

    def test_second_passes(self) -> None:
        ok, _ = _eval_condition(
            {"hash_matches": False, "excluded": True},
            {
                "op": "or",
                "checks": [
                    {"op": "eq", "field": "hash_matches", "value": True},
                    {"op": "eq", "field": "excluded", "value": True},
                ],
            },
        )
        assert ok

    def test_none_pass(self) -> None:
        ok, _ = _eval_condition(
            {"hash_matches": False, "excluded": False},
            {
                "op": "or",
                "checks": [
                    {"op": "eq", "field": "hash_matches", "value": True},
                    {"op": "eq", "field": "excluded", "value": True},
                ],
            },
        )
        assert not ok


class TestSubsetCheck:
    def test_subset(self) -> None:
        ok, _ = _eval_condition(
            {"actual": ["a", "b"], "superset": ["a", "b", "c"]},
            {
                "op": "subset_check",
                "actual": "actual",
                "expected_superset": "superset",
            },
        )
        assert ok

    def test_not_subset(self) -> None:
        ok, status = _eval_condition(
            {"actual": ["a", "b", "d"], "superset": ["a", "b", "c"]},
            {
                "op": "subset_check",
                "actual": "actual",
                "expected_superset": "superset",
                "on_extra_boxes": {"status": "unknownBox"},
            },
        )
        assert not ok
        assert status == "unknownBox"


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


class TestPredicateEngine:
    @pytest.fixture
    def predicates_path(self, tmp_path: Path) -> Path:
        """Create a minimal predicates.json for testing."""
        data = {
            "spec_version": "2.4",
            "predicate_schema_version": "0.1.0",
            "format_families": {
                "test": {
                    "description": "Test family",
                    "mime_types": ["test/plain"],
                    "binding_mechanism": "c2pa.hash.data",
                    "predicates": [
                        {
                            "predicate_id": "PRED-TEST-001",
                            "source_rules": ["VAL-TEST-0001"],
                            "severity": "shall",
                            "title": "Test field present",
                            "description": "Test",
                            "condition": {
                                "op": "field_present",
                                "field": "hash",
                                "on_absent": {
                                    "status": "test.missing",
                                    "result": "fail",
                                },
                            },
                        }
                    ],
                }
            },
            "cross_cutting": {"predicates": []},
            "coverage_summary": {},
        }
        path = tmp_path / "predicates.json"
        path.write_text(json.dumps(data))
        return path

    def test_load(self, predicates_path: Path) -> None:
        engine = PredicateEngine(predicates_path)
        assert engine.predicate_count == 1
        assert engine.spec_version == "2.4"

    def test_evaluate_pass(self, predicates_path: Path) -> None:
        engine = PredicateEngine(predicates_path)
        result = engine.evaluate_predicate("PRED-TEST-001", {"hash": "abc"})
        assert result.result == ResultType.PASS

    def test_evaluate_fail(self, predicates_path: Path) -> None:
        engine = PredicateEngine(predicates_path)
        result = engine.evaluate_predicate("PRED-TEST-001", {})
        assert result.result == ResultType.FAIL
        assert result.status_code == "test.missing"

    def test_evaluate_unknown_predicate(self, predicates_path: Path) -> None:
        engine = PredicateEngine(predicates_path)
        result = engine.evaluate_predicate("PRED-NOPE-999", {})
        assert result.result == ResultType.ERROR

    def test_evaluate_all(self, predicates_path: Path) -> None:
        engine = PredicateEngine(predicates_path)
        report = engine.evaluate_all({"hash": "abc"}, binding="c2pa.hash.data")
        assert report.pass_count == 1
        assert report.fail_count == 0
