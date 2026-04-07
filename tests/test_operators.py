"""Tests for non-crypto runtime predicate operators.

Each operator that was previously a noop and now has a real implementation
is covered by at least a pass case and a fail case.
"""

from __future__ import annotations

from typing import Any

from c2pa_conformance.evaluator.engine import (
    _eval_check_uniqueness,
    _eval_count,
    _eval_coverage_check,
    _eval_dispatch_by_type,
    _eval_full_coverage,
    _eval_if,
    _eval_mutual_exclusion,
    _eval_no_overlap,
    _eval_none_of_patterns,
    _eval_one_of_content,
    _eval_one_of_type,
    _eval_ordered_fallback,
    _eval_ordered_match,
    _eval_priority_check,
    _eval_scan_for_delimiters,
    _eval_scan_for_magic,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _cond(**kwargs: Any) -> dict[str, Any]:
    """Build a condition dict for brevity."""
    return dict(kwargs)


# ---------------------------------------------------------------------------
# Group 1: Range validation
# ---------------------------------------------------------------------------


class TestNoOverlap:
    def _cond(self, over: str = "ranges") -> dict[str, Any]:
        return {
            "op": "no_overlap",
            "over": over,
            "start_field": "start",
            "length_field": "length",
            "on_violation": {"status": "overlap.found"},
        }

    def test_valid_non_overlapping(self) -> None:
        ctx = {"ranges": [{"start": 0, "length": 10}, {"start": 20, "length": 10}]}
        ok, msg = _eval_no_overlap(ctx, self._cond())
        assert ok is True
        assert msg == ""

    def test_overlapping_ranges(self) -> None:
        ctx = {"ranges": [{"start": 0, "length": 15}, {"start": 10, "length": 10}]}
        ok, msg = _eval_no_overlap(ctx, self._cond())
        assert ok is False
        assert msg == "overlap.found"

    def test_adjacent_not_overlapping(self) -> None:
        # End of first == start of second: touching, not overlapping
        ctx = {"ranges": [{"start": 0, "length": 10}, {"start": 10, "length": 5}]}
        ok, _ = _eval_no_overlap(ctx, self._cond())
        assert ok is True

    def test_single_range(self) -> None:
        ctx = {"ranges": [{"start": 5, "length": 20}]}
        ok, _ = _eval_no_overlap(ctx, self._cond())
        assert ok is True

    def test_empty_array(self) -> None:
        ctx: dict[str, Any] = {"ranges": []}
        ok, _ = _eval_no_overlap(ctx, self._cond())
        assert ok is True

    def test_missing_field_returns_pass(self) -> None:
        # When the field is absent from context, we cannot evaluate -> pass
        ok, _ = _eval_no_overlap({}, self._cond())
        assert ok is True


class TestFullCoverage:
    def _cond(self, total: int | None = None) -> dict[str, Any]:
        c: dict[str, Any] = {
            "op": "full_coverage",
            "over": "ranges",
            "start_field": "start",
            "length_field": "length",
            "on_violation": {"status": "coverage.gap"},
        }
        if total is not None:
            c["total_field"] = "total_size"
        return c

    def test_complete_coverage(self) -> None:
        ctx = {
            "ranges": [{"start": 0, "length": 10}, {"start": 10, "length": 10}],
            "total_size": 20,
        }
        ok, _ = _eval_full_coverage(ctx, self._cond(total=20))
        assert ok is True

    def test_gap_in_coverage(self) -> None:
        ctx = {
            "ranges": [{"start": 0, "length": 5}, {"start": 10, "length": 5}],
            "total_size": 15,
        }
        ok, msg = _eval_full_coverage(ctx, self._cond(total=15))
        assert ok is False
        assert msg == "coverage.gap"

    def test_overlapping_ranges_still_covers(self) -> None:
        ctx = {
            "ranges": [{"start": 0, "length": 15}, {"start": 10, "length": 10}],
            "total_size": 20,
        }
        ok, _ = _eval_full_coverage(ctx, self._cond(total=20))
        assert ok is True

    def test_no_total_with_gap(self) -> None:
        # Without total_field, we rely on internal gap detection from 0
        ctx = {"ranges": [{"start": 5, "length": 5}]}
        cond = {
            "op": "full_coverage",
            "over": "ranges",
            "start_field": "start",
            "length_field": "length",
            "on_violation": {"status": "coverage.gap"},
        }
        ok, msg = _eval_full_coverage(ctx, cond)
        assert ok is False
        assert msg == "coverage.gap"

    def test_no_total_contiguous_from_zero(self) -> None:
        ctx = {"ranges": [{"start": 0, "length": 10}, {"start": 10, "length": 10}]}
        cond = {
            "op": "full_coverage",
            "over": "ranges",
            "start_field": "start",
            "length_field": "length",
            "on_violation": {"status": "coverage.gap"},
        }
        ok, _ = _eval_full_coverage(ctx, cond)
        assert ok is True


class TestOneOfContent:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "one_of_content",
            "field": "content_type",
            "allowed": ["c2pa_manifest_store", "zero_padding", "format_specific_padding"],
            "on_violation": {"status": "assertion.dataHash.badContentType"},
        }

    def test_value_in_allowed(self) -> None:
        ok, _ = _eval_one_of_content({"content_type": "zero_padding"}, self._cond())
        assert ok is True

    def test_value_not_in_allowed(self) -> None:
        ok, msg = _eval_one_of_content({"content_type": "unknown_type"}, self._cond())
        assert ok is False
        assert msg == "assertion.dataHash.badContentType"

    def test_missing_field(self) -> None:
        ok, msg = _eval_one_of_content({}, self._cond())
        assert ok is False
        assert msg == "assertion.dataHash.badContentType"


class TestOneOfType:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "one_of_type",
            "field": "exclusion_type",
            "allowed": ["c2pa_required", "free", "skip"],
            "on_violation": {"status": "assertion.dataHash.badType"},
        }

    def test_value_in_allowed(self) -> None:
        ok, _ = _eval_one_of_type({"exclusion_type": "free"}, self._cond())
        assert ok is True

    def test_value_not_in_allowed(self) -> None:
        ok, msg = _eval_one_of_type({"exclusion_type": "reserved"}, self._cond())
        assert ok is False
        assert msg == "assertion.dataHash.badType"

    def test_missing_field(self) -> None:
        ok, msg = _eval_one_of_type({}, self._cond())
        assert ok is False
        assert msg == "assertion.dataHash.badType"


class TestNoneOfPatterns:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "none_of_patterns",
            "field": "uri",
            "patterns": [r"^\.\./", r"^/", r"^[a-zA-Z]:/"],
            "on_violation": {"status": "assertion.collectionHash.invalidURI"},
        }

    def test_valid_relative_uri(self) -> None:
        ok, _ = _eval_none_of_patterns({"uri": "subfolder/image.jpg"}, self._cond())
        assert ok is True

    def test_parent_traversal_forbidden(self) -> None:
        ok, msg = _eval_none_of_patterns({"uri": "../secret.txt"}, self._cond())
        assert ok is False
        assert msg == "assertion.collectionHash.invalidURI"

    def test_absolute_unix_path_forbidden(self) -> None:
        ok, msg = _eval_none_of_patterns({"uri": "/etc/passwd"}, self._cond())
        assert ok is False
        assert msg == "assertion.collectionHash.invalidURI"

    def test_windows_path_forbidden(self) -> None:
        ok, msg = _eval_none_of_patterns({"uri": "C:/Windows/system32"}, self._cond())
        assert ok is False
        assert msg == "assertion.collectionHash.invalidURI"

    def test_missing_field_passes(self) -> None:
        ok, _ = _eval_none_of_patterns({}, self._cond())
        assert ok is True


# ---------------------------------------------------------------------------
# Group 2: Conditional and dispatch
# ---------------------------------------------------------------------------


class TestIf:
    def test_condition_true_then_passes(self) -> None:
        ctx = {"flag": "yes"}
        cond = {
            "op": "if",
            "condition": {"op": "field_present", "field": "flag"},
            "then": {"op": "eq", "field": "flag", "value": "yes"},
        }
        ok, _ = _eval_if(ctx, cond)
        assert ok is True

    def test_condition_true_then_fails(self) -> None:
        ctx = {"flag": "no"}
        cond = {
            "op": "if",
            "condition": {"op": "field_present", "field": "flag"},
            "then": {"op": "eq", "field": "flag", "value": "yes"},
        }
        ok, _ = _eval_if(ctx, cond)
        assert ok is False

    def test_condition_false_skipped(self) -> None:
        # 'then' would fail, but condition is false so we get (True, "")
        ctx: dict[str, Any] = {}
        cond = {
            "op": "if",
            "condition": {"op": "field_present", "field": "missing"},
            "then": {"op": "eq", "field": "missing", "value": "something"},
        }
        ok, _ = _eval_if(ctx, cond)
        assert ok is True


class TestDispatchByType:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "dispatch_by_type",
            "field": "binding_label",
            "routes": {
                "c2pa.hash.data": {"op": "field_present", "field": "data_hash"},
                "c2pa.hash.bmff": {"op": "field_present", "field": "bmff_hash"},
            },
            "on_unknown": {"status": "assertion.unknown"},
        }

    def test_known_route_passes(self) -> None:
        ctx = {"binding_label": "c2pa.hash.data", "data_hash": "abc123"}
        ok, _ = _eval_dispatch_by_type(ctx, self._cond())
        assert ok is True

    def test_known_route_then_fails(self) -> None:
        # Route found but the routed condition fails
        ctx = {"binding_label": "c2pa.hash.data"}  # data_hash is missing
        ok, _ = _eval_dispatch_by_type(ctx, self._cond())
        assert ok is False

    def test_unknown_type(self) -> None:
        ctx = {"binding_label": "c2pa.hash.unknown"}
        ok, msg = _eval_dispatch_by_type(ctx, self._cond())
        assert ok is False
        assert msg == "assertion.unknown"

    def test_missing_field(self) -> None:
        ok, msg = _eval_dispatch_by_type({}, self._cond())
        assert ok is False
        assert msg == "assertion.unknown"


class TestPriorityCheck:
    def test_always_passes(self) -> None:
        ctx = {"manifest_store": {"embedded": True, "remote": "http://example.com"}}
        cond = {
            "op": "priority_check",
            "embedded_field": "manifest_store.embedded",
            "remote_field": "manifest_store.remote",
            "if_both_present": "use_embedded",
        }
        ok, _ = _eval_priority_check(ctx, cond)
        assert ok is True


class TestOrderedFallback:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "ordered_fallback",
            "attempts": [
                {"op": "field_present", "field": "embedded"},
                {"op": "field_present", "field": "link_header"},
            ],
            "on_all_fail": {"status": "manifest.inaccessible"},
        }

    def test_first_succeeds(self) -> None:
        ctx = {"embedded": True}
        ok, _ = _eval_ordered_fallback(ctx, self._cond())
        assert ok is True

    def test_second_succeeds(self) -> None:
        ctx = {"link_header": "http://example.com"}
        ok, _ = _eval_ordered_fallback(ctx, self._cond())
        assert ok is True

    def test_all_fail(self) -> None:
        ok, msg = _eval_ordered_fallback({}, self._cond())
        assert ok is False
        assert msg == "manifest.inaccessible"


# ---------------------------------------------------------------------------
# Group 3: Miscellaneous
# ---------------------------------------------------------------------------


class TestCount:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "count",
            "over": "assertions",
            "filter": {"field": "label", "eq": "c2pa.hash.data"},
            "on_nonzero": {"status": "assertion.multipleDataHash", "result": "informational"},
        }

    def test_nonzero_count(self) -> None:
        ctx = {
            "assertions": [
                {"label": "c2pa.hash.data"},
                {"label": "c2pa.actions"},
                {"label": "c2pa.hash.data"},
            ]
        }
        ok, msg = _eval_count(ctx, self._cond())
        assert ok is True
        assert msg == "assertion.multipleDataHash"

    def test_zero_count(self) -> None:
        ctx = {"assertions": [{"label": "c2pa.actions"}]}
        ok, msg = _eval_count(ctx, self._cond())
        assert ok is True
        assert msg == ""

    def test_empty_array(self) -> None:
        ctx: dict[str, Any] = {"assertions": []}
        ok, msg = _eval_count(ctx, self._cond())
        assert ok is True
        assert msg == ""

    def test_missing_array_passes(self) -> None:
        ok, _ = _eval_count({}, self._cond())
        assert ok is True


class TestMutualExclusion:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "mutual_exclusion",
            "fields": ["field_a", "field_b"],
            "on_violation": {"status": "claim.malformed"},
        }

    def test_only_first_present(self) -> None:
        ok, _ = _eval_mutual_exclusion({"field_a": "value"}, self._cond())
        assert ok is True

    def test_only_second_present(self) -> None:
        ok, _ = _eval_mutual_exclusion({"field_b": "value"}, self._cond())
        assert ok is True

    def test_both_present_fails(self) -> None:
        ok, msg = _eval_mutual_exclusion({"field_a": "x", "field_b": "y"}, self._cond())
        assert ok is False
        assert msg == "claim.malformed"

    def test_neither_present(self) -> None:
        ok, _ = _eval_mutual_exclusion({}, self._cond())
        assert ok is True


class TestOrderedMatch:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "ordered_match",
            "actual": "boxes_in_asset",
            "expected": "expected_boxes",
            "match_field": "name",
            "on_mismatch": {"status": "assertion.boxesHash.mismatch"},
        }

    def test_matching_arrays(self) -> None:
        ctx = {
            "boxes_in_asset": [{"name": "ftyp"}, {"name": "mdat"}],
            "expected_boxes": [{"name": "ftyp"}, {"name": "mdat"}],
        }
        ok, _ = _eval_ordered_match(ctx, self._cond())
        assert ok is True

    def test_mismatched_order(self) -> None:
        ctx = {
            "boxes_in_asset": [{"name": "mdat"}, {"name": "ftyp"}],
            "expected_boxes": [{"name": "ftyp"}, {"name": "mdat"}],
        }
        ok, msg = _eval_ordered_match(ctx, self._cond())
        assert ok is False
        assert msg == "assertion.boxesHash.mismatch"

    def test_different_lengths(self) -> None:
        ctx = {
            "boxes_in_asset": [{"name": "ftyp"}],
            "expected_boxes": [{"name": "ftyp"}, {"name": "mdat"}],
        }
        ok, msg = _eval_ordered_match(ctx, self._cond())
        assert ok is False
        assert msg == "assertion.boxesHash.mismatch"

    def test_empty_arrays_match(self) -> None:
        ctx: dict[str, Any] = {"boxes_in_asset": [], "expected_boxes": []}
        ok, _ = _eval_ordered_match(ctx, self._cond())
        assert ok is True

    def test_missing_actual_passes(self) -> None:
        ctx = {"expected_boxes": [{"name": "ftyp"}]}
        ok, _ = _eval_ordered_match(ctx, self._cond())
        assert ok is True


class TestCoverageCheck:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "coverage_check",
            "hashed_field": "hashed_ranges",
            "rendered_field": "rendered_ranges",
            "on_violation": {"status": "assertion.dataHash.mismatch"},
        }

    def test_full_coverage(self) -> None:
        ctx = {
            "hashed_ranges": [{"start": 0, "length": 100}],
            "rendered_ranges": [{"start": 10, "length": 20}],
        }
        ok, _ = _eval_coverage_check(ctx, self._cond())
        assert ok is True

    def test_gap_in_hashed(self) -> None:
        # Hashed covers [0,10) and [20,30), rendered wants [5,15) -- byte 10-14 not hashed
        ctx = {
            "hashed_ranges": [{"start": 0, "length": 10}, {"start": 20, "length": 10}],
            "rendered_ranges": [{"start": 5, "length": 10}],
        }
        ok, msg = _eval_coverage_check(ctx, self._cond())
        assert ok is False
        assert msg == "assertion.dataHash.mismatch"

    def test_empty_rendered(self) -> None:
        ctx: dict[str, Any] = {
            "hashed_ranges": [{"start": 0, "length": 10}],
            "rendered_ranges": [],
        }
        ok, _ = _eval_coverage_check(ctx, self._cond())
        assert ok is True

    def test_missing_fields_passes(self) -> None:
        ok, _ = _eval_coverage_check({}, self._cond())
        assert ok is True


# ---------------------------------------------------------------------------
# Group 4: Text wrapper operators
# ---------------------------------------------------------------------------


class TestScanForMagic:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "scan_for_magic",
            "magic_bytes": "C2PA_MANIFEST",
            "on_not_found": {"status": "manifest.text.corruptedWrapper"},
        }

    def test_magic_found_in_bytes(self) -> None:
        ctx = {"asset_bytes": b"some data C2PA_MANIFEST more data"}
        ok, _ = _eval_scan_for_magic(ctx, self._cond())
        assert ok is True

    def test_magic_not_found(self) -> None:
        ctx = {"asset_bytes": b"this does not contain the marker"}
        ok, msg = _eval_scan_for_magic(ctx, self._cond())
        assert ok is False
        assert msg == "manifest.text.corruptedWrapper"

    def test_no_asset_bytes_in_context(self) -> None:
        # Without asset_bytes we cannot verify, so we pass
        ok, _ = _eval_scan_for_magic({}, self._cond())
        assert ok is True

    def test_magic_found_in_string(self) -> None:
        ctx = {"asset_bytes": "preamble C2PA_MANIFEST suffix"}
        ok, _ = _eval_scan_for_magic(ctx, self._cond())
        assert ok is True


class TestCheckUniqueness:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "check_uniqueness",
            "on_multiple": {"status": "manifest.text.multipleWrappers"},
        }

    def test_single_wrapper(self) -> None:
        ok, _ = _eval_check_uniqueness({"wrapper_count": 1}, self._cond())
        assert ok is True

    def test_multiple_wrappers(self) -> None:
        ok, msg = _eval_check_uniqueness({"wrapper_count": 3}, self._cond())
        assert ok is False
        assert msg == "manifest.text.multipleWrappers"

    def test_no_count_passes(self) -> None:
        ok, _ = _eval_check_uniqueness({}, self._cond())
        assert ok is True


class TestScanForDelimiters:
    def _cond(self) -> dict[str, Any]:
        return {
            "op": "scan_for_delimiters",
            "begin": "-----BEGIN C2PA MANIFEST-----",
            "end": "-----END C2PA MANIFEST-----",
            "on_not_found": {"status": "manifest.structuredText.noManifest"},
        }

    def test_delimiters_found(self) -> None:
        content = b"text -----BEGIN C2PA MANIFEST----- data -----END C2PA MANIFEST----- end"
        ok, _ = _eval_scan_for_delimiters({"asset_bytes": content}, self._cond())
        assert ok is True

    def test_begin_not_found(self) -> None:
        content = b"text -----END C2PA MANIFEST----- end"
        ok, msg = _eval_scan_for_delimiters({"asset_bytes": content}, self._cond())
        assert ok is False
        assert msg == "manifest.structuredText.noManifest"

    def test_end_not_found(self) -> None:
        content = b"text -----BEGIN C2PA MANIFEST----- data"
        ok, msg = _eval_scan_for_delimiters({"asset_bytes": content}, self._cond())
        assert ok is False
        assert msg == "manifest.structuredText.noManifest"

    def test_neither_found(self) -> None:
        ok, msg = _eval_scan_for_delimiters({"asset_bytes": b"plain text"}, self._cond())
        assert ok is False
        assert msg == "manifest.structuredText.noManifest"

    def test_no_asset_bytes_passes(self) -> None:
        ok, _ = _eval_scan_for_delimiters({}, self._cond())
        assert ok is True

    def test_string_asset_bytes(self) -> None:
        content = "-----BEGIN C2PA MANIFEST----- data -----END C2PA MANIFEST-----"
        ok, _ = _eval_scan_for_delimiters({"asset_bytes": content}, self._cond())
        assert ok is True
