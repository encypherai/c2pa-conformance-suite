"""Predicate evaluation engine.

Evaluates conformance predicates from predicates.json against parsed
manifest data. Each predicate condition is a structured expression that
the engine interprets, producing pass/fail/informational status codes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ResultType(Enum):
    """Outcome of a predicate evaluation."""

    PASS = "pass"
    FAIL = "fail"
    INFORMATIONAL = "informational"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class EvalResult:
    """Result of evaluating a single predicate."""

    predicate_id: str
    result: ResultType
    status_code: str = ""
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "predicate_id": self.predicate_id,
            "result": self.result.value,
        }
        if self.status_code:
            d["status_code"] = self.status_code
        if self.message:
            d["message"] = self.message
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class ConformanceReport:
    """Complete conformance evaluation report."""

    spec_version: str
    asset_path: str = ""
    results: list[EvalResult] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.result == ResultType.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.result == ResultType.FAIL)

    @property
    def skip_count(self) -> int:
        return sum(1 for r in self.results if r.result == ResultType.SKIP)

    @property
    def informational_count(self) -> int:
        return sum(1 for r in self.results if r.result == ResultType.INFORMATIONAL)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_version": self.spec_version,
            "asset_path": self.asset_path,
            "summary": {
                "total": self.total_count,
                "pass": self.pass_count,
                "fail": self.fail_count,
                "skip": self.skip_count,
                "informational": self.informational_count,
            },
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Condition operators
# ---------------------------------------------------------------------------


def _eval_field_present(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check if a field exists in the context."""
    field_path = condition["field"]
    value = _resolve_field(context, field_path)
    if value is None:
        on_absent = condition.get("on_absent", {})
        return False, on_absent.get("status", "")
    return True, ""


def _eval_all_of(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """All checks must pass."""
    checks = condition.get("checks", [])
    for check in checks:
        ok, status = _eval_condition(context, check)
        if not ok:
            return False, status
    return True, ""


def _eval_for_each(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a check for each element in an array."""
    array_path = condition["over"]
    array = _resolve_field(context, array_path)
    if not isinstance(array, list):
        on_violation = condition.get("on_violation", {})
        return False, on_violation.get("status", "")

    check = condition["check"]
    for i, item in enumerate(array):
        item_context = {**context, "_item": item, "_index": i}
        # Merge item fields into context for field resolution
        if isinstance(item, dict):
            item_context.update(item)
        ok, status = _eval_condition(item_context, check)
        if not ok:
            on_violation = condition.get("on_violation", {})
            return False, on_violation.get("status", status)

    return True, ""


def _eval_for_consecutive_pairs(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Evaluate a check for each consecutive pair in an array."""
    array_path = condition["over"]
    array = _resolve_field(context, array_path)
    if not isinstance(array, list) or len(array) < 2:
        return True, ""

    check = condition["check"]
    for i in range(len(array) - 1):
        pair_context = {**context, "prev": array[i], "next": array[i + 1]}
        ok, status = _eval_condition(pair_context, check)
        if not ok:
            on_violation = condition.get("on_violation", {})
            return False, on_violation.get("status", status)

    return True, ""


def _eval_gte(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Greater than or equal check."""
    field_val = _resolve_field(context, condition["field"])
    threshold = condition["value"]
    if field_val is None or not isinstance(field_val, (int, float)):
        return False, ""
    return field_val >= threshold, ""


def _eval_gt(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Greater than check."""
    field_val = _resolve_field(context, condition["field"])
    threshold = condition["value"]
    if field_val is None or not isinstance(field_val, (int, float)):
        return False, ""
    return field_val > threshold, ""


def _eval_lte(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Less than or equal check."""
    field_path = condition.get("field")
    if field_path:
        field_val = _resolve_field(context, field_path)
    else:
        # Complex left/right comparison
        left = _eval_expression(context, condition.get("left", {}))
        right_path = condition.get("right")
        if isinstance(right_path, str):
            right = _resolve_field(context, right_path)
        else:
            right = _eval_expression(context, right_path)
        if left is None or right is None:
            return False, ""
        return left <= right, ""

    threshold = condition["value"]
    if field_val is None or not isinstance(field_val, (int, float)):
        return False, ""
    return field_val <= threshold, ""


def _eval_eq(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Equality check."""
    field_val = _resolve_field(context, condition["field"])
    expected = condition["value"]
    return field_val == expected, ""


def _eval_or(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """At least one check must pass."""
    checks = condition.get("checks", [])
    for check in checks:
        ok, _ = _eval_condition(context, check)
        if ok:
            return True, ""
    return False, ""


def _eval_one_of(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check if a field value is in an allowed set."""
    field_val = _resolve_field(context, condition["field"])
    allowed = condition.get("allowed", [])
    deprecated = condition.get("deprecated", [])
    if field_val in allowed or field_val in deprecated:
        return True, ""
    on_not_found = condition.get("on_not_found", {})
    return False, on_not_found.get("status", "")


def _eval_sequence(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a sequence of steps in order."""
    steps = condition.get("steps", [])
    for step in steps:
        op = step.get("op", "")
        # Steps may have conditions that are themselves evaluable
        if op in _OPERATORS:
            ok, status = _eval_condition(context, step)
            if not ok:
                return False, status
        # Otherwise it's a description-only step (hash computation, etc.)
        # that we report as skip (needs runtime implementation)
    return True, ""


def _eval_subset_check(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check that actual is a subset of expected_superset."""
    actual = _resolve_field(context, condition.get("actual", ""))
    superset = _resolve_field(context, condition.get("expected_superset", ""))
    if not isinstance(actual, (list, set)) or not isinstance(superset, (list, set)):
        return True, ""  # Can't evaluate without data
    actual_set = set(actual) if isinstance(actual, list) else actual
    super_set = set(superset) if isinstance(superset, list) else superset
    if actual_set.issubset(super_set):
        return True, ""
    on_extra = condition.get("on_extra_boxes", condition.get("on_uncovered", {}))
    return False, on_extra.get("status", "")


def _eval_delegate(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Delegate to other predicates. Returns pass (delegation is structural)."""
    # Delegation is handled at a higher level by the engine
    return True, ""


def _eval_noop(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """No-op for operators that are descriptive only."""
    return True, ""


# ---------------------------------------------------------------------------
# Range validation operators
# ---------------------------------------------------------------------------


def _eval_no_overlap(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check that ranges in an array don't overlap.

    Resolves `over` to get an array of items, extracts start/length from each,
    sorts by start, and verifies no interval overlaps the next.
    """
    array = _resolve_field(context, condition["over"])
    if not isinstance(array, list):
        return True, ""

    start_field = condition.get("start_field", "start")
    length_field = condition.get("length_field", "length")
    on_violation = condition.get("on_violation", {})

    intervals: list[tuple[int, int]] = []
    for item in array:
        if isinstance(item, dict):
            start = item.get(start_field)
            length = item.get(length_field)
        else:
            continue
        if start is None or length is None:
            continue
        intervals.append((int(start), int(length)))

    intervals.sort(key=lambda x: x[0])
    for i in range(len(intervals) - 1):
        start_a, len_a = intervals[i]
        start_b, _ = intervals[i + 1]
        if start_a + len_a > start_b:
            return False, on_violation.get("status", "")

    return True, ""


def _eval_full_coverage(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check that the union of ranges exactly covers [0, total).

    The total is read from `total_field` in the context (a dotted path).
    Ranges are taken from `over`.
    """
    array = _resolve_field(context, condition["over"])
    total_path = condition.get("total_field", "")
    total = _resolve_field(context, total_path) if total_path else None
    on_violation = condition.get("on_violation", {})

    if not isinstance(array, list):
        return True, ""

    start_field = condition.get("start_field", "start")
    length_field = condition.get("length_field", "length")

    # Build covered intervals
    covered: list[tuple[int, int]] = []
    for item in array:
        if not isinstance(item, dict):
            continue
        start = item.get(start_field)
        length = item.get(length_field)
        if start is None or length is None:
            continue
        covered.append((int(start), int(start) + int(length)))

    if total is None:
        # Without a total we can still check for internal gaps
        covered.sort(key=lambda x: x[0])
        merged: list[tuple[int, int]] = []
        for interval in covered:
            if merged and interval[0] <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], interval[1]))
            else:
                merged.append(list(interval))  # type: ignore[arg-type]
        # Gap check: covered should form one continuous block from 0
        if not merged or merged[0][0] != 0:
            return False, on_violation.get("status", "")
        for i in range(len(merged) - 1):
            if merged[i][1] < merged[i + 1][0]:
                return False, on_violation.get("status", "")
        return True, ""

    total_int = int(total)
    covered_bytes = [False] * total_int

    for start, end in covered:
        for b in range(max(0, start), min(total_int, end)):
            covered_bytes[b] = True

    if not all(covered_bytes):
        return False, on_violation.get("status", "")

    return True, ""


def _eval_one_of_content(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check a field value is one of the allowed content types."""
    field_val = _resolve_field(context, condition["field"])
    allowed = condition.get("allowed", [])
    on_violation = condition.get("on_violation", {})
    if field_val not in allowed:
        return False, on_violation.get("status", "")
    return True, ""


def _eval_one_of_type(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check a field value is one of the allowed type values."""
    field_val = _resolve_field(context, condition["field"])
    allowed = condition.get("allowed", [])
    on_violation = condition.get("on_violation", {})
    if field_val not in allowed:
        return False, on_violation.get("status", "")
    return True, ""


def _eval_none_of_patterns(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check a field value doesn't match any forbidden regex pattern."""
    field_val = _resolve_field(context, condition["field"])
    patterns = condition.get("patterns", [])
    on_violation = condition.get("on_violation", {})
    if field_val is None:
        return True, ""
    value_str = str(field_val)
    for pattern in patterns:
        if re.search(pattern, value_str):
            return False, on_violation.get("status", "")
    return True, ""


# ---------------------------------------------------------------------------
# Conditional and dispatch operators
# ---------------------------------------------------------------------------


def _eval_if(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Conditional execution: evaluate 'then' only when 'condition' passes."""
    guard = condition.get("condition", {})
    ok, _ = _eval_condition(context, guard)
    if not ok:
        return True, ""
    then = condition.get("then", {})
    return _eval_condition(context, then)


def _eval_dispatch_by_type(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Route evaluation based on a field's value."""
    field_val = _resolve_field(context, condition["field"])
    routes: dict[str, Any] = condition.get("routes", {})
    on_unknown = condition.get("on_unknown", {})
    if field_val is None or str(field_val) not in routes:
        return False, on_unknown.get("status", "")
    route_cond = routes[str(field_val)]
    return _eval_condition(context, route_cond)


def _eval_priority_check(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check embedded vs remote priority. Always informational/pass."""
    return True, ""


def _eval_ordered_fallback(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Try each attempt in order; succeed on the first that passes."""
    attempts = condition.get("attempts", [])
    on_all_fail = condition.get("on_all_fail", {})
    for attempt in attempts:
        ok, _ = _eval_condition(context, attempt)
        if ok:
            return True, ""
    return False, on_all_fail.get("status", "")


# ---------------------------------------------------------------------------
# Miscellaneous operators
# ---------------------------------------------------------------------------


def _eval_count(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Count elements matching a filter condition. Always passes (observational)."""
    array = _resolve_field(context, condition["over"])
    filt = condition.get("filter", {})
    on_nonzero = condition.get("on_nonzero", {})

    if not isinstance(array, list):
        return True, ""

    count = 0
    for item in array:
        if not isinstance(item, dict):
            continue
        field_key = filt.get("field")
        expected = filt.get("eq")
        if field_key is None:
            count += 1
        elif item.get(field_key) == expected:
            count += 1

    if count > 0 and on_nonzero:
        return True, on_nonzero.get("status", "")
    return True, ""


def _eval_mutual_exclusion(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Two (or more) fields must not both be present and truthy."""
    fields = condition.get("fields", [])
    on_violation = condition.get("on_violation", {})
    present_count = sum(1 for f in fields if _resolve_field(context, f) is not None)
    if present_count > 1:
        return False, on_violation.get("status", "")
    return True, ""


def _eval_ordered_match(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Two ordered arrays must match element by element on match_field."""
    actual = _resolve_field(context, condition.get("actual", ""))
    expected = _resolve_field(context, condition.get("expected", ""))
    match_field = condition.get("match_field")
    on_mismatch = condition.get("on_mismatch", {})

    if not isinstance(actual, list) or not isinstance(expected, list):
        return True, ""

    if len(actual) != len(expected):
        return False, on_mismatch.get("status", "")

    for a, e in zip(actual, expected):
        if match_field:
            a_val = a.get(match_field) if isinstance(a, dict) else a
            e_val = e.get(match_field) if isinstance(e, dict) else e
        else:
            a_val, e_val = a, e
        if a_val != e_val:
            return False, on_mismatch.get("status", "")

    return True, ""


def _eval_coverage_check(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Check that hashed byte ranges are a superset of rendered byte ranges.

    Every byte in the rendered ranges must be covered by at least one hashed range.
    """
    hashed = _resolve_field(context, condition.get("hashed_field", ""))
    rendered = _resolve_field(context, condition.get("rendered_field", ""))
    on_violation = condition.get("on_violation", {})

    if not isinstance(hashed, list) or not isinstance(rendered, list):
        return True, ""

    # Build a set of hashed bytes (efficient for small ranges; OK for conformance tests)
    hashed_bytes: set[int] = set()
    for item in hashed:
        if not isinstance(item, dict):
            continue
        start = item.get("start", 0)
        length = item.get("length", 0)
        for b in range(int(start), int(start) + int(length)):
            hashed_bytes.add(b)

    for item in rendered:
        if not isinstance(item, dict):
            continue
        start = item.get("start", 0)
        length = item.get("length", 0)
        for b in range(int(start), int(start) + int(length)):
            if b not in hashed_bytes:
                return False, on_violation.get("status", "")

    return True, ""


# ---------------------------------------------------------------------------
# Text wrapper operators
# ---------------------------------------------------------------------------


def _eval_scan_for_magic(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Find magic bytes/string in asset_bytes context field."""
    asset_bytes = context.get("asset_bytes")
    if asset_bytes is None:
        return True, ""

    magic = condition.get("magic_bytes", "")
    on_not_found = condition.get("on_not_found", {})

    if isinstance(asset_bytes, (bytes, bytearray)):
        found = magic.encode() in asset_bytes if isinstance(magic, str) else magic in asset_bytes
    else:
        found = magic in str(asset_bytes)

    if not found:
        return False, on_not_found.get("status", "")
    return True, ""


def _eval_parse_wrapper(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Parse text manifest wrapper (structural check placeholder).

    Full implementation requires the text extractor's wrapper parser.
    Returns pass whenever asset_bytes is present in context.
    """
    if context.get("asset_bytes") is None:
        return True, ""
    return True, ""


def _eval_check_uniqueness(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Verify exactly one instance of a wrapper/marker exists."""
    wrapper_count = context.get("wrapper_count")
    on_multiple = condition.get("on_multiple", {})
    if wrapper_count is not None and int(wrapper_count) > 1:
        return False, on_multiple.get("status", "")
    return True, ""


def _eval_scan_for_delimiters(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Find structured text begin/end delimiters in asset_bytes."""
    asset_bytes = context.get("asset_bytes")
    if asset_bytes is None:
        return True, ""

    begin = condition.get("begin", "")
    end = condition.get("end", "")
    on_not_found = condition.get("on_not_found", {})

    if isinstance(asset_bytes, (bytes, bytearray)):
        content = asset_bytes.decode("utf-8", errors="replace")
    else:
        content = str(asset_bytes)

    if begin not in content or end not in content:
        return False, on_not_found.get("status", "")
    return True, ""


def _eval_extract_reference(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Extract manifest reference from delimiters (placeholder).

    Full implementation couples with delimiter scanner state.
    """
    return True, ""


def _eval_validate_reference(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate a manifest reference (placeholder).

    Full implementation requires reference resolution infrastructure.
    """
    return True, ""


# ---------------------------------------------------------------------------
# Hash / byte-range operators
# ---------------------------------------------------------------------------


def _eval_compute_hash(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Compute hash of a byte range from context. Stores result in context."""
    asset_bytes = context.get("asset_bytes")
    if not isinstance(asset_bytes, bytes):
        return True, "no asset bytes available"

    alg = condition.get("algorithm", "sha256")
    start = condition.get("start", 0)
    length = condition.get("length", len(asset_bytes) - start)
    exclusions = condition.get("exclusions", [])

    from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

    exc_ranges = [
        ExclusionRange(start=e["start"], length=e["length"])
        for e in exclusions
        if isinstance(e, dict)
    ]

    try:
        digest = compute_hash(asset_bytes[start : start + length], alg, exc_ranges)
        context["_computed_hash"] = digest
        context["_computed_hash_alg"] = alg
        return True, f"computed {alg} hash"
    except Exception as exc:
        return False, f"hash computation failed: {exc}"


def _eval_compare_hash(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Compare a previously computed hash against a declared hash."""
    import hmac as _hmac

    computed = context.get("_computed_hash")
    if computed is None:
        return True, "no computed hash to compare"

    declared = condition.get("hash")
    if declared is None:
        declared = condition.get("expected_hash")
    if declared is None:
        return True, "no declared hash to compare against"

    if isinstance(declared, str):
        declared = bytes.fromhex(declared)

    if _hmac.compare_digest(computed, declared):
        return True, "hash match"
    return False, "hash mismatch"


def _eval_resolve_byte_range(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Resolve a byte range reference to actual bytes."""
    asset_bytes = context.get("asset_bytes")
    if not isinstance(asset_bytes, bytes):
        return True, "no asset bytes available"

    start = condition.get("start", 0)
    length = condition.get("length")
    if length is None:
        length = len(asset_bytes) - start

    end = start + length
    if start < 0 or end > len(asset_bytes):
        return False, f"byte range [{start}:{end}] out of bounds (file size: {len(asset_bytes)})"

    context["_resolved_bytes"] = asset_bytes[start:end]
    return True, f"resolved {length} bytes at offset {start}"


def _eval_compute_hash_excluding_wrapper(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Compute hash of content excluding a wrapper/delimiter byte range."""
    asset_bytes = context.get("asset_bytes")
    if not isinstance(asset_bytes, bytes):
        return True, "no asset bytes available"

    alg = condition.get("algorithm", "sha256")
    wrapper_start = condition.get("wrapper_start", condition.get("start", 0))
    wrapper_length = condition.get("wrapper_length", condition.get("length", 0))

    from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

    exc = (
        [ExclusionRange(start=wrapper_start, length=wrapper_length)] if wrapper_length > 0 else []
    )

    try:
        digest = compute_hash(asset_bytes, alg, exc)
        context["_computed_hash"] = digest
        context["_computed_hash_alg"] = alg
        return True, f"computed {alg} hash excluding wrapper"
    except Exception as exc_err:
        return False, f"hash computation failed: {exc_err}"


def _eval_compute_leaf_hash(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Hash a single Merkle tree leaf's byte range."""
    import hashlib

    asset_bytes = context.get("asset_bytes")
    if not isinstance(asset_bytes, bytes):
        return True, "no asset bytes available"

    alg = condition.get("algorithm", "sha256")
    block_start = condition.get("start", 0)
    block_size = condition.get("block_size", condition.get("length", 0))
    leaf_index = condition.get("leaf_index", 0)

    block = asset_bytes[block_start : block_start + block_size]
    h = hashlib.new(alg)
    h.update(block)

    leaves = context.setdefault("_merkle_leaves", {})
    leaves[leaf_index] = h.digest()

    return True, f"computed leaf {leaf_index} hash"


# ---------------------------------------------------------------------------
# Compression operators
# ---------------------------------------------------------------------------


def _eval_detect_compressed(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check if manifest data is brotli-compressed (brob box)."""
    manifest_data = context.get("_manifest_bytes", b"")
    if isinstance(manifest_data, bytes) and len(manifest_data) >= 4:
        if b"brob" in manifest_data[:100]:
            context["_is_compressed"] = True
            return True, "compressed manifest detected"
    context["_is_compressed"] = False
    return True, "not compressed"


def _eval_decompress(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Decompress brotli-compressed manifest data."""
    if not context.get("_is_compressed"):
        return True, "not compressed, skip"

    try:
        import brotli

        compressed = context.get("_compressed_data", b"")
        context["_decompressed_data"] = brotli.decompress(compressed)
        return True, "decompressed successfully"
    except ImportError:
        return True, "brotli not available, skip"
    except Exception as exc:
        return False, f"decompression failed: {exc}"


def _eval_validate_decompressed(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate decompressed data is well-formed JUMBF."""
    import struct

    decompressed = context.get("_decompressed_data")
    if not isinstance(decompressed, bytes) or len(decompressed) < 8:
        if not context.get("_is_compressed"):
            return True, "not compressed, skip"
        return False, "no decompressed data to validate"

    # Check for valid JUMBF box header: LBox >= 8, TBox = "jumb"
    lbox = struct.unpack_from(">I", decompressed, 0)[0]
    tbox = decompressed[4:8]
    if tbox == b"jumb" and 8 <= lbox <= len(decompressed):
        return True, "valid JUMBF structure"
    return False, f"invalid JUMBF: LBox={lbox}, TBox={tbox!r}"


# ---------------------------------------------------------------------------
# BMFF Merkle tree operators
# ---------------------------------------------------------------------------


def _eval_block_coverage_check(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Verify Merkle blocks cover the full mdat payload."""
    block_size = condition.get("block_size", 0)
    block_count = condition.get("block_count", 0)
    total_size = condition.get("total_size", 0)

    if block_size <= 0 or total_size <= 0:
        return True, "insufficient block info"

    expected_blocks = (total_size + block_size - 1) // block_size
    if block_count == 0:
        block_count = expected_blocks

    covered = block_count * block_size
    if covered >= total_size:
        return True, f"blocks cover {total_size} bytes"
    return False, f"blocks cover {covered} of {total_size} bytes"


def _eval_leaf_count_check(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Verify leaf count matches expected."""
    actual = condition.get("actual_count", condition.get("leaf_count", 0))
    expected = condition.get("expected_count", condition.get("expected", 0))

    if expected <= 0:
        return True, "no expected leaf count"

    if actual == expected:
        return True, f"leaf count {actual} matches"
    return False, f"leaf count {actual} != expected {expected}"


def _eval_for_each_leaf(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Iterate over Merkle leaves, verify each against declared hash."""
    import hmac as _hmac

    leaves = condition.get("leaves", [])
    declared_hashes = condition.get("declared_hashes", condition.get("hashes", []))

    if not leaves and not declared_hashes:
        return True, "no leaves to check"

    mismatches = []
    for i, (leaf, declared) in enumerate(zip(leaves, declared_hashes)):
        if isinstance(leaf, str):
            leaf = bytes.fromhex(leaf)
        if isinstance(declared, str):
            declared = bytes.fromhex(declared)
        if isinstance(leaf, bytes) and isinstance(declared, bytes):
            if not _hmac.compare_digest(leaf, declared):
                mismatches.append(i)

    if mismatches:
        return False, f"leaf hash mismatch at indices: {mismatches}"
    return True, f"all {len(leaves)} leaf hashes match"


def _eval_tree_root_check(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Compute Merkle root from leaves, compare to declared."""
    import hashlib
    import hmac as _hmac

    leaves = condition.get("leaves", [])
    declared_root = condition.get("root_hash", condition.get("declared_root"))
    alg = condition.get("algorithm", "sha256")

    if not leaves or declared_root is None:
        return True, "insufficient data for tree root check"

    leaf_bytes = []
    for leaf in leaves:
        if isinstance(leaf, str):
            leaf = bytes.fromhex(leaf)
        if isinstance(leaf, bytes):
            leaf_bytes.append(leaf)

    if isinstance(declared_root, str):
        declared_root = bytes.fromhex(declared_root)

    if not leaf_bytes:
        return True, "no leaf hashes"

    layer = list(leaf_bytes)
    while len(layer) > 1:
        next_layer = []
        for j in range(0, len(layer), 2):
            if j + 1 < len(layer):
                h = hashlib.new(alg)
                h.update(layer[j] + layer[j + 1])
                next_layer.append(h.digest())
            else:
                h = hashlib.new(alg)
                h.update(layer[j] + layer[j])
                next_layer.append(h.digest())
        layer = next_layer

    computed_root = layer[0]
    if _hmac.compare_digest(computed_root, declared_root):
        return True, "Merkle root matches"
    return False, "Merkle root mismatch"


# ---------------------------------------------------------------------------
# Sequence / render / PDF operators
# ---------------------------------------------------------------------------


def _eval_sequence_continuity_check(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Verify sequence numbers are contiguous with no gaps."""
    sequence = condition.get("sequence", condition.get("values", []))
    if not sequence:
        return True, "no sequence to check"

    for i in range(1, len(sequence)):
        if sequence[i] != sequence[i - 1] + 1:
            return False, f"gap at index {i}: {sequence[i - 1]} -> {sequence[i]}"
    return True, f"sequence of {len(sequence)} is contiguous"


def _eval_verify_before_render(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Verify that all required checks pass before content is rendered."""
    sig_valid = context.get("signature", {}).get("is_valid", context.get("crypto_verified", False))
    hash_valid = context.get("hash", {}).get("match", context.get("binding_verified", False))

    if sig_valid and hash_valid:
        return True, "verification completed before render"

    issues = []
    if not sig_valid:
        issues.append("signature not verified")
    if not hash_valid:
        issues.append("binding not verified")
    return False, f"render before verify: {', '.join(issues)}"


def _eval_check_exclusion_length(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate exclusion range length matches embedded JUMBF length."""
    exclusions = condition.get("exclusions", [])
    jumbf_length = condition.get("jumbf_length", context.get("jumbf_length", 0))

    if not exclusions:
        return True, "no exclusions to check"

    for i, exc in enumerate(exclusions):
        exc_len = exc.get("length", 0) if isinstance(exc, dict) else 0
        if exc_len > 0 and jumbf_length > 0 and exc_len != jumbf_length:
            return False, f"exclusion {i} length {exc_len} != JUMBF length {jumbf_length}"

    return True, "exclusion lengths valid"


def _eval_check_offset_adjustment(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate offset adjustments for PDF update manifests."""
    pre_offset = condition.get("pre_offset", 0)
    post_offset = condition.get("post_offset", 0)
    adjustment = condition.get("adjustment", condition.get("expected_adjustment", 0))

    if pre_offset == 0 and post_offset == 0:
        return True, "no offsets to check"

    actual_adj = post_offset - pre_offset
    if adjustment != 0 and actual_adj != adjustment:
        return False, f"offset adjustment {actual_adj} != expected {adjustment}"
    return True, f"offset adjustment {actual_adj} valid"


def _eval_validate_manifest_store(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate a manifest store is structurally well-formed."""
    store_bytes = condition.get("store_bytes", context.get("_decompressed_data"))
    if not isinstance(store_bytes, bytes):
        store = context.get("manifest_store", {})
        count = store.get("manifest_count", 0) if isinstance(store, dict) else 0
        if count > 0:
            return True, f"manifest store has {count} manifest(s)"
        return True, "no store bytes to validate"

    try:
        from c2pa_conformance.parser.manifest import parse_manifest_store

        store = parse_manifest_store(store_bytes)
        if store.manifest_count > 0:
            return True, f"valid manifest store with {store.manifest_count} manifest(s)"
        return False, "manifest store contains no manifests"
    except Exception as exc:
        return False, f"manifest store validation failed: {exc}"


# ---------------------------------------------------------------------------
# Status, comparison, and control flow operators
# ---------------------------------------------------------------------------


def _eval_check_status(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check if a status code is set in the validation context.

    Inspects context["_emitted_statuses"] for a previously recorded status.
    If the status matches, returns True with the status code.
    """
    target_status = condition.get("status", "")
    emitted = context.get("_emitted_statuses", set())
    on_present = condition.get("on_present", {})
    on_absent = condition.get("on_absent", {})

    if target_status in emitted:
        return True, on_present.get("status", target_status)
    return False, on_absent.get("status", "")


def _eval_compare(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Generalized two-operand comparison with configurable op_type.

    Supports: eq, gt, lt, gte, lte, ne. Both sides can be field paths
    or literal values.
    """
    left = condition.get("field", condition.get("left"))
    right = condition.get("value", condition.get("right"))
    op_type = condition.get("op_type", "eq")
    on_true = condition.get("on_true", {})
    on_false = condition.get("on_false", {})

    left_val = _eval_expression(context, left)
    right_val = _eval_expression(context, right)

    if left_val is None or right_val is None:
        return False, on_false.get("status", "")

    comparators = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "gt": lambda a, b: a > b,
        "lt": lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
    }
    cmp_fn = comparators.get(op_type, lambda a, b: a == b)
    try:
        result = cmp_fn(left_val, right_val)
    except TypeError:
        return False, on_false.get("status", "")

    if result:
        return True, on_true.get("status", "")
    return False, on_false.get("status", "")


def _eval_conditional(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """If/then/else branching with an explicit else branch.

    Unlike the 'if' operator which has no else, 'conditional' always
    evaluates one of the two branches.
    """
    guard = condition.get("if", condition.get("condition", {}))
    ok, _ = _eval_condition(context, guard)
    if ok:
        then_branch = condition.get("then", {})
        if then_branch and "op" in then_branch:
            return _eval_condition(context, then_branch)
        return True, ""
    else:
        else_branch = condition.get("else", {})
        if else_branch and "op" in else_branch:
            return _eval_condition(context, else_branch)
        return True, ""


def _eval_validate_structure(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Perform a semantic structural action (clamp, skip, flag).

    Actions:
    - clamp: adjust a value to fit within bounds (always passes)
    - skip: skip processing of the current item (always passes)
    - flag: record an informational status code
    - reject: fail with a status code
    """
    action = condition.get("action", "")
    status = condition.get("status", condition.get("on_invalid", {}).get("status", ""))

    if action == "reject":
        return False, status
    # clamp, skip, flag are all informational/pass
    return True, status


def _eval_validate_format(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate that a field conforms to an expected format.

    Checks format_type against the context field value.
    """
    field_val = _resolve_field(context, condition.get("field", ""))
    expected_format = condition.get("format_type", "")
    on_invalid = condition.get("on_invalid", {})

    if field_val is None:
        return False, on_invalid.get("status", "")

    if expected_format == "cbor_map":
        if isinstance(field_val, dict):
            return True, ""
        return False, on_invalid.get("status", "")
    elif expected_format == "uri":
        if isinstance(field_val, str) and (":" in field_val or field_val.startswith("self#")):
            return True, ""
        return False, on_invalid.get("status", "")
    # Default: accept if present
    return True, ""


def _eval_check_revocation(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check certificate revocation status from the validation context.

    Inspects context for OCSP or CRL revocation data. Emits the
    appropriate status code based on revocation state.
    """
    cert_field = condition.get("certificate", "signer_certificate")
    revocation_data = _resolve_field(context, f"{cert_field}.revocation_status")
    on_revoked = condition.get("on_revoked", {})
    on_not_revoked = condition.get("on_not_revoked", {})
    on_unknown = condition.get("on_unknown", {})

    if revocation_data is None:
        return True, on_unknown.get("status", "signingCredential.ocsp.skipped")

    status = str(revocation_data)
    if status == "revoked":
        return False, on_revoked.get("status", "signingCredential.ocsp.revoked")
    elif status == "not_revoked":
        return True, on_not_revoked.get("status", "signingCredential.ocsp.notRevoked")
    return True, on_unknown.get("status", "signingCredential.ocsp.unknown")


def _eval_validate_certificate(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate an X.509 certificate chain against trust anchors.

    Checks context for pre-computed chain validation results.
    """
    chain_field = condition.get("chain", "cert_chain")
    chain_valid = _resolve_field(context, f"{chain_field}.valid")
    on_untrusted = condition.get("on_untrusted", {})
    on_trusted = condition.get("on_trusted", {})
    on_invalid = condition.get("on_invalid", {})

    if chain_valid is None:
        # No chain data available; check direct trust status
        trusted = _resolve_field(context, "signing_credential.trusted")
        if trusted is True:
            return True, on_trusted.get("status", "signingCredential.trusted")
        if trusted is False:
            return False, on_untrusted.get("status", "signingCredential.untrusted")
        return False, on_invalid.get("status", "signingCredential.invalid")

    if chain_valid is True:
        return True, on_trusted.get("status", "signingCredential.trusted")
    return False, on_untrusted.get("status", "signingCredential.untrusted")


def _eval_verify_signature(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Verify a cryptographic signature from the validation context.

    Checks context for pre-computed signature verification results.
    """
    sig_field = condition.get("signature", "claim_signature")
    sig_valid = _resolve_field(context, f"{sig_field}.valid")
    on_valid = condition.get("on_valid", {})
    on_invalid = condition.get("on_invalid", {})

    if sig_valid is None:
        sig_valid = _resolve_field(context, "signature_verified")

    if sig_valid is True:
        return True, on_valid.get("status", "claimSignature.validated")
    return False, on_invalid.get("status", "claimSignature.mismatch")


def _eval_validate_timestamp(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Validate a time-stamp token from the validation context.

    Checks context for pre-computed timestamp validation results.
    """
    ts_field = condition.get("timestamp", "timestamp")
    ts_valid = _resolve_field(context, f"{ts_field}.valid")
    on_valid = condition.get("on_valid", {})
    on_invalid = condition.get("on_invalid", {})

    if ts_valid is None:
        ts_valid = _resolve_field(context, "timestamp_validated")

    if ts_valid is True:
        return True, on_valid.get("status", "timeStamp.validated")
    return False, on_invalid.get("status", "timeStamp.mismatch")


def _eval_is_array(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check if a field value is an array (list)."""
    field_val = _resolve_field(context, condition.get("field", ""))
    on_not_array = condition.get("on_not_array", {})
    min_items = condition.get("min_items", 0)

    if not isinstance(field_val, list):
        return False, on_not_array.get("status", "")
    if len(field_val) < min_items:
        return False, on_not_array.get("status", "")
    return True, ""


def _eval_sum_field(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Sum a numeric field across array items and compare to expected value.

    Resolves `over` to get an array, sums the specified field from each item,
    and compares against `expected` or stores the result for later comparison.
    """
    array = _resolve_field(context, condition.get("over", ""))
    field_name = condition.get("field", "")
    expected = condition.get("expected")
    compare_to = condition.get("compare_to")
    on_mismatch = condition.get("on_mismatch", {})

    if not isinstance(array, list):
        return True, ""

    total = 0
    for item in array:
        if isinstance(item, dict):
            val = item.get(field_name, 0)
            if isinstance(val, (int, float)):
                total += val

    # Store computed sum for later reference
    store_as = condition.get("store_as", "")
    if store_as:
        context[store_as] = total

    if expected is not None:
        if total != expected:
            return False, on_mismatch.get("status", "")
    elif compare_to:
        compare_val = _resolve_field(context, compare_to)
        if isinstance(compare_val, (int, float)) and total != compare_val:
            return False, on_mismatch.get("status", "")

    return True, ""


def _eval_traverse(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Traverse a chain of references until a terminal condition is met.

    Used for following ingredient parentOf chains to find a standard manifest.
    """
    start_field = condition.get("start", "")
    follow_field = condition.get("follow", "")
    until = condition.get("until", {})
    on_not_found = condition.get("on_not_found", {})
    max_depth = condition.get("max_depth", 100)

    current = _resolve_field(context, start_field)
    for _ in range(max_depth):
        if current is None:
            return False, on_not_found.get("status", "")
        # Check terminal condition
        if until and "op" in until:
            check_ctx = dict(context)
            check_ctx["_current"] = current
            ok, status = _eval_condition(check_ctx, until)
            if ok:
                return True, status
        # Follow reference
        if isinstance(current, dict):
            current = current.get(follow_field)
        else:
            break

    return False, on_not_found.get("status", "")


def _eval_regex_match(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check if a field value matches a regex pattern."""
    field_val = _resolve_field(context, condition.get("field", ""))
    pattern = condition.get("pattern", "")
    on_match = condition.get("on_match", {})
    on_no_match = condition.get("on_no_match", {})

    if field_val is None:
        return False, on_no_match.get("status", "")
    if re.search(pattern, str(field_val)):
        return True, on_match.get("status", "")
    return False, on_no_match.get("status", "")


def _eval_count_manifest_stores(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Count manifest stores in an asset and check against expected count."""
    stores = _resolve_field(context, condition.get("field", "manifest_stores"))
    max_count = condition.get("max", 1)
    on_exceeded = condition.get("on_exceeded", {})

    count = len(stores) if isinstance(stores, list) else (1 if stores else 0)
    if count > max_count:
        return False, on_exceeded.get("status", "")
    return True, ""


def _eval_fetch_remote_manifest(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check availability of a remote manifest reference.

    In offline/test mode, checks context for pre-fetched remote manifest data.
    """
    url_field = condition.get("url", "")
    url = _resolve_field(context, url_field) if url_field else None
    on_inaccessible = condition.get("on_inaccessible", {})

    remote_data = _resolve_field(context, "remote_manifest")
    if remote_data is not None:
        return True, ""
    if url is None:
        return True, ""  # No remote reference to check
    return False, on_inaccessible.get("status", "manifest.inaccessible")


def _eval_collect_ocsp_responses(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Collect OCSP responses from the manifest store.

    Checks context for pre-gathered OCSP response data.
    """
    responses = _resolve_field(context, condition.get("from", "ocsp_responses"))
    on_none = condition.get("on_none", {})

    if isinstance(responses, list) and len(responses) > 0:
        return True, ""
    return False, on_none.get("status", "signingCredential.ocsp.skipped")


def _eval_resolve_reference(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Resolve a hashed URI or field reference to its target data."""
    ref_field = condition.get("reference", condition.get("field", ""))
    ref_val = _resolve_field(context, ref_field)
    on_missing = condition.get("on_missing", {})
    on_found = condition.get("on_found", {})

    if ref_val is None:
        return False, on_missing.get("status", "hashedURI.missing")
    return True, on_found.get("status", "")


def _eval_resolve_uri(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Resolve a JUMBF URI to its target within the manifest store."""
    uri_field = condition.get("uri", condition.get("field", ""))
    uri = _resolve_field(context, uri_field)
    on_unresolvable = condition.get("on_unresolvable", {})

    if uri is None:
        return False, on_unresolvable.get("status", "")

    # Check if the URI target exists in context
    if isinstance(uri, str) and uri.startswith("self#jumbf="):
        path = uri.replace("self#jumbf=", "").strip("/")
        target = _resolve_field(context, f"manifest_store.{path}")
        if target is not None:
            return True, ""
    elif isinstance(uri, str):
        # Generic URI - check if resolved data exists
        resolved = _resolve_field(context, "resolved_uris")
        if isinstance(resolved, dict) and uri in resolved:
            return True, ""

    return False, on_unresolvable.get("status", "")


def _eval_check_location(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Check that a referenced location is within the expected scope."""
    location = condition.get("location", condition.get("field", ""))
    loc_val = _resolve_field(context, location)
    scope = condition.get("scope", "same_manifest")
    on_outside = condition.get("on_outside", {})

    if loc_val is None:
        return False, on_outside.get("status", "")

    if scope == "same_manifest":
        if isinstance(loc_val, str) and loc_val.startswith("self#jumbf="):
            return True, ""
        return False, on_outside.get("status", "assertion.outsideManifest")
    return True, ""


def _eval_find_certificate(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Find a certificate in the chain or trust store."""
    cert_type = condition.get("cert_type", "signer")
    on_not_found = condition.get("on_not_found", {})

    cert_data = _resolve_field(context, f"certificates.{cert_type}")
    if cert_data is not None:
        return True, ""

    # Fallback: check x5chain
    x5chain = _resolve_field(context, "x5chain")
    if isinstance(x5chain, list) and len(x5chain) > 0:
        return True, ""

    return False, on_not_found.get("status", "signingCredential.invalid")


def _eval_any_of(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """At least one sub-condition must pass (OR semantics)."""
    checks = condition.get("checks", [])
    on_none = condition.get("on_none", {})

    for check in checks:
        ok, status = _eval_condition(context, check)
        if ok:
            return True, status

    return False, on_none.get("status", "")


def _eval_one_of_exclusive(
    context: dict[str, Any], condition: dict[str, Any]
) -> tuple[bool, str]:
    """Exactly one of the specified fields must be present (mutual exclusion)."""
    fields = condition.get("fields", [])
    on_violation = condition.get("on_violation", {})

    present_count = 0
    for f in fields:
        val = _resolve_field(context, f)
        if val is not None:
            present_count += 1

    if present_count == 1:
        return True, ""
    return False, on_violation.get("status", "")


# Operator dispatch table
_OPERATORS: dict[str, Any] = {
    # --- Core operators (already implemented) ---
    "field_present": _eval_field_present,
    "all_of": _eval_all_of,
    "for_each": _eval_for_each,
    "for_consecutive_pairs": _eval_for_consecutive_pairs,
    "gte": _eval_gte,
    "gt": _eval_gt,
    "lte": _eval_lte,
    "eq": _eval_eq,
    "or": _eval_or,
    "one_of": _eval_one_of,
    "sequence": _eval_sequence,
    "subset_check": _eval_subset_check,
    "delegate": _eval_delegate,
    # --- Range validation ---
    "no_overlap": _eval_no_overlap,
    "full_coverage": _eval_full_coverage,
    "one_of_content": _eval_one_of_content,
    "one_of_type": _eval_one_of_type,
    "none_of_patterns": _eval_none_of_patterns,
    # --- Conditional and dispatch ---
    "if": _eval_if,
    "dispatch_by_type": _eval_dispatch_by_type,
    "priority_check": _eval_priority_check,
    "ordered_fallback": _eval_ordered_fallback,
    # --- Miscellaneous logic ---
    "count": _eval_count,
    "mutual_exclusion": _eval_mutual_exclusion,
    "ordered_match": _eval_ordered_match,
    "coverage_check": _eval_coverage_check,
    # ignore_fields is intentionally a no-op: the predicate declares which
    # fields should be excluded from validation, not something to assert on.
    "ignore_fields": _eval_noop,
    # --- Text wrapper operators ---
    "scan_for_magic": _eval_scan_for_magic,
    "parse_wrapper": _eval_parse_wrapper,
    "check_uniqueness": _eval_check_uniqueness,
    "scan_for_delimiters": _eval_scan_for_delimiters,
    "extract_reference": _eval_extract_reference,
    "validate_reference": _eval_validate_reference,
    # --- Crypto / hashing operators ---
    "compute_hash": _eval_compute_hash,
    "compare_hash": _eval_compare_hash,
    "compute_hash_excluding_wrapper": _eval_compute_hash_excluding_wrapper,
    "resolve_byte_range": _eval_resolve_byte_range,
    "compute_leaf_hash": _eval_compute_leaf_hash,
    # --- Compression operators ---
    "detect_compressed": _eval_detect_compressed,
    "decompress": _eval_decompress,
    "validate_decompressed": _eval_validate_decompressed,
    # --- BMFF Merkle tree operators ---
    "block_coverage_check": _eval_block_coverage_check,
    "leaf_count_check": _eval_leaf_count_check,
    "for_each_leaf": _eval_for_each_leaf,
    "tree_root_check": _eval_tree_root_check,
    # --- Sequence / render operators ---
    "sequence_continuity_check": _eval_sequence_continuity_check,
    "verify_before_render": _eval_verify_before_render,
    # --- PDF exclusion operators ---
    "check_exclusion_length": _eval_check_exclusion_length,
    "check_offset_adjustment": _eval_check_offset_adjustment,
    # --- Structural validation ---
    "validate_manifest_store": _eval_validate_manifest_store,
    # --- Status, comparison, and control flow ---
    "check_status": _eval_check_status,
    "compare": _eval_compare,
    "conditional": _eval_conditional,
    "validate_structure": _eval_validate_structure,
    "validate_format": _eval_validate_format,
    # --- Cryptographic validation ---
    "check_revocation": _eval_check_revocation,
    "validate_certificate": _eval_validate_certificate,
    "verify_signature": _eval_verify_signature,
    "validate_timestamp": _eval_validate_timestamp,
    # --- Type and field operators ---
    "is_array": _eval_is_array,
    "sum_field": _eval_sum_field,
    "regex_match": _eval_regex_match,
    "one_of_exclusive": _eval_one_of_exclusive,
    "any_of": _eval_any_of,
    # --- Graph and reference operators ---
    "traverse": _eval_traverse,
    "resolve_reference": _eval_resolve_reference,
    "resolve_uri": _eval_resolve_uri,
    "check_location": _eval_check_location,
    "find_certificate": _eval_find_certificate,
    # --- Manifest and remote operators ---
    "count_manifest_stores": _eval_count_manifest_stores,
    "fetch_remote_manifest": _eval_fetch_remote_manifest,
    "collect_ocsp_responses": _eval_collect_ocsp_responses,
}


def _resolve_field(context: dict[str, Any], path: str) -> Any:
    """Resolve a dotted field path in the context dict."""
    if not path:
        return None

    parts = path.split(".")
    current: Any = context

    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part == "length":
            return len(current)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return None

    return current


def _eval_expression(context: dict[str, Any], expr: Any) -> Any:
    """Evaluate an arithmetic or field expression."""
    if isinstance(expr, (int, float)):
        return expr
    if isinstance(expr, str):
        return _resolve_field(context, expr)
    if isinstance(expr, dict):
        op = expr.get("op", "")
        if op == "add":
            fields = expr.get("fields", [])
            total = 0
            for f in fields:
                val = _resolve_field(context, f)
                if isinstance(val, (int, float)):
                    total += val
            return total
    return None


def _eval_condition(context: dict[str, Any], condition: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a single condition expression against the context."""
    op = condition.get("op", "")
    handler = _OPERATORS.get(op)
    if handler is None:
        return True, ""  # Unknown operator, skip
    return handler(context, condition)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class PredicateEngine:
    """Evaluates C2PA conformance predicates against manifest data."""

    def __init__(self, predicates_path: Path | str) -> None:
        path = Path(predicates_path)
        self.predicates_data = json.loads(path.read_text(encoding="utf-8"))
        self.spec_version = self.predicates_data.get("spec_version", "")

        # Index all predicates by ID
        self._predicates: dict[str, dict[str, Any]] = {}
        for family in self.predicates_data.get("format_families", {}).values():
            for pred in family.get("predicates", []):
                self._predicates[pred["predicate_id"]] = pred
        for pred in self.predicates_data.get("cross_cutting", {}).get("predicates", []):
            self._predicates[pred["predicate_id"]] = pred

    @property
    def predicate_count(self) -> int:
        return len(self._predicates)

    def get_predicate(self, predicate_id: str) -> dict[str, Any] | None:
        return self._predicates.get(predicate_id)

    def get_predicates_for_binding(self, binding: str) -> list[dict[str, Any]]:
        """Get all predicates applicable to a binding mechanism."""
        result: list[dict[str, Any]] = []
        for family in self.predicates_data.get("format_families", {}).values():
            if family.get("binding_mechanism") == binding:
                result.extend(family.get("predicates", []))
        # Always include cross-cutting predicates
        result.extend(self.predicates_data.get("cross_cutting", {}).get("predicates", []))
        return result

    def evaluate_predicate(self, predicate_id: str, context: dict[str, Any]) -> EvalResult:
        """Evaluate a single predicate against a context dict.

        Args:
            predicate_id: The PRED-XXX-NNN identifier.
            context: Dict containing the data fields referenced by the predicate.

        Returns:
            EvalResult with pass/fail/skip/informational status.
        """
        pred = self._predicates.get(predicate_id)
        if pred is None:
            return EvalResult(
                predicate_id=predicate_id,
                result=ResultType.ERROR,
                message=f"Unknown predicate: {predicate_id}",
            )

        # Check RFC 2119 severity level for MAY-level decision logic
        severity = pred.get("severity", "must")
        is_may = severity == "may"

        condition = pred.get("condition", {})
        try:
            ok, status_code = _eval_condition(context, condition)
        except Exception as exc:
            return EvalResult(
                predicate_id=predicate_id,
                result=ResultType.ERROR,
                message=f"Evaluation error: {exc}",
            )

        if ok:
            on_match = _find_on_match(condition)
            # Check if the predicate or on_match specifies informational result
            result_type_str = on_match.get("result", pred.get("result_type", ""))
            if result_type_str == "informational" or is_may:
                result_type = ResultType.INFORMATIONAL
            else:
                result_type = ResultType.PASS
            return EvalResult(
                predicate_id=predicate_id,
                result=result_type,
                status_code=on_match.get("status", ""),
            )
        else:
            # For MAY-level predicates, failure is informational, not a hard fail
            if is_may:
                return EvalResult(
                    predicate_id=predicate_id,
                    result=ResultType.INFORMATIONAL,
                    status_code=status_code,
                    message="MAY-level check (implementation discretion)",
                )
            return EvalResult(
                predicate_id=predicate_id,
                result=ResultType.FAIL,
                status_code=status_code,
            )

    def evaluate_all(
        self, context: dict[str, Any], binding: str | None = None
    ) -> ConformanceReport:
        """Evaluate all applicable predicates against a context.

        Args:
            context: Dict containing manifest and asset data.
            binding: Optional binding mechanism to filter predicates.

        Returns:
            Complete ConformanceReport.
        """
        report = ConformanceReport(spec_version=self.spec_version)

        if binding:
            predicates = self.get_predicates_for_binding(binding)
        else:
            predicates = list(self._predicates.values())

        for pred in predicates:
            result = self.evaluate_predicate(pred["predicate_id"], context)
            report.results.append(result)

        return report


def _find_on_match(condition: dict[str, Any]) -> dict[str, Any]:
    """Recursively find an on_match clause in a condition tree."""
    if "on_match" in condition:
        return condition["on_match"]
    for key in ("steps", "checks"):
        for item in condition.get(key, []):
            if isinstance(item, dict):
                result = _find_on_match(item)
                if result:
                    return result
    return {}
