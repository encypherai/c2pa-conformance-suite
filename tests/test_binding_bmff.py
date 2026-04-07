"""Tests for BMFF hash, boxes hash, and BMFF box parser verifiers."""

from __future__ import annotations

import hashlib
import struct

from c2pa_conformance.binding.bmff_hash import (
    _compute_merkle_root,
    verify_bmff_hash,
)
from c2pa_conformance.binding.bmff_parser import (
    classify_exclusion,
    parse_bmff_boxes,
    resolve_xpath_exclusions,
)
from c2pa_conformance.binding.boxes_hash import (
    verify_boxes_hash,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _build_merkle_data(
    block_size: int = 16,
    num_blocks: int = 4,
) -> tuple[bytes, list[bytes], bytes]:
    """Build test data and compute the correct Merkle structure.

    Returns:
        (data, leaves, root) where data is block_size*num_blocks bytes,
        leaves are per-block sha256 digests, and root is the Merkle root.
    """
    # Deterministic bytes that span the range 0-255 repeatedly
    pattern = bytes(range(256))
    needed = block_size * num_blocks
    data = (pattern * (needed // 256 + 1))[:needed]

    leaves: list[bytes] = []
    for i in range(num_blocks):
        chunk = data[i * block_size : (i + 1) * block_size]
        leaves.append(_sha256(chunk))

    level = list(leaves)
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_sha256(left + right))
        level = next_level
    root = level[0]

    return data, leaves, root


# ---------------------------------------------------------------------------
# BMFF hash -- standard path
# ---------------------------------------------------------------------------


def test_bmff_hash_match() -> None:
    """Asset bytes + correct hash + no exclusions -> match."""
    asset = b"hello bmff world"
    h = _sha256(asset)
    result = verify_bmff_hash(asset, {"alg": "sha256", "hash": h})
    assert result.is_valid
    assert result.status_code == "assertion.bmffHash.match"


def test_bmff_hash_mismatch() -> None:
    """Tampered bytes produce a mismatch."""
    asset = b"hello bmff world"
    h = _sha256(asset)
    tampered = b"hello XXXX world"
    result = verify_bmff_hash(tampered, {"alg": "sha256", "hash": h})
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.mismatch"


def test_bmff_hash_with_exclusions() -> None:
    """Hash with byte-range exclusions verifies correctly."""
    asset = b"AAAA" + b"\x00" * 8 + b"BBBB"
    # Exclude the middle 8 bytes that would contain the JUMBF manifest
    import hashlib as _hl

    h_obj = _hl.sha256()
    h_obj.update(b"AAAA")
    h_obj.update(b"BBBB")
    expected = h_obj.digest()

    assertion = {
        "alg": "sha256",
        "hash": expected,
        "exclusions": [{"start": 4, "length": 8}],
    }
    result = verify_bmff_hash(asset, assertion)
    assert result.is_valid
    assert result.status_code == "assertion.bmffHash.match"


def test_bmff_hash_malformed_no_alg() -> None:
    """Missing algorithm field -> algorithm.unsupported."""
    result = verify_bmff_hash(b"data", {"hash": b"\x00" * 32})
    assert not result.is_valid
    assert result.status_code == "algorithm.unsupported"


def test_bmff_hash_malformed_no_hash() -> None:
    """Missing hash field -> malformed."""
    result = verify_bmff_hash(b"data", {"alg": "sha256"})
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.malformed"


def test_bmff_hash_unsupported_algorithm() -> None:
    """Unsupported algorithm -> algorithm.unsupported."""
    result = verify_bmff_hash(b"data", {"alg": "md5", "hash": b"\x00" * 16})
    assert not result.is_valid
    assert result.status_code == "algorithm.unsupported"


# ---------------------------------------------------------------------------
# BMFF hash -- Merkle tree path
# ---------------------------------------------------------------------------


def test_merkle_tree_valid() -> None:
    """4 blocks with correct leaves and correct root -> match."""
    data, leaves, root = _build_merkle_data(block_size=16, num_blocks=4)
    assertion = {
        "alg": "sha256",
        "hash": root,
        "block_size": 16,
        "blocks": leaves,
    }
    result = verify_bmff_hash(data, assertion)
    assert result.is_valid
    assert result.status_code == "assertion.bmffHash.match"


def test_merkle_tree_leaf_mismatch() -> None:
    """One tampered leaf -> mismatch."""
    data, leaves, root = _build_merkle_data(block_size=16, num_blocks=4)
    bad_leaves = list(leaves)
    bad_leaves[2] = b"\xff" * 32  # corrupt leaf 2
    assertion = {
        "alg": "sha256",
        "hash": root,
        "block_size": 16,
        "blocks": bad_leaves,
    }
    result = verify_bmff_hash(data, assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.mismatch"
    assert "Leaf 2" in result.message


def test_merkle_tree_root_mismatch() -> None:
    """Correct leaves, wrong declared root -> mismatch."""
    data, leaves, _root = _build_merkle_data(block_size=16, num_blocks=4)
    bad_root = b"\xab" * 32
    assertion = {
        "alg": "sha256",
        "hash": bad_root,
        "block_size": 16,
        "blocks": leaves,
    }
    result = verify_bmff_hash(data, assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.mismatch"
    assert "root" in result.message.lower()


def test_merkle_tree_leaf_count_mismatch() -> None:
    """Wrong number of declared blocks -> mismatch."""
    data, leaves, root = _build_merkle_data(block_size=16, num_blocks=4)
    # Provide only 3 leaves for 4-block data
    assertion = {
        "alg": "sha256",
        "hash": root,
        "block_size": 16,
        "blocks": leaves[:3],
    }
    result = verify_bmff_hash(data, assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.mismatch"
    assert "count" in result.message.lower()


def test_merkle_tree_invalid_block_size() -> None:
    """block_size=0 -> malformed."""
    data, leaves, root = _build_merkle_data(block_size=16, num_blocks=4)
    assertion = {
        "alg": "sha256",
        "hash": root,
        "block_size": 0,
        "blocks": leaves,
    }
    result = verify_bmff_hash(data, assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.bmffHash.malformed"


def test_merkle_single_block() -> None:
    """Single block asset with a 1-leaf Merkle tree."""
    asset = b"single block data"
    leaf = _sha256(asset)
    # With 1 leaf the root IS the leaf
    root = leaf
    assertion = {
        "alg": "sha256",
        "hash": root,
        "block_size": len(asset),
        "blocks": [leaf],
    }
    result = verify_bmff_hash(asset, assertion)
    assert result.is_valid
    assert result.status_code == "assertion.bmffHash.match"


def test_compute_merkle_root_two_leaves() -> None:
    """Known hash for a 2-leaf tree."""
    leaf_a = _sha256(b"block_a")
    leaf_b = _sha256(b"block_b")
    expected_root = _sha256(leaf_a + leaf_b)
    computed = _compute_merkle_root([leaf_a, leaf_b], "sha256")
    assert computed == expected_root


def test_compute_merkle_root_odd_leaves() -> None:
    """3 leaves: last leaf is duplicated to form its parent."""
    leaf_a = _sha256(b"a")
    leaf_b = _sha256(b"b")
    leaf_c = _sha256(b"c")
    # Level 1: hash(a+b), hash(c+c)
    parent_ab = _sha256(leaf_a + leaf_b)
    parent_cc = _sha256(leaf_c + leaf_c)
    expected_root = _sha256(parent_ab + parent_cc)
    computed = _compute_merkle_root([leaf_a, leaf_b, leaf_c], "sha256")
    assert computed == expected_root


# ---------------------------------------------------------------------------
# Boxes hash tests
# ---------------------------------------------------------------------------


def _make_boxes_assertion(
    asset: bytes,
    box_ranges: list[tuple[int, int]],
    names_per_box: list[list[str]] | None = None,
    alg: str = "sha256",
    exclusions_per_box: list[list[dict]] | None = None,
) -> dict:
    """Build a minimal boxes hash assertion from explicit byte ranges."""
    if names_per_box is None:
        names_per_box = [["box"] for _ in box_ranges]
    if exclusions_per_box is None:
        exclusions_per_box = [[] for _ in box_ranges]

    boxes = []
    for i, (start, length) in enumerate(box_ranges):
        box_bytes = asset[start : start + length]
        excl_list = exclusions_per_box[i]

        # Compute hash respecting exclusions
        from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

        exclusions = [ExclusionRange(int(e["start"]), int(e["length"])) for e in excl_list]
        h = compute_hash(box_bytes, alg, exclusions if exclusions else None)

        entry: dict = {
            "names": names_per_box[i],
            "hash": h,
            "start": start,
            "length": length,
        }
        if excl_list:
            entry["exclusions"] = excl_list
        boxes.append(entry)

    return {"alg": alg, "boxes": boxes}


def test_boxes_hash_match() -> None:
    """2 boxes with correct per-box hashes -> match."""
    asset = b"AAAA" + b"BBBB" + b"CCCC"
    assertion = _make_boxes_assertion(
        asset,
        [(0, 4), (4, 8)],
        names_per_box=[["boxA"], ["boxB"]],
    )
    result = verify_boxes_hash(asset, assertion)
    assert result.is_valid
    assert result.status_code == "assertion.boxesHash.match"
    assert result.boxes_checked == 2
    assert result.boxes_matched == 2


def test_boxes_hash_mismatch() -> None:
    """One tampered box -> mismatch reported for that box."""
    asset = b"AAAA" + b"BBBB" + b"CCCC"
    assertion = _make_boxes_assertion(
        asset,
        [(0, 4), (4, 8)],
        names_per_box=[["boxA"], ["boxB"]],
    )
    # Tamper with box 1's hash
    assertion["boxes"][1]["hash"] = b"\xff" * 32
    result = verify_boxes_hash(asset, assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.boxesHash.mismatch"
    assert result.boxes_checked == 2
    assert result.boxes_matched == 1


def test_boxes_hash_with_exclusions() -> None:
    """Per-box exclusion ranges are respected during hash verification."""
    # Box has 8 bytes; exclude middle 2 bytes (simulate embedded marker)
    box_data = b"AA" + b"\x00\x00" + b"BB"
    asset = box_data
    # Build expected hash excluding offset 2..4
    import hashlib as _hl

    h_obj = _hl.sha256()
    h_obj.update(b"AA")
    h_obj.update(b"BB")
    expected = h_obj.digest()

    assertion = {
        "alg": "sha256",
        "boxes": [
            {
                "names": ["testBox"],
                "hash": expected,
                "start": 0,
                "length": 6,
                "exclusions": [{"start": 2, "length": 2}],
            }
        ],
    }
    result = verify_boxes_hash(asset, assertion)
    assert result.is_valid
    assert result.status_code == "assertion.boxesHash.match"


def test_boxes_hash_malformed_no_boxes() -> None:
    """Missing 'boxes' field -> malformed."""
    result = verify_boxes_hash(b"data", {"alg": "sha256"})
    assert not result.is_valid
    assert result.status_code == "assertion.boxesHash.malformed"


def test_boxes_hash_malformed_missing_box_hash() -> None:
    """A box entry without a hash field -> malformed."""
    assertion = {
        "alg": "sha256",
        "boxes": [
            {"names": ["boxA"], "start": 0, "length": 4}
            # missing "hash"
        ],
    }
    result = verify_boxes_hash(b"AAAA", assertion)
    assert not result.is_valid
    assert result.status_code == "assertion.boxesHash.malformed"


def test_boxes_hash_unsupported_alg() -> None:
    """Unsupported algorithm -> algorithm.unsupported."""
    assertion = {
        "alg": "md5",
        "boxes": [{"names": ["boxA"], "hash": b"\x00" * 16, "start": 0, "length": 4}],
    }
    result = verify_boxes_hash(b"AAAA", assertion)
    assert not result.is_valid
    assert result.status_code == "algorithm.unsupported"


def test_boxes_hash_empty_asset() -> None:
    """Boxes referencing zero-length regions on an empty asset."""
    # A box with start=0, length=0 produces an empty hash; the verifier
    # should handle this without crashing.
    empty_asset = b""
    h = _sha256(b"")
    assertion = {
        "alg": "sha256",
        "boxes": [{"names": ["emptyBox"], "hash": h, "start": 0, "length": 0}],
    }
    result = verify_boxes_hash(empty_asset, assertion)
    # An empty box produces sha256("") which matches our declared hash
    assert result.is_valid
    assert result.status_code == "assertion.boxesHash.match"


# ---------------------------------------------------------------------------
# BMFF box tree parser tests
# ---------------------------------------------------------------------------


def _make_box(box_type: bytes, payload: bytes) -> bytes:
    """Build a raw ISOBMFF box."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def _make_uuid_box(uuid_bytes: bytes, payload: bytes) -> bytes:
    """Build a raw UUID box."""
    size = 8 + 16 + len(payload)
    return struct.pack(">I", size) + b"uuid" + uuid_bytes + payload


class TestParseBmffBoxes:
    def test_single_box(self) -> None:
        data = _make_box(b"ftyp", b"\x00" * 12)
        boxes = parse_bmff_boxes(data)
        assert len(boxes) == 1
        assert boxes[0].box_type == b"ftyp"
        assert boxes[0].offset == 0
        assert boxes[0].size == 20

    def test_multiple_boxes(self) -> None:
        ftyp = _make_box(b"ftyp", b"\x00" * 4)
        mdat = _make_box(b"mdat", b"\x01" * 8)
        moov = _make_box(b"moov", b"\x02" * 16)
        data = ftyp + mdat + moov
        boxes = parse_bmff_boxes(data)
        assert len(boxes) == 3
        assert boxes[0].type_str == "ftyp"
        assert boxes[1].type_str == "mdat"
        assert boxes[2].type_str == "moov"
        assert boxes[1].offset == boxes[0].size
        assert boxes[2].offset == boxes[0].size + boxes[1].size

    def test_uuid_box(self) -> None:
        uuid = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
        data = _make_uuid_box(uuid, b"\xff" * 10)
        boxes = parse_bmff_boxes(data)
        assert len(boxes) == 1
        assert boxes[0].box_type == b"uuid"
        assert boxes[0].extended_type == uuid

    def test_extended_size_box(self) -> None:
        payload = b"\x00" * 8
        total_size = 16 + len(payload)
        data = struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", total_size) + payload
        boxes = parse_bmff_boxes(data)
        assert len(boxes) == 1
        assert boxes[0].size == total_size

    def test_empty_data(self) -> None:
        assert parse_bmff_boxes(b"") == []

    def test_truncated_data(self) -> None:
        assert parse_bmff_boxes(b"\x00\x00\x00") == []


class TestClassifyExclusion:
    def test_uuid_is_c2pa_required(self) -> None:
        assert classify_exclusion("/uuid") == "c2pa_required"

    def test_ftyp_is_c2pa_required(self) -> None:
        assert classify_exclusion("/ftyp") == "c2pa_required"

    def test_free_is_free(self) -> None:
        assert classify_exclusion("/free") == "free"

    def test_skip_is_skip(self) -> None:
        assert classify_exclusion("/skip") == "skip"

    def test_mfra_is_skip(self) -> None:
        assert classify_exclusion("/mfra") == "skip"

    def test_unknown_type(self) -> None:
        assert classify_exclusion("/meta") == "unknown"


class TestResolveXpathExclusions:
    def test_simple_type_match(self) -> None:
        uuid = bytes(16)
        data = (
            _make_box(b"ftyp", b"\x00" * 4)
            + _make_uuid_box(uuid, b"\x00" * 10)
            + _make_box(b"free", b"\x00" * 4)
        )
        boxes = parse_bmff_boxes(data)
        exclusions = [{"xpath": "/ftyp"}, {"xpath": "/free"}]
        resolved = resolve_xpath_exclusions(boxes, exclusions)
        assert len(resolved) == 2
        assert resolved[0]["xpath"] == "/ftyp"
        assert resolved[0]["start"] == 0
        assert resolved[0]["type"] == "c2pa_required"
        assert resolved[1]["xpath"] == "/free"
        assert resolved[1]["type"] == "free"

    def test_uuid_with_data_discriminator(self) -> None:
        c2pa_uuid = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
        other_uuid = bytes(16)
        data = _make_uuid_box(c2pa_uuid, b"\x00" * 4) + _make_uuid_box(other_uuid, b"\x00" * 4)
        boxes = parse_bmff_boxes(data)
        exclusions = [
            {
                "xpath": "/uuid",
                "data": [{"offset": 8, "value": "d8fec3d61b0e483c92975828877ec481"}],
            }
        ]
        resolved = resolve_xpath_exclusions(boxes, exclusions)
        assert len(resolved) == 1
        assert resolved[0]["start"] == 0

    def test_missing_box_type_omitted(self) -> None:
        data = _make_box(b"ftyp", b"\x00" * 4)
        boxes = parse_bmff_boxes(data)
        resolved = resolve_xpath_exclusions(boxes, [{"xpath": "/mfra"}])
        assert len(resolved) == 0

    def test_all_within_asset_bounds(self) -> None:
        data = _make_box(b"ftyp", b"\x00" * 4) + _make_box(b"free", b"\x00" * 4)
        boxes = parse_bmff_boxes(data)
        exclusions = [{"xpath": "/ftyp"}, {"xpath": "/free"}]
        resolved = resolve_xpath_exclusions(boxes, exclusions)
        for r in resolved:
            assert r["start"] + r["length"] <= len(data)
