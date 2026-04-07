"""Tests for the JUMBF parser."""

from __future__ import annotations

import struct

import pytest

from c2pa_conformance.parser.jumbf import (
    CBOR_BOX,
    FREE,
    JSON_BOX,
    JUMB,
    JUMBFBox,
    JUMBFParseError,
    iter_boxes,
    parse_box_header,
    parse_boxes,
    parse_jumd,
)


def _make_box(box_type: bytes, payload: bytes) -> bytes:
    """Build a raw JUMBF box from type and payload."""
    total_size = 8 + len(payload)
    return struct.pack(">I", total_size) + box_type + payload


def _make_superbox(box_type: bytes, children_bytes: bytes) -> bytes:
    """Build a JUMBF superbox wrapping child box bytes."""
    total_size = 8 + len(children_bytes)
    return struct.pack(">I", total_size) + box_type + children_bytes


class TestParseBoxHeader:
    def test_standard_header(self) -> None:
        data = struct.pack(">I", 20) + b"test" + b"\x00" * 12
        box_type, size, header_size = parse_box_header(data, 0)
        assert box_type == b"test"
        assert size == 20
        assert header_size == 8

    def test_extended_header(self) -> None:
        data = struct.pack(">I", 1) + b"test" + struct.pack(">Q", 32) + b"\x00" * 16
        box_type, size, header_size = parse_box_header(data, 0)
        assert box_type == b"test"
        assert size == 32
        assert header_size == 16

    def test_zero_size_means_rest_of_data(self) -> None:
        data = struct.pack(">I", 0) + b"test" + b"\x00" * 100
        box_type, size, header_size = parse_box_header(data, 0)
        assert size == len(data)

    def test_truncated_raises(self) -> None:
        with pytest.raises(JUMBFParseError, match="Truncated"):
            parse_box_header(b"\x00\x00", 0)


class TestParseBoxes:
    def test_single_box(self) -> None:
        raw = _make_box(b"test", b"hello")
        boxes = parse_boxes(raw)
        assert len(boxes) == 1
        assert boxes[0].box_type == b"test"
        assert boxes[0].payload == b"hello"

    def test_two_sequential_boxes(self) -> None:
        raw = _make_box(b"aaaa", b"one") + _make_box(b"bbbb", b"two")
        boxes = parse_boxes(raw)
        assert len(boxes) == 2
        assert boxes[0].type_str == "aaaa"
        assert boxes[1].type_str == "bbbb"

    def test_nested_superbox(self) -> None:
        inner = _make_box(CBOR_BOX, b"\xa0")  # empty CBOR map
        outer = _make_superbox(JUMB, inner)
        boxes = parse_boxes(outer)
        assert len(boxes) == 1
        assert boxes[0].is_superbox
        assert len(boxes[0].children) == 1
        assert boxes[0].children[0].box_type == CBOR_BOX

    def test_overflow_raises(self) -> None:
        # Box claims to be 100 bytes but data is only 20
        raw = struct.pack(">I", 100) + b"test" + b"\x00" * 12
        with pytest.raises(JUMBFParseError, match="extends beyond"):
            parse_boxes(raw)


class TestParseJumd:
    def test_with_label(self) -> None:
        # 16 bytes UUID + 1 byte toggles (bit 0 set) + label + null
        uuid_bytes = b"\x01" * 16
        payload = uuid_bytes + b"\x01" + b"test-label\x00"
        type_uuid, label = parse_jumd(payload)
        assert type_uuid == uuid_bytes
        assert label == "test-label"

    def test_without_label(self) -> None:
        uuid_bytes = b"\x02" * 16
        payload = uuid_bytes + b"\x00"  # toggles = 0, no label
        type_uuid, label = parse_jumd(payload)
        assert type_uuid == uuid_bytes
        assert label == ""

    def test_too_short_raises(self) -> None:
        with pytest.raises(JUMBFParseError, match="too short"):
            parse_jumd(b"\x00" * 10)


class TestJUMBFBox:
    def test_find_child(self) -> None:
        parent = JUMBFBox(box_type=JUMB, offset=0, size=0, payload_offset=0)
        child1 = JUMBFBox(box_type=CBOR_BOX, offset=0, size=0, payload_offset=0)
        child2 = JUMBFBox(box_type=JSON_BOX, offset=0, size=0, payload_offset=0)
        parent.children = [child1, child2]

        assert parent.find_child(CBOR_BOX) is child1
        assert parent.find_child(JSON_BOX) is child2
        assert parent.find_child(FREE) is None

    def test_find_by_label(self) -> None:
        root = JUMBFBox(box_type=JUMB, offset=0, size=0, payload_offset=0)
        child = JUMBFBox(box_type=JUMB, offset=0, size=0, payload_offset=0, label="target")
        root.children = [child]
        assert root.find_by_label("target") is child
        assert root.find_by_label("missing") is None


class TestIterBoxes:
    def test_flat(self) -> None:
        boxes = [
            JUMBFBox(box_type=b"aaaa", offset=0, size=0, payload_offset=0),
            JUMBFBox(box_type=b"bbbb", offset=0, size=0, payload_offset=0),
        ]
        result = list(iter_boxes(boxes))
        assert len(result) == 2

    def test_nested(self) -> None:
        child = JUMBFBox(box_type=CBOR_BOX, offset=0, size=0, payload_offset=0)
        parent = JUMBFBox(box_type=JUMB, offset=0, size=0, payload_offset=0, children=[child])
        result = list(iter_boxes([parent]))
        assert len(result) == 2
        assert result[0] is parent
        assert result[1] is child
