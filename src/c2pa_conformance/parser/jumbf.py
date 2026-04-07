"""JUMBF (JPEG Universal Metadata Box Format) parser.

Parses raw JUMBF bytes into a tree of boxes per ISO 19566-5.
This is the format-agnostic entry point: once container extractors
produce raw JUMBF bytes, this parser handles everything.

JUMBF box structure:
    LBox (4 bytes) | TBox (4 bytes) | [XLBox (8 bytes)] | payload
    Where TBox is a 4-character type code (e.g., 'jumb', 'jumd', 'jp2c').
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator

# Well-known JUMBF box types
JUMB = b"jumb"  # JUMBF superbox
JUMD = b"jumd"  # JUMBF description box
JP2C = b"jp2c"  # Codestream box (embedded content)
JSON_BOX = b"json"  # JSON content box
CBOR_BOX = b"cbor"  # CBOR content box
UUID_BOX = b"uuid"  # UUID box
BFDB = b"bfdb"  # Binary data box
FREE = b"free"  # Free space box

# C2PA-specific type UUIDs (in JUMD description box)
# Per C2PA v2.0 spec and c2pa-rs reference implementation:
C2PA_MANIFEST_STORE_UUID = bytes.fromhex("6332706100110010800000aa00389b71")  # c2pa
C2PA_MANIFEST_UUID = bytes.fromhex("63326d6100110010800000aa00389b71")  # c2ma
C2PA_ASSERTION_STORE_UUID = bytes.fromhex("6332617300110010800000aa00389b71")  # c2as
C2PA_CLAIM_UUID = bytes.fromhex("6332636c00110010800000aa00389b71")  # c2cl
C2PA_SIGNATURE_UUID = bytes.fromhex("6332637300110010800000aa00389b71")  # c2cs
C2PA_CBOR_ASSERTION_UUID = bytes.fromhex("63626f7200110010800000aa00389b71")  # cbor


@dataclass
class JUMBFBox:
    """A single JUMBF box."""

    box_type: bytes
    offset: int
    size: int
    payload_offset: int
    payload: bytes = b""
    children: list[JUMBFBox] = field(default_factory=list)
    label: str = ""
    uuid: bytes = b""

    @property
    def type_str(self) -> str:
        return self.box_type.decode("ascii", errors="replace")

    @property
    def is_superbox(self) -> bool:
        return self.box_type == JUMB

    def find_child(self, box_type: bytes) -> JUMBFBox | None:
        for child in self.children:
            if child.box_type == box_type:
                return child
        return None

    def find_children(self, box_type: bytes) -> list[JUMBFBox]:
        return [c for c in self.children if c.box_type == box_type]

    def find_by_label(self, label: str) -> JUMBFBox | None:
        for child in self.children:
            if child.label == label:
                return child
            found = child.find_by_label(label)
            if found:
                return found
        return None


class JUMBFParseError(Exception):
    """Raised when JUMBF data is malformed."""


def parse_box_header(data: bytes, offset: int) -> tuple[bytes, int, int]:
    """Parse a single box header, returning (type, total_size, header_size).

    Returns:
        Tuple of (box_type, total_size, header_size).
        total_size == 0 means "box extends to end of data".
        total_size == 1 means extended size (XLBox) is used.
    """
    if offset + 8 > len(data):
        raise JUMBFParseError(f"Truncated box header at offset {offset}")

    lbox = struct.unpack_from(">I", data, offset)[0]
    tbox = data[offset + 4 : offset + 8]
    header_size = 8

    if lbox == 1:
        # Extended size
        if offset + 16 > len(data):
            raise JUMBFParseError(f"Truncated extended box header at offset {offset}")
        xlbox = struct.unpack_from(">Q", data, offset + 8)[0]
        lbox = xlbox
        header_size = 16
    elif lbox == 0:
        # Box extends to end of data
        lbox = len(data) - offset

    return tbox, lbox, header_size


def parse_jumd(payload: bytes) -> tuple[bytes, str]:
    """Parse a JUMD (description) box payload.

    Returns (type_uuid, label).
    """
    if len(payload) < 17:
        raise JUMBFParseError(f"JUMD payload too short: {len(payload)} bytes")

    type_uuid = payload[:16]
    toggles = payload[16]

    label = ""
    pos = 17

    # Bit 0 of toggles: label field is present
    if toggles & 0x01:
        # Label is null-terminated UTF-8
        end = payload.find(b"\x00", pos)
        if end == -1:
            label = payload[pos:].decode("utf-8", errors="replace")
        else:
            label = payload[pos:end].decode("utf-8", errors="replace")

    return type_uuid, label


def parse_boxes(
    data: bytes,
    offset: int = 0,
    end: int | None = None,
    *,
    _strict: bool = True,
) -> list[JUMBFBox]:
    """Parse a sequence of JUMBF boxes from raw bytes.

    Args:
        data: Raw JUMBF byte data.
        offset: Starting offset within data.
        end: End offset (defaults to len(data)).
        _strict: If True (default for top-level), raise on invalid boxes.
            When False (used for superbox children), stop parsing on error.

    Returns:
        List of parsed JUMBFBox objects.
    """
    if end is None:
        end = len(data)

    boxes: list[JUMBFBox] = []

    while offset < end:
        if offset + 8 > end:
            break  # Not enough data for another box header

        box_type, total_size, header_size = parse_box_header(data, offset)
        payload_offset = offset + header_size
        box_end = offset + total_size

        # Zero-type boxes are padding/terminator, not valid JUMBF
        if box_type == b"\x00\x00\x00\x00":
            break

        if box_end > end:
            if _strict:
                raise JUMBFParseError(
                    f"Box at offset {offset} (type={box_type!r}) extends beyond "
                    f"data boundary: {box_end} > {end}"
                )
            # Non-strict: stop parsing, remaining bytes are opaque
            break

        payload = data[payload_offset:box_end]

        box = JUMBFBox(
            box_type=box_type,
            offset=offset,
            size=total_size,
            payload_offset=payload_offset,
            payload=payload,
        )

        if box_type == JUMB:
            # Superbox: parse children non-strictly so embedded binary
            # content (thumbnails, etc.) doesn't crash the entire parse
            box.children = parse_boxes(data, payload_offset, box_end, _strict=False)
            jumd = box.find_child(JUMD)
            if jumd and jumd.payload:
                box.uuid, box.label = parse_jumd(jumd.payload)
        elif box_type == JUMD:
            if payload:
                box.uuid, box.label = parse_jumd(payload)

        boxes.append(box)
        offset = box_end

    return boxes


def parse_jumbf(data: bytes) -> list[JUMBFBox]:
    """Parse complete JUMBF data into a box tree.

    This is the primary entry point. Takes raw JUMBF bytes (as extracted
    from a container format) and returns the parsed box hierarchy.
    """
    return parse_boxes(data)


def iter_boxes(boxes: list[JUMBFBox]) -> Iterator[JUMBFBox]:
    """Depth-first iteration over a box tree."""
    for box in boxes:
        yield box
        yield from iter_boxes(box.children)
