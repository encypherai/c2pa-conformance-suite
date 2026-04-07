"""ISOBMFF box tree parser for C2PA xpath exclusion resolution.

Parses an ISOBMFF (ISO 14496-12) file into a flat list of top-level boxes
with type, offset, and size. Resolves C2PA xpath exclusion strings to
concrete (offset, length) byte ranges for hash verification.

ISOBMFF box header:
    LBox (4 bytes, big-endian) | TBox (4 bytes, FourCC) | [XLBox (8 bytes)] | payload
    LBox == 0: box extends to end of file
    LBox == 1: extended size in XLBox
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any


@dataclass
class BMFFBox:
    """A single ISOBMFF box."""

    box_type: bytes  # 4-byte FourCC (e.g., b"ftyp", b"moov", b"uuid")
    offset: int  # Byte offset of the box start within the file
    size: int  # Total box size in bytes (header + payload)
    extended_type: bytes = b""  # 16-byte UUID for uuid boxes

    @property
    def type_str(self) -> str:
        return self.box_type.decode("ascii", errors="replace")

    @property
    def end(self) -> int:
        return self.offset + self.size


class BMFFParseError(Exception):
    """Raised when ISOBMFF data is malformed."""


def parse_bmff_boxes(data: bytes) -> list[BMFFBox]:
    """Parse top-level ISOBMFF boxes from raw file bytes.

    Returns a flat list of BMFFBox with type, offset, size, and
    extended_type (for uuid boxes). Only parses top-level boxes;
    container boxes (moov, trak, etc.) are not recursed into because
    C2PA xpath exclusions reference top-level box types only.

    Args:
        data: Complete raw file bytes.

    Returns:
        List of BMFFBox objects in file order.
    """
    boxes: list[BMFFBox] = []
    offset = 0
    end = len(data)

    while offset + 8 <= end:
        lbox = struct.unpack_from(">I", data, offset)[0]
        tbox = data[offset + 4 : offset + 8]
        header_size = 8

        if lbox == 1:
            # Extended size
            if offset + 16 > end:
                break
            lbox = struct.unpack_from(">Q", data, offset + 8)[0]
            header_size = 16
        elif lbox == 0:
            # Box extends to end of data
            lbox = end - offset

        if lbox < 8 or offset + lbox > end:
            break

        extended_type = b""
        if tbox == b"uuid" and offset + header_size + 16 <= end:
            extended_type = data[offset + header_size : offset + header_size + 16]

        boxes.append(
            BMFFBox(
                box_type=tbox,
                offset=offset,
                size=lbox,
                extended_type=extended_type,
            )
        )
        offset += lbox

    return boxes


# Well-known C2PA exclusion type classifications
_C2PA_REQUIRED_XPATHS = frozenset({"/uuid"})
_FREE_XPATHS = frozenset({"/free"})
_SKIP_XPATHS = frozenset({"/skip", "/mfra"})


def classify_exclusion(xpath: str) -> str:
    """Classify an xpath exclusion string for PRED-BMFF-004.

    Returns one of: "c2pa_required", "free", "skip", or "unknown".
    """
    if xpath in _C2PA_REQUIRED_XPATHS:
        return "c2pa_required"
    if xpath in _FREE_XPATHS:
        return "free"
    if xpath in _SKIP_XPATHS:
        return "skip"
    # /ftyp is a required exclusion per C2PA spec
    if xpath == "/ftyp":
        return "c2pa_required"
    return "unknown"


def _matches_uuid_discriminator(box: BMFFBox, data_entries: list[dict[str, Any]]) -> bool:
    """Check whether a uuid box matches the data discriminator entries.

    Each entry has {"offset": int, "value": hex_string}. The offset is
    relative to the box payload start (after the 8-byte header). The value
    is compared as raw bytes against the box's extended_type or payload.
    """
    if not data_entries:
        return True  # No discriminator means match all uuid boxes

    for entry in data_entries:
        if not isinstance(entry, dict):
            continue
        entry_offset = entry.get("offset", 0)
        value = entry.get("value", "")
        if isinstance(value, bytes):
            expected = value
        elif isinstance(value, str):
            try:
                expected = bytes.fromhex(value)
            except ValueError:
                continue
        else:
            continue

        # Offset 8 from box start = first byte after the 8-byte header = extended_type
        if entry_offset == 8 and box.extended_type:
            if box.extended_type[: len(expected)] != expected:
                return False
        else:
            # Generic payload comparison
            actual = b""
            # We don't have file data here; the caller resolves via box offset
            # For the common case (offset=8, uuid), extended_type handles it
            if box.extended_type and entry_offset >= 8:
                local = entry_offset - 8
                actual = box.extended_type[local : local + len(expected)]
            if actual != expected:
                return False
    return True


def resolve_xpath_exclusions(
    boxes: list[BMFFBox],
    exclusions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve C2PA xpath exclusion entries to byte-range dicts.

    Each input exclusion has an "xpath" key (e.g., "/uuid", "/free", "/ftyp")
    and optionally a "data" key with discriminator entries for uuid boxes.

    Returns a list of dicts, each with:
        - "start": byte offset in the file
        - "length": byte length of the box
        - "xpath": original xpath string
        - "type": classification string for PRED-BMFF-004

    Unresolvable exclusions (xpath referencing a box type not present in
    the file) are omitted.
    """
    resolved: list[dict[str, Any]] = []

    for excl in exclusions:
        xpath = excl.get("xpath", "")
        if not xpath:
            # Already has start/length (pre-resolved)
            if excl.get("start") is not None and excl.get("length") is not None:
                resolved.append(
                    {
                        "start": excl["start"],
                        "length": excl["length"],
                        "xpath": "",
                        "type": "unknown",
                    }
                )
            continue

        # Extract box type from xpath: "/type" -> b"type"
        box_type_str = xpath.lstrip("/").split("[")[0].split("/")[0]
        box_type_bytes = box_type_str.encode("ascii")[:4]
        # Pad to 4 bytes if shorter (e.g., "mp4" -> "mp4 ")
        if len(box_type_bytes) < 4:
            box_type_bytes = box_type_bytes.ljust(4, b" ")

        data_entries = excl.get("data") or []
        classification = classify_exclusion(xpath)

        for box in boxes:
            if box.box_type != box_type_bytes:
                continue

            # For uuid boxes, check discriminator
            if box.box_type == b"uuid" and data_entries:
                if not _matches_uuid_discriminator(box, data_entries):
                    continue

            resolved.append(
                {
                    "start": box.offset,
                    "length": box.size,
                    "xpath": xpath,
                    "type": classification,
                }
            )

    return resolved
