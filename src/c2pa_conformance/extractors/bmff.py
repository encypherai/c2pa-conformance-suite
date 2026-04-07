"""BMFF/ISOBMFF container extractor (MP4, HEIF, AVIF, 3GP, etc.).

Extracts C2PA JUMBF manifest store from BMFF uuid boxes.

The C2PA manifest store lives in a top-level uuid box (FullBox) with:
    Extended type:    D8FEC3D6-1B0E-483C-9297-58 28 87 7E C4 81
    Version/flags:    4 bytes (1 byte version + 3 bytes flags, typically 0)
    box_purpose:      "manifest\x00" (null-terminated)
    merkle_offset:    8 bytes (offset to auxiliary merkle box, 0 if none)
    Then:             raw JUMBF manifest store bytes

Standard ISOBMFF box header:
    size: 4 bytes big-endian (0 = extends to EOF, 1 = extended size)
    type: 4 bytes ASCII
    [extended_size: 8 bytes if size == 1]
    [extended_type: 16 bytes if type == "uuid"]
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

# Known BMFF suffixes
BMFF_SUFFIXES = {
    ".mp4",
    ".m4a",
    ".m4v",
    ".mov",
    ".heif",
    ".heic",
    ".avif",
    ".3gp",
    ".3g2",
}


def _parse_c2pa_uuid() -> bytes:
    """Return the 16-byte C2PA UUID for BMFF uuid boxes."""
    raw = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
    return raw.ljust(16, b"\x00")[:16]


C2PA_MANIFEST_UUID = _parse_c2pa_uuid()


@register
class BMFFExtractor:
    """Extract C2PA JUMBF from BMFF uuid box."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in BMFF_SUFFIXES:
            return True
        # Check for ftyp box at start
        if len(data) >= 8:
            box_type = data[4:8]
            return box_type == b"ftyp"
        return False

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        pos = 0
        length = len(data)

        while pos < length:
            if pos + 8 > length:
                break

            box_size = struct.unpack_from(">I", data, pos)[0]
            box_type = data[pos + 4 : pos + 8]
            header_size = 8

            if box_size == 1:
                # Extended size
                if pos + 16 > length:
                    break
                box_size = struct.unpack_from(">Q", data, pos + 8)[0]
                header_size = 16
            elif box_size == 0:
                # Box extends to end of file
                box_size = length - pos

            if box_size < header_size:
                break

            box_end = pos + box_size
            if box_end > length:
                break

            if box_type == b"uuid":
                # Read the 16-byte extended type
                uuid_start = pos + header_size
                if uuid_start + 16 > box_end:
                    pos = box_end
                    continue

                extended_type = data[uuid_start : uuid_start + 16]

                if extended_type == C2PA_MANIFEST_UUID:
                    # Skip 4-byte version/flags (FullBox)
                    purpose_start = uuid_start + 16 + 4
                    if purpose_start >= box_end:
                        pos = box_end
                        continue
                    # Read null-terminated box_purpose string
                    null_pos = data.find(b"\x00", purpose_start, box_end)
                    if null_pos == -1:
                        pos = box_end
                        continue

                    # Skip 8-byte offset field after purpose string
                    jumbf_start = null_pos + 1 + 8
                    if jumbf_start >= box_end:
                        pos = box_end
                        continue

                    jumbf_bytes = data[jumbf_start:box_end]
                    return ExtractionResult(
                        jumbf_bytes=jumbf_bytes,
                        container_format="bmff",
                        jumbf_offset=jumbf_start,
                        jumbf_length=len(jumbf_bytes),
                    )

            pos = box_end

        raise ExtractionError("No C2PA uuid box found in BMFF container")
