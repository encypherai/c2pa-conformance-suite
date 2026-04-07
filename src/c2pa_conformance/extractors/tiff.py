"""TIFF container extractor.

Extracts C2PA JUMBF from TIFF files. C2PA data is stored in a private
TIFF tag (0xCD41 = 52545) in the first IFD. The tag value contains
raw JUMBF bytes.

TIFF header:
    Byte order: 2 bytes ("II" = little-endian, "MM" = big-endian)
    Magic:      2 bytes (42)
    IFD offset: 4 bytes (offset to first IFD)

IFD entry:
    Tag:    2 bytes
    Type:   2 bytes
    Count:  4 bytes
    Value:  4 bytes (value or offset to value if > 4 bytes)
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

TIFF_LE = b"II"
TIFF_BE = b"MM"
C2PA_TIFF_TAG = 0xCD41  # Private tag for C2PA JUMBF data


@register
class TIFFExtractor:
    """Extract C2PA JUMBF from TIFF C2PA tag."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in (".tiff", ".tif", ".dng"):
            return True
        if len(data) >= 4:
            return (data[:2] == TIFF_LE and data[2:4] == b"\x2a\x00") or (
                data[:2] == TIFF_BE and data[2:4] == b"\x00\x2a"
            )
        return False

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 8:
            raise ExtractionError("TIFF file too short")

        # Determine byte order
        bom = data[:2]
        if bom == TIFF_LE:
            endian = "<"
        elif bom == TIFF_BE:
            endian = ">"
        else:
            raise ExtractionError("Not a valid TIFF file (bad byte order mark)")

        magic = struct.unpack_from(f"{endian}H", data, 2)[0]
        if magic != 42:
            raise ExtractionError(f"Not a valid TIFF file (magic={magic}, expected 42)")

        ifd_offset = struct.unpack_from(f"{endian}I", data, 4)[0]

        # Walk IFDs looking for C2PA tag
        visited: set[int] = set()
        while ifd_offset != 0 and ifd_offset not in visited:
            visited.add(ifd_offset)

            if ifd_offset + 2 > len(data):
                break

            entry_count = struct.unpack_from(f"{endian}H", data, ifd_offset)[0]
            pos = ifd_offset + 2

            for _ in range(entry_count):
                if pos + 12 > len(data):
                    break

                tag = struct.unpack_from(f"{endian}H", data, pos)[0]
                # type_id = struct.unpack_from(f"{endian}H", data, pos + 2)[0]
                count = struct.unpack_from(f"{endian}I", data, pos + 4)[0]
                value_or_offset = struct.unpack_from(f"{endian}I", data, pos + 8)[0]

                if tag == C2PA_TIFF_TAG:
                    # UNDEFINED type (7), count = byte length
                    # Value is an offset to the JUMBF data
                    byte_count = count
                    if byte_count <= 4:
                        # Inline value (unlikely for JUMBF but handle it)
                        jumbf_bytes = data[pos + 8 : pos + 8 + byte_count]
                    else:
                        offset = value_or_offset
                        if offset + byte_count > len(data):
                            raise ExtractionError(
                                f"C2PA TIFF tag data extends beyond file "
                                f"({offset + byte_count} > {len(data)})"
                            )
                        jumbf_bytes = data[offset : offset + byte_count]

                    return ExtractionResult(
                        jumbf_bytes=jumbf_bytes,
                        container_format="tiff",
                        jumbf_offset=value_or_offset if byte_count > 4 else pos + 8,
                        jumbf_length=byte_count,
                    )

                pos += 12

            # Next IFD offset
            next_ifd_pos = pos
            if next_ifd_pos + 4 > len(data):
                break
            ifd_offset = struct.unpack_from(f"{endian}I", data, next_ifd_pos)[0]

        raise ExtractionError("No C2PA tag (0xCD41) found in TIFF IFD")
