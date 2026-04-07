"""PNG container extractor.

Extracts C2PA JUMBF manifest store from the PNG caBX chunk.

PNG chunk structure:
    Length: 4 bytes big-endian (data length only, excludes type/CRC)
    Type:   4 bytes ASCII (e.g., "caBX")
    Data:   Length bytes (raw JUMBF for caBX)
    CRC:    4 bytes

The caBX chunk is a private, ancillary, not-safe-to-copy chunk.
It typically precedes IDAT but may appear anywhere before IEND.
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CABX_TYPE = b"caBX"


@register
class PNGExtractor:
    """Extract C2PA JUMBF from PNG caBX chunk."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix == ".png":
            return True
        return len(data) >= 8 and data[:8] == PNG_SIGNATURE

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 8 or data[:8] != PNG_SIGNATURE:
            raise ExtractionError("Not a valid PNG file (bad signature)")

        pos = 8  # Skip PNG signature

        while pos + 12 <= len(data):  # Need at least length(4) + type(4) + CRC(4)
            chunk_length = struct.unpack_from(">I", data, pos)[0]
            chunk_type = data[pos + 4 : pos + 8]
            chunk_data_start = pos + 8
            chunk_end = chunk_data_start + chunk_length + 4  # +4 for CRC

            if chunk_end > len(data):
                raise ExtractionError(
                    f"PNG chunk at offset {pos} extends beyond file ({chunk_end} > {len(data)})"
                )

            if chunk_type == CABX_TYPE:
                jumbf_bytes = data[chunk_data_start : chunk_data_start + chunk_length]
                return ExtractionResult(
                    jumbf_bytes=jumbf_bytes,
                    container_format="png",
                    jumbf_offset=chunk_data_start,
                    jumbf_length=chunk_length,
                )

            # IEND marks end of PNG
            if chunk_type == b"IEND":
                break

            pos = chunk_end

        raise ExtractionError("No C2PA caBX chunk found in PNG")
