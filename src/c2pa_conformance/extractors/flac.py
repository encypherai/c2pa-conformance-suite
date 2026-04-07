"""FLAC container extractor.

Extracts C2PA JUMBF manifest store from FLAC APPLICATION metadata blocks.

FLAC format:
    Magic: "fLaC" (4 bytes)
    Metadata blocks (one or more):
        Header: is_last(1 bit) + type(7 bits) + length(3 bytes big-endian)
        Data: length bytes

    Type 2 = APPLICATION block:
        Application ID (4 bytes, e.g., "c2pa")
        Application data (remaining bytes = JUMBF manifest store)
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

FLAC_MAGIC = b"fLaC"
APPLICATION_BLOCK_TYPE = 2
C2PA_APP_ID = b"c2pa"


@register
class FLACExtractor:
    """Extract C2PA JUMBF from FLAC APPLICATION metadata block."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix == ".flac":
            return True
        return len(data) >= 4 and data[:4] == FLAC_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 4 or data[:4] != FLAC_MAGIC:
            raise ExtractionError("Not a valid FLAC file (missing fLaC magic)")

        pos = 4  # Skip magic

        while pos < len(data):
            if pos + 4 > len(data):
                break

            header_byte = data[pos]
            is_last = (header_byte >> 7) & 1
            block_type = header_byte & 0x7F
            block_size = struct.unpack_from(">I", b"\x00" + data[pos + 1 : pos + 4], 0)[0]

            block_data_start = pos + 4
            block_data_end = block_data_start + block_size

            if block_data_end > len(data):
                break

            if block_type == APPLICATION_BLOCK_TYPE and block_size >= 4:
                app_id = data[block_data_start : block_data_start + 4]
                if app_id == C2PA_APP_ID:
                    jumbf_bytes = data[block_data_start + 4 : block_data_end]
                    return ExtractionResult(
                        jumbf_bytes=jumbf_bytes,
                        container_format="flac",
                        jumbf_offset=block_data_start + 4,
                        jumbf_length=len(jumbf_bytes),
                    )

            if is_last:
                break

            pos = block_data_end

        raise ExtractionError("No C2PA APPLICATION block found in FLAC file")
