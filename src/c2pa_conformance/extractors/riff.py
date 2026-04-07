"""RIFF container extractor (WAV, WebP, AVI).

Extracts C2PA JUMBF manifest store from RIFF C2PA chunk.

RIFF structure:
    "RIFF" (4 bytes) + file_size-8 (4 bytes LE) + format_type (4 bytes)
    Then sub-chunks, each:
        chunk_id (4 bytes) + chunk_data_size (4 bytes LE) + data + optional pad byte

The C2PA chunk has chunk_id "C2PA" and contains raw JUMBF bytes.
Per spec, it shall be the last sub-chunk of the first RIFF header chunk.
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

RIFF_MAGIC = b"RIFF"
C2PA_CHUNK_ID = b"C2PA"
RIFF_SUFFIXES = {".wav", ".webp", ".avi"}


@register
class RIFFExtractor:
    """Extract C2PA JUMBF from RIFF C2PA chunk."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in RIFF_SUFFIXES:
            return True
        return len(data) >= 4 and data[:4] == RIFF_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 12 or data[:4] != RIFF_MAGIC:
            raise ExtractionError("Not a valid RIFF file")

        riff_size = struct.unpack_from("<I", data, 4)[0]
        riff_end = min(8 + riff_size, len(data))

        # Skip RIFF header (4 magic + 4 size + 4 format type)
        pos = 12

        while pos + 8 <= riff_end:
            chunk_id = data[pos : pos + 4]
            chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
            chunk_data_start = pos + 8

            if chunk_id == C2PA_CHUNK_ID:
                chunk_data_end = chunk_data_start + chunk_size
                if chunk_data_end > riff_end:
                    raise ExtractionError(
                        f"C2PA chunk extends beyond RIFF boundary ({chunk_data_end} > {riff_end})"
                    )
                jumbf_bytes = data[chunk_data_start:chunk_data_end]
                return ExtractionResult(
                    jumbf_bytes=jumbf_bytes,
                    container_format="riff",
                    jumbf_offset=chunk_data_start,
                    jumbf_length=chunk_size,
                )

            # Advance to next chunk (pad to even boundary)
            pos = chunk_data_start + chunk_size
            if pos % 2 != 0:
                pos += 1

        raise ExtractionError("No C2PA chunk found in RIFF container")
