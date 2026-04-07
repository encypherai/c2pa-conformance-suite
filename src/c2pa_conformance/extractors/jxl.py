"""JPEG XL container extractor.

Extracts C2PA JUMBF manifest store from JPEG XL (JXL) files.

JPEG XL uses ISOBMFF-style box structure when in container mode:
    Signature box: 0x0000000C 4A584C20 0D0A870A (12 bytes)
    Then standard ISOBMFF boxes including jumb (JUMBF) boxes.

The C2PA manifest store is in a jumb superbox within the JXL container,
following the same JUMBF structure as other formats.

JPEG XL can also be in codestream-only mode (starts with 0xFF0A),
which does not support embedded C2PA.
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

# JPEG XL container signature box content
JXL_CONTAINER_SIGNATURE = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"
JXL_CODESTREAM_MAGIC = b"\xff\x0a"

JUMB_TYPE = b"jumb"
C2PA_TYPE = b"c2pa"  # c2pa-rs uses this box type in JXL containers


@register
class JXLExtractor:
    """Extract C2PA JUMBF from JPEG XL container."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in (".jxl",):
            return True
        if len(data) >= 12:
            return data[:12] == JXL_CONTAINER_SIGNATURE
        return False

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 12:
            raise ExtractionError("JPEG XL file too short")

        if data[:2] == JXL_CODESTREAM_MAGIC:
            raise ExtractionError("JPEG XL codestream-only mode does not support embedded C2PA")

        if data[:12] != JXL_CONTAINER_SIGNATURE:
            raise ExtractionError("Not a valid JPEG XL container (bad signature)")

        # Parse ISOBMFF-style boxes after the signature
        pos = 12
        length = len(data)

        while pos < length:
            if pos + 8 > length:
                break

            box_size = struct.unpack_from(">I", data, pos)[0]
            box_type = data[pos + 4 : pos + 8]
            header_size = 8

            if box_size == 1:
                if pos + 16 > length:
                    break
                box_size = struct.unpack_from(">Q", data, pos + 8)[0]
                header_size = 16
            elif box_size == 0:
                box_size = length - pos

            if box_size < header_size:
                break

            box_end = pos + box_size
            if box_end > length:
                break

            if box_type == JUMB_TYPE:
                # jumb box IS the JUMBF superbox (include header)
                jumbf_bytes = data[pos:box_end]
                return ExtractionResult(
                    jumbf_bytes=jumbf_bytes,
                    container_format="jxl",
                    jumbf_offset=pos,
                    jumbf_length=len(jumbf_bytes),
                )

            if box_type == C2PA_TYPE:
                # c2pa box wraps raw JUMBF content (exclude box header)
                jumbf_bytes = data[pos + header_size : box_end]
                return ExtractionResult(
                    jumbf_bytes=jumbf_bytes,
                    container_format="jxl",
                    jumbf_offset=pos + header_size,
                    jumbf_length=len(jumbf_bytes),
                )

            pos = box_end

        raise ExtractionError("No JUMBF box found in JPEG XL container")
