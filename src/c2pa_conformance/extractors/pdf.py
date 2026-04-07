"""PDF container extractor.

Extracts C2PA JUMBF manifest store from PDF files.

C2PA data in PDF is stored as an incremental update containing a stream
object with the JUMBF data. The C2PA spec defines a specific structure
using the Associated File feature (ISO 32000-2:2020):

1. A file specification dictionary with /AFRelationship /EncryptedPayload
   or /Data referencing the C2PA stream object.
2. The stream object contains raw JUMBF bytes.

For detection, we look for the "/C2PA" or "c2pa" keyword in the PDF
cross-reference or object table, or scan for JUMBF magic bytes within
stream objects.
"""

from __future__ import annotations

import re

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

PDF_MAGIC = b"%PDF-"
JUMBF_BOX_TYPE = b"jumb"

# Pattern to find stream content
STREAM_PATTERN = re.compile(rb"stream\r?\n([\s\S]*?)\r?\nendstream", re.DOTALL)

# Pattern to find C2PA-related objects
C2PA_OBJ_PATTERN = re.compile(rb"/C2PA\b|/Subtype\s*/C2PA", re.IGNORECASE)


@register
class PDFExtractor:
    """Extract C2PA JUMBF from PDF stream objects."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix == ".pdf":
            return True
        return len(data) >= 5 and data[:5] == PDF_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 5 or data[:5] != PDF_MAGIC:
            raise ExtractionError("Not a valid PDF file")

        # Strategy 1: Look for stream objects containing JUMBF data
        # JUMBF always starts with a box header where bytes 4-7 are "jumb"
        for match in STREAM_PATTERN.finditer(data):
            stream_data = match.group(1)
            # Check if this stream contains JUMBF data
            if len(stream_data) >= 8 and stream_data[4:8] == JUMBF_BOX_TYPE:
                return ExtractionResult(
                    jumbf_bytes=stream_data,
                    container_format="pdf",
                    jumbf_offset=match.start(1),
                    jumbf_length=len(stream_data),
                )

        # Strategy 2: Scan the entire file for JUMBF superbox magic
        # This handles cases where the stream is not properly delimited
        pos = 0
        while pos < len(data) - 8:
            if data[pos + 4 : pos + 8] == JUMBF_BOX_TYPE:
                # Read the box size to determine extent
                import struct

                box_size = struct.unpack_from(">I", data, pos)[0]
                if box_size == 1 and pos + 16 <= len(data):
                    box_size = struct.unpack_from(">Q", data, pos + 8)[0]
                elif box_size == 0:
                    box_size = len(data) - pos

                if 16 <= box_size <= len(data) - pos:
                    jumbf_bytes = data[pos : pos + box_size]
                    return ExtractionResult(
                        jumbf_bytes=jumbf_bytes,
                        container_format="pdf",
                        jumbf_offset=pos,
                        jumbf_length=box_size,
                    )
            pos += 1

        raise ExtractionError("No C2PA JUMBF manifest found in PDF")
