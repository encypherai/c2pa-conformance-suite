"""GIF container extractor.

Extracts C2PA JUMBF from GIF Application Extension blocks.

GIF C2PA storage uses an Application Extension (0x21 0xFF):
    Block size:     1 byte (11 = length of app identifier + auth code)
    App identifier: 8 bytes ("C2PA\x00\x00\x00\x00" or similar)
    Auth code:      3 bytes
    Sub-blocks:     sequence of (length_byte + data) until 0x00 terminator

The concatenated sub-block data is raw JUMBF.
"""

from __future__ import annotations

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

GIF87_MAGIC = b"GIF87a"
GIF89_MAGIC = b"GIF89a"
C2PA_APP_ID = b"C2PA"


@register
class GIFExtractor:
    """Extract C2PA JUMBF from GIF Application Extension."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix == ".gif":
            return True
        return len(data) >= 6 and data[:6] in (GIF87_MAGIC, GIF89_MAGIC)

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 6 or data[:6] not in (GIF87_MAGIC, GIF89_MAGIC):
            raise ExtractionError("Not a valid GIF file")

        pos = 6  # After header

        # Skip Logical Screen Descriptor (7 bytes)
        if pos + 7 > len(data):
            raise ExtractionError("GIF too short for screen descriptor")
        packed = data[pos + 4]
        has_gct = (packed >> 7) & 1
        gct_size = packed & 0x07
        pos += 7

        # Skip Global Color Table if present
        if has_gct:
            pos += 3 * (2 ** (gct_size + 1))

        # Scan blocks
        while pos < len(data):
            block_type = data[pos]
            pos += 1

            if block_type == 0x3B:
                # Trailer - end of GIF
                break

            if block_type == 0x21:
                # Extension block
                if pos >= len(data):
                    break
                ext_label = data[pos]
                pos += 1

                if ext_label == 0xFF:
                    # Application Extension
                    if pos >= len(data):
                        break
                    block_size = data[pos]
                    pos += 1

                    if block_size == 11 and pos + 11 <= len(data):
                        app_id = data[pos : pos + 8]
                        pos += 11  # skip identifier + auth code

                        if C2PA_APP_ID in app_id:
                            # Read sub-blocks
                            jumbf_start = pos
                            chunks: list[bytes] = []
                            while pos < len(data):
                                sub_size = data[pos]
                                pos += 1
                                if sub_size == 0:
                                    break
                                if pos + sub_size > len(data):
                                    break
                                chunks.append(data[pos : pos + sub_size])
                                pos += sub_size

                            jumbf_bytes = b"".join(chunks)
                            return ExtractionResult(
                                jumbf_bytes=jumbf_bytes,
                                container_format="gif",
                                jumbf_offset=jumbf_start,
                                jumbf_length=len(jumbf_bytes),
                            )
                        else:
                            # Skip sub-blocks of non-C2PA extension
                            pos = _skip_sub_blocks(data, pos)
                    else:
                        pos = _skip_sub_blocks(data, pos + block_size)
                else:
                    # Other extension (Graphics Control, Comment, etc.)
                    pos = _skip_sub_blocks(data, pos)

            elif block_type == 0x2C:
                # Image Descriptor (9 bytes after the separator)
                if pos + 9 > len(data):
                    break
                packed_img = data[pos + 8]
                has_lct = (packed_img >> 7) & 1
                lct_size = packed_img & 0x07
                pos += 9

                if has_lct:
                    pos += 3 * (2 ** (lct_size + 1))

                # Skip LZW minimum code size
                pos += 1
                # Skip image data sub-blocks
                pos = _skip_sub_blocks(data, pos)

        raise ExtractionError("No C2PA Application Extension found in GIF")


def _skip_sub_blocks(data: bytes, pos: int) -> int:
    """Skip a sequence of GIF sub-blocks (terminated by 0x00)."""
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            break
        pos += size
    return pos
