"""Text/plain container extractor (C2PATextManifestWrapper).

Extracts C2PA JUMBF manifest store from plain text files using the v2.4
C2PATextManifestWrapper encoding with Unicode Variation Selectors.

The wrapper encodes each byte of a binary structure as a single Unicode
Variation Selector character:
    byte 0x00-0x0F -> U+FE00 through U+FE0F
    byte 0x10-0xFF -> U+E0100 through U+E01EF

The binary structure:
    magic (8 bytes):         "C2PATXT\\0" (0x43 0x32 0x50 0x41 0x54 0x58 0x54 0x00)
    version (1 byte):        0x01
    manifestLength (4 bytes): big-endian uint32
    jumbfContainer[manifestLength]: raw JUMBF bytes

The VS block is preceded by U+FEFF (BOM / Zero-Width No-Break Space) as
a detection marker.

Also supports the legacy ASCII-armor format:
    ---BEGIN C2PA MANIFEST---
    <base64-encoded JUMBF>
    ---END C2PA MANIFEST---
"""

from __future__ import annotations

import base64
import re

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

C2PATXT_MAGIC = b"C2PATXT\x00"

# Legacy delimiters (pre-v2.4 or simplified implementations)
LEGACY_BEGIN = b"---BEGIN C2PA MANIFEST---"
LEGACY_END = b"---END C2PA MANIFEST---"
LEGACY_PATTERN = re.compile(
    rb"---BEGIN C2PA MANIFEST---\s*\n([\s\S]*?)\n\s*---END C2PA MANIFEST---",
)

# U+FEFF in UTF-8
BOM_UTF8 = b"\xef\xbb\xbf"

# VS1-VS16 range in UTF-8: U+FE00-U+FE0F -> 3 bytes each
# Supplementary VS: U+E0100-U+E01EF -> 4 bytes each


@register
class TextExtractor:
    """Extract C2PA JUMBF from C2PATextManifestWrapper in text files."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in (".txt", ".md", ".rst", ".text"):
            # Check for either VS-encoded wrapper or legacy delimiters
            return _has_vs_wrapper(data) or LEGACY_BEGIN in data
        return _has_vs_wrapper(data) or LEGACY_BEGIN in data

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        # Try v2.4 VS-encoded wrapper first
        result = _try_vs_extract(data)
        if result is not None:
            return result

        # Fall back to legacy ASCII-armor
        match = LEGACY_PATTERN.search(data)
        if match:
            b64_block = match.group(1)
            b64_clean = re.sub(rb"\s+", b"", b64_block)
            try:
                jumbf_bytes = base64.b64decode(b64_clean)
            except Exception as exc:
                raise ExtractionError(
                    f"Failed to decode base64 in legacy C2PA wrapper: {exc}"
                ) from exc

            return ExtractionResult(
                jumbf_bytes=jumbf_bytes,
                container_format="text",
                jumbf_offset=match.start(),
                jumbf_length=len(jumbf_bytes),
            )

        raise ExtractionError(
            "No C2PATextManifestWrapper found (no VS-encoded block or legacy delimiters)"
        )


def _has_vs_wrapper(data: bytes) -> bool:
    """Quick check for presence of U+FEFF followed by variation selectors."""
    return BOM_UTF8 in data


class TextWrapper:
    """One decoded C2PATextManifestWrapper found in a text asset."""

    __slots__ = ("offset", "version", "manifest_length", "jumbf_bytes", "complete")

    def __init__(
        self, offset: int, version: int, manifest_length: int, jumbf_bytes: bytes, complete: bool
    ) -> None:
        self.offset = offset
        self.version = version
        self.manifest_length = manifest_length
        self.jumbf_bytes = jumbf_bytes
        self.complete = complete


def find_text_wrappers(data: bytes) -> list[TextWrapper]:
    """Every VS-encoded block whose decoded header starts with the official magic.

    The magic ``C2PATXT\\0`` never appears literally in the asset: it is carried
    as variation selectors after a U+FEFF marker, so a byte scan for the ASCII
    string finds nothing. This decodes each BOM-prefixed run and reports every
    block that carries the magic, including malformed ones (wrong version or a
    truncated manifest), so a validator can distinguish "no wrapper" from
    "corrupted wrapper" from "multiple wrappers".
    """
    wrappers: list[TextWrapper] = []
    bom_pos = data.find(BOM_UTF8)
    while bom_pos != -1:
        decoded = _decode_vs_bytes(data, bom_pos + len(BOM_UTF8))
        if len(decoded) >= 8 and decoded[:8] == C2PATXT_MAGIC:
            version = decoded[8] if len(decoded) > 8 else -1
            manifest_length = int.from_bytes(decoded[9:13], "big") if len(decoded) >= 13 else -1
            jumbf = decoded[13 : 13 + manifest_length] if manifest_length >= 0 else b""
            complete = (
                version == 1 and manifest_length >= 0 and len(decoded) >= 13 + manifest_length
            )
            wrappers.append(TextWrapper(bom_pos, version, manifest_length, bytes(jumbf), complete))
        bom_pos = data.find(BOM_UTF8, bom_pos + 1)
    return wrappers


def _try_vs_extract(data: bytes) -> ExtractionResult | None:
    """Extract JUMBF from the first complete VS-encoded C2PATextManifestWrapper."""
    for wrapper in find_text_wrappers(data):
        if wrapper.complete:
            return ExtractionResult(
                jumbf_bytes=wrapper.jumbf_bytes,
                container_format="text",
                jumbf_offset=wrapper.offset,
                jumbf_length=len(wrapper.jumbf_bytes),
            )
    return None


def _decode_vs_bytes(data: bytes, pos: int) -> bytes:
    """Decode a sequence of variation selector characters back to bytes.

    U+FE00-U+FE0F (UTF-8: EF B8 80 - EF B8 8F) -> byte 0x00-0x0F
    U+E0100-U+E01EF (UTF-8: F3 A0 84 80 - F3 A0 87 AF) -> byte 0x10-0xFF
    """
    result = bytearray()

    while pos < len(data):
        # Check for 3-byte VS (U+FE00-U+FE0F)
        if (
            pos + 2 < len(data)
            and data[pos] == 0xEF
            and data[pos + 1] == 0xB8
            and 0x80 <= data[pos + 2] <= 0x8F
        ):
            byte_val = data[pos + 2] - 0x80
            result.append(byte_val)
            pos += 3
            continue

        # Check for 4-byte supplementary VS (U+E0100-U+E01EF)
        if pos + 3 < len(data) and data[pos] == 0xF3 and data[pos + 1] == 0xA0:
            # U+E0100 = F3 A0 84 80, U+E01EF = F3 A0 87 AF
            # Decode: codepoint = 0xE0000 + ((b2 & 0x3F) << 6) + (b3 & 0x3F)
            b2 = data[pos + 2]
            b3 = data[pos + 3]
            codepoint = 0xE0000 + ((b2 & 0x3F) << 6) + (b3 & 0x3F)

            if 0xE0100 <= codepoint <= 0xE01EF:
                byte_val = codepoint - 0xE0100 + 0x10
                result.append(byte_val)
                pos += 4
                continue

        # Not a variation selector - end of VS block
        break

    return bytes(result)
