"""SVG/XML/structured text container extractor.

Extracts C2PA manifest store from SVG, XML, and other structured text
formats using three mechanisms per the C2PA v2.4 spec:

1. SVG-specific: <!-- c2pa manifest="base64" --> comment
2. SVG-specific: <c2pa:manifest>base64</c2pa:manifest> element
3. Generic structured text: -----BEGIN C2PA MANIFEST----- / -----END C2PA MANIFEST-----
   with either a data: URI (inline base64) or external URL reference

The generic structured text mechanism applies to all XML-derived formats
(text/xml, application/xml, application/xhtml+xml) and any structured
text format not covered by a format-specific section.
"""

from __future__ import annotations

import base64
import re

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

SVG_SUFFIXES = {".svg", ".svgz"}
XML_SUFFIXES = {".xml", ".xhtml"}

# SVG-specific: <!-- c2pa manifest="..." -->
C2PA_COMMENT_PATTERN = re.compile(
    rb'<!--\s*c2pa\s+manifest\s*=\s*"([A-Za-z0-9+/=\s]+)"\s*-->',
    re.DOTALL,
)

# SVG-specific: <c2pa:manifest>base64</c2pa:manifest>
C2PA_ELEMENT_PATTERN = re.compile(
    rb"<c2pa:manifest[^>]*>\s*([A-Za-z0-9+/=\s]+)\s*</c2pa:manifest>",
    re.DOTALL,
)

# Generic structured text: -----BEGIN C2PA MANIFEST-----
STRUCTURED_BEGIN = b"-----BEGIN C2PA MANIFEST-----"
STRUCTURED_END = b"-----END C2PA MANIFEST-----"

# Single-line form (in XML comment):
# <!-- -----BEGIN C2PA MANIFEST----- <ref> -----END C2PA MANIFEST----- -->
STRUCTURED_INLINE_PATTERN = re.compile(
    rb"-----BEGIN C2PA MANIFEST-----\s*([\s\S]*?)\s*-----END C2PA MANIFEST-----",
)

# data: URI prefix
DATA_URI_PREFIX = b"data:application/c2pa;base64,"


@register
class SVGExtractor:
    """Extract C2PA JUMBF from SVG/XML/structured text."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        # Exclude ZIP archives (DOCX, EPUB, ODT, etc.) - handled by ZIPExtractor
        if len(data) >= 4 and data[:4] == b"PK\x03\x04":
            return False
        if suffix in SVG_SUFFIXES or suffix in XML_SUFFIXES:
            return True
        if suffix == ".xhtml":
            return True
        header = data[:512]
        if b"<svg" in header:
            return True
        if b"<?xml" in header and (b"c2pa" in data[:4096] or STRUCTURED_BEGIN in data):
            return True
        # Generic structured text detection
        if STRUCTURED_BEGIN in data:
            return True
        return False

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        # Try SVG-specific comment pattern
        match = C2PA_COMMENT_PATTERN.search(data)
        if match:
            b64_data = match.group(1)
            b64_clean = re.sub(rb"\s+", b"", b64_data)
            jumbf_bytes = base64.b64decode(b64_clean)
            return ExtractionResult(
                jumbf_bytes=jumbf_bytes,
                container_format="svg",
                jumbf_offset=match.start(),
                jumbf_length=len(jumbf_bytes),
            )

        # Try SVG-specific element pattern
        match = C2PA_ELEMENT_PATTERN.search(data)
        if match:
            b64_data = match.group(1)
            b64_clean = re.sub(rb"\s+", b"", b64_data)
            jumbf_bytes = base64.b64decode(b64_clean)
            return ExtractionResult(
                jumbf_bytes=jumbf_bytes,
                container_format="svg",
                jumbf_offset=match.start(),
                jumbf_length=len(jumbf_bytes),
            )

        # Try generic structured text delimiters
        match = STRUCTURED_INLINE_PATTERN.search(data)
        if match:
            content = match.group(1).strip()
            return _parse_structured_reference(content, match.start())

        raise ExtractionError("No C2PA manifest found in SVG/XML/structured text")


def _parse_structured_reference(content: bytes, offset: int) -> ExtractionResult:
    """Parse the manifest reference between BEGIN/END delimiters."""
    # Check for data: URI (inline base64)
    if content.startswith(DATA_URI_PREFIX):
        b64_str = content[len(DATA_URI_PREFIX) :]
        b64_clean = re.sub(rb"\s+", b"", b64_str)
        try:
            jumbf_bytes = base64.b64decode(b64_clean)
        except Exception as exc:
            raise ExtractionError(f"Failed to decode data URI in structured text: {exc}") from exc
        return ExtractionResult(
            jumbf_bytes=jumbf_bytes,
            container_format="structured_text",
            jumbf_offset=offset,
            jumbf_length=len(jumbf_bytes),
        )

    # Check if content looks like plain base64 (no URI scheme)
    b64_clean = re.sub(rb"\s+", b"", content)
    if b64_clean and re.match(rb"^[A-Za-z0-9+/=]+$", b64_clean):
        try:
            jumbf_bytes = base64.b64decode(b64_clean)
            return ExtractionResult(
                jumbf_bytes=jumbf_bytes,
                container_format="structured_text",
                jumbf_offset=offset,
                jumbf_length=len(jumbf_bytes),
            )
        except Exception:
            pass

    # External URL reference
    url = content.decode("utf-8", errors="replace").strip()
    raise ExtractionError(
        f"Structured text C2PA manifest is an external reference: {url} "
        "(use sidecar .c2pa file or data: URI for inline embedding)"
    )
