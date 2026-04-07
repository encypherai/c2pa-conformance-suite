"""HTML container extractor.

Extracts C2PA JUMBF from HTML documents containing either:
1. Inline: <script type="application/c2pa">base64-encoded-JUMBF</script>
2. External: <link rel="c2pa-manifest" href="..." type="application/c2pa">

Per spec, at most one C2PA manifest element per document; script and link
cannot coexist.
"""

from __future__ import annotations

import base64
import re

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

HTML_SUFFIXES = {".html", ".htm", ".xhtml"}

# Match <script type="application/c2pa">...base64...</script>
SCRIPT_PATTERN = re.compile(
    rb'<script\s[^>]*type\s*=\s*["\']application/c2pa["\'][^>]*>'
    rb"\s*([\s\S]*?)\s*</script>",
    re.IGNORECASE,
)

# Match <link rel="c2pa-manifest" href="..." ...>
LINK_PATTERN = re.compile(
    rb'<link\s[^>]*rel\s*=\s*["\']c2pa-manifest["\'][^>]*/?>',
    re.IGNORECASE,
)

HREF_PATTERN = re.compile(
    rb'href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@register
class HTMLExtractor:
    """Extract C2PA JUMBF from HTML script or link element."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in HTML_SUFFIXES:
            return True
        header = data[:512].lower()
        return b"<!doctype html" in header or b"<html" in header

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        # Check for inline script
        script_matches = list(SCRIPT_PATTERN.finditer(data))
        link_matches = list(LINK_PATTERN.finditer(data))

        if script_matches and link_matches:
            raise ExtractionError(
                "HTML contains both <script> and <link> C2PA elements "
                "(manifest.html.multipleManifests)"
            )

        if len(script_matches) > 1:
            raise ExtractionError(
                "HTML contains multiple C2PA <script> elements (manifest.html.multipleManifests)"
            )

        if len(link_matches) > 1:
            raise ExtractionError(
                "HTML contains multiple C2PA <link> elements (manifest.html.multipleManifests)"
            )

        if script_matches:
            b64_content = script_matches[0].group(1)
            b64_clean = re.sub(rb"\s+", b"", b64_content)
            try:
                jumbf_bytes = base64.b64decode(b64_clean)
            except Exception as exc:
                raise ExtractionError(
                    f"Failed to decode base64 in C2PA script element: {exc}"
                ) from exc

            return ExtractionResult(
                jumbf_bytes=jumbf_bytes,
                container_format="html",
                jumbf_offset=script_matches[0].start(),
                jumbf_length=len(jumbf_bytes),
            )

        if link_matches:
            href_match = HREF_PATTERN.search(link_matches[0].group(0))
            if href_match:
                href = href_match.group(1).decode("utf-8", errors="replace")

                # Handle data: URI inline
                if href.startswith("data:application/c2pa;base64,"):
                    b64_str = href[len("data:application/c2pa;base64,") :]
                    try:
                        jumbf_bytes = base64.b64decode(b64_str)
                    except Exception as exc:
                        raise ExtractionError(
                            f"Failed to decode data URI in C2PA link: {exc}"
                        ) from exc

                    return ExtractionResult(
                        jumbf_bytes=jumbf_bytes,
                        container_format="html",
                        jumbf_offset=link_matches[0].start(),
                        jumbf_length=len(jumbf_bytes),
                    )

                # External reference - we cannot fetch it, report it
                raise ExtractionError(
                    f"C2PA manifest is an external reference: {href} "
                    "(use sidecar .c2pa file or inline script element)"
                )

            raise ExtractionError("C2PA <link> element has no href attribute")

        raise ExtractionError("No C2PA manifest found in HTML")
