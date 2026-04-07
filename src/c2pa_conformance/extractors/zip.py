"""ZIP container extractor (EPUB, DOCX/OOXML, ODF, OpenXPS).

Extracts C2PA JUMBF from ZIP archives containing a manifest store at
the path META-INF/content_credential.c2pa.

Per the C2PA spec, this file must be stored uncompressed (compression
method 0) and not encrypted. The file contents are raw JUMBF bytes.
"""

from __future__ import annotations

import zipfile
from io import BytesIO

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

C2PA_ZIP_PATH = "META-INF/content_credential.c2pa"

ZIP_SUFFIXES = {
    ".epub",
    ".docx",
    ".xlsx",
    ".pptx",  # OOXML
    ".odt",
    ".ods",
    ".odp",  # ODF
    ".oxps",
    ".xps",  # OpenXPS
    ".zip",
}

ZIP_MAGIC = b"PK\x03\x04"


@register
class ZIPExtractor:
    """Extract C2PA JUMBF from ZIP META-INF/content_credential.c2pa."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in ZIP_SUFFIXES:
            return True
        return len(data) >= 4 and data[:4] == ZIP_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        try:
            zf = zipfile.ZipFile(BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise ExtractionError(f"Not a valid ZIP file: {exc}") from exc

        if C2PA_ZIP_PATH not in zf.namelist():
            zf.close()
            raise ExtractionError(f"No {C2PA_ZIP_PATH} found in ZIP archive")

        info = zf.getinfo(C2PA_ZIP_PATH)

        # Spec requires stored (uncompressed) and not encrypted
        if info.compress_type != zipfile.ZIP_STORED:
            zf.close()
            raise ExtractionError(
                f"{C2PA_ZIP_PATH} is compressed (method={info.compress_type}), "
                "spec requires stored (method=0)"
            )

        jumbf_bytes = zf.read(C2PA_ZIP_PATH)
        zf.close()

        return ExtractionResult(
            jumbf_bytes=jumbf_bytes,
            container_format="zip",
            jumbf_offset=info.header_offset,
            jumbf_length=len(jumbf_bytes),
        )
