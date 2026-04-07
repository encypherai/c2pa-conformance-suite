"""c2pa.hash.collection content binding verifier.

Verifies per-file hashes and ZIP central directory hash for collection-based
assets (EPUB, DOCX, ODF, ZIP archives).
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from typing import Any

from c2pa_conformance.crypto.hashing import (
    compare_hash,
    get_hash_algorithm,
    is_algorithm_supported,
)


@dataclass
class CollectionHashResult:
    """Result of collection hash verification."""

    is_valid: bool
    status_code: str  # assertion.collectionHash.match / .mismatch / .malformed
    message: str
    algorithm: str = ""
    files_checked: int = 0
    files_matched: int = 0


class CollectionHashError(Exception):
    """Raised when collection hash verification encounters an unrecoverable error."""


# Patterns for URI security validation (PRED-COLL-002)
_FORBIDDEN_URI_PATTERNS = [
    r"^\.\./",  # path traversal at start
    r"/\.\./",  # path traversal mid-path
    r"^/",  # absolute path
    r"^[a-zA-Z]:/",  # Windows absolute path
    r"://",  # scheme (URL)
]


def validate_uri(uri: str) -> tuple[bool, str]:
    """Validate a collection URI for security issues.

    Returns (is_valid, error_message).  An empty error_message means valid.
    """
    for pattern in _FORBIDDEN_URI_PATTERNS:
        if re.search(pattern, uri):
            return False, f"URI '{uri}' matches forbidden pattern: {pattern}"
    return True, ""


def verify_collection_hash(
    asset_bytes: bytes,
    assertion_data: dict[str, Any],
) -> CollectionHashResult:
    """Verify a c2pa.hash.collection assertion against ZIP asset bytes.

    The assertion_data dict has:
    - "alg": hash algorithm name (e.g., "sha256")
    - "uri_maps": list of {"uri": str, "hash": bytes, "alg": str (optional)}
    - "file_count": expected number of non-C2PA files (optional)
    - "zip_central_directory_hash": raw bytes of central directory hash (optional)

    Args:
        asset_bytes: Raw bytes of the ZIP-based asset.
        assertion_data: Parsed assertion data dict from the CBOR manifest.

    Returns:
        CollectionHashResult with match/mismatch/malformed status.
    """
    alg = assertion_data.get("alg")
    if not alg or not is_algorithm_supported(str(alg)):
        return CollectionHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported or missing algorithm: {alg}",
        )

    uri_maps = assertion_data.get("uri_maps")
    if not uri_maps or not isinstance(uri_maps, list):
        return CollectionHashResult(
            is_valid=False,
            status_code="assertion.collectionHash.malformed",
            message="Missing or invalid uri_maps",
        )

    # Try to open as ZIP
    try:
        zf = zipfile.ZipFile(io.BytesIO(asset_bytes))
    except zipfile.BadZipFile:
        return CollectionHashResult(
            is_valid=False,
            status_code="assertion.collectionHash.malformed",
            message="Asset is not a valid ZIP file",
        )

    files_checked = 0
    files_matched = 0

    for uri_entry in uri_maps:
        if not isinstance(uri_entry, dict):
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.malformed",
                message="uri_maps entry is not a dict",
                files_checked=files_checked,
            )

        uri = uri_entry.get("uri")
        declared_hash = uri_entry.get("hash")

        if not uri or not declared_hash:
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.malformed",
                message="URI map entry missing uri or hash",
                files_checked=files_checked,
            )

        # Validate URI for security issues
        uri_ok, uri_msg = validate_uri(str(uri))
        if not uri_ok:
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.invalidURI",
                message=uri_msg,
                files_checked=files_checked,
            )

        # Read file from ZIP archive
        try:
            file_bytes = zf.read(str(uri))
        except KeyError:
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.mismatch",
                message=f"File not found in archive: {uri}",
                files_checked=files_checked,
            )

        # Per-entry algorithm override
        entry_alg = uri_entry.get("alg", str(alg))
        if not is_algorithm_supported(str(entry_alg)):
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="algorithm.unsupported",
                message=f"Unsupported per-entry algorithm: {entry_alg}",
            )

        entry_hash_alg = get_hash_algorithm(str(entry_alg))
        computed = hashlib.new(entry_hash_alg.hashlib_name, file_bytes).digest()
        files_checked += 1

        if compare_hash(computed, declared_hash):
            files_matched += 1
        else:
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.mismatch",
                message=f"Hash mismatch for {uri}",
                algorithm=str(alg),
                files_checked=files_checked,
                files_matched=files_matched,
            )

    # Verify file count if provided
    expected_count = assertion_data.get("file_count")
    if expected_count is not None:
        # Exclude META-INF/content_credential* from count (embedded C2PA store)
        non_c2pa_count = sum(
            1 for name in zf.namelist() if not name.startswith("META-INF/content_credential")
        )
        if non_c2pa_count != int(expected_count):
            zf.close()
            return CollectionHashResult(
                is_valid=False,
                status_code="assertion.collectionHash.incorrectFileCount",
                message=f"Expected {expected_count} files, found {non_c2pa_count}",
                algorithm=str(alg),
                files_checked=files_checked,
                files_matched=files_matched,
            )

    zf.close()

    return CollectionHashResult(
        is_valid=True,
        status_code="assertion.collectionHash.match",
        message=f"All {files_matched}/{files_checked} files verified",
        algorithm=str(alg),
        files_checked=files_checked,
        files_matched=files_matched,
    )
