"""Tests for collection_hash.py and text_hash.py binding verifiers."""

from __future__ import annotations

import hashlib
import io
import zipfile

from c2pa_conformance.binding.collection_hash import (
    validate_uri,
    verify_collection_hash,
)
from c2pa_conformance.binding.text_hash import (
    find_structured_delimiters,
    find_text_wrappers,
    verify_structured_text_hash,
    verify_text_hash,
)
from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_zip(files: dict[str, bytes]) -> bytes:
    """Build an in-memory ZIP archive from a name->bytes mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


# ---------------------------------------------------------------------------
# Collection hash tests (1-13)
# ---------------------------------------------------------------------------


def test_collection_hash_match() -> None:
    """Test 1: ZIP with 2 files and correct per-file SHA-256 hashes -> match."""
    content_a = b"Hello from file A"
    content_b = b"Hello from file B"
    asset_bytes = _build_zip({"chapter1.xhtml": content_a, "chapter2.xhtml": content_b})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "chapter1.xhtml", "hash": _sha256(content_a)},
            {"uri": "chapter2.xhtml", "hash": _sha256(content_b)},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is True
    assert result.status_code == "assertion.collectionHash.match"
    assert result.files_checked == 2
    assert result.files_matched == 2
    assert result.algorithm == "sha256"


def test_collection_hash_mismatch() -> None:
    """Test 2: Tamper one file after computing hashes -> mismatch."""
    content_a = b"Original content"
    content_b = b"Other file"
    # Build ZIP with tampered content_a but hash of original
    asset_bytes = _build_zip({"doc/a.txt": b"Tampered content", "doc/b.txt": content_b})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "doc/a.txt", "hash": _sha256(content_a)},  # wrong hash
            {"uri": "doc/b.txt", "hash": _sha256(content_b)},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.mismatch"
    assert "doc/a.txt" in result.message


def test_collection_hash_file_not_found() -> None:
    """Test 3: Reference a file that does not exist in the archive -> mismatch."""
    asset_bytes = _build_zip({"existing.txt": b"data"})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "nonexistent.txt", "hash": _sha256(b"data")},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.mismatch"
    assert "nonexistent.txt" in result.message


def test_collection_hash_invalid_uri_traversal() -> None:
    """Test 4: Path traversal URI (../evil.txt) -> invalidURI."""
    asset_bytes = _build_zip({"legit.txt": b"ok"})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "../evil.txt", "hash": _sha256(b"ok")},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.invalidURI"
    assert "../evil.txt" in result.message


def test_collection_hash_absolute_uri() -> None:
    """Test 5: Absolute path URI -> invalidURI."""
    asset_bytes = _build_zip({"ok.txt": b"data"})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "/etc/passwd", "hash": _sha256(b"data")},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.invalidURI"


def test_collection_hash_scheme_uri() -> None:
    """Test 6: URI with http:// scheme -> invalidURI."""
    asset_bytes = _build_zip({"ok.txt": b"data"})

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [
            {"uri": "http://example.com/file.txt", "hash": _sha256(b"data")},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.invalidURI"


def test_collection_hash_malformed_no_uri_maps() -> None:
    """Test 7: Missing uri_maps -> malformed."""
    asset_bytes = _build_zip({"a.txt": b"data"})

    result = verify_collection_hash(asset_bytes, {"alg": "sha256"})

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.malformed"
    assert "uri_maps" in result.message.lower()


def test_collection_hash_unsupported_alg() -> None:
    """Test 8: Unsupported algorithm -> algorithm.unsupported."""
    asset_bytes = _build_zip({"a.txt": b"data"})

    assertion_data = {
        "alg": "md5",
        "uri_maps": [{"uri": "a.txt", "hash": b"\x00" * 16}],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "algorithm.unsupported"


def test_collection_hash_bad_zip() -> None:
    """Test 9: Non-ZIP bytes -> malformed."""
    not_a_zip = b"This is definitely not a ZIP file. PK nowhere."

    assertion_data = {
        "alg": "sha256",
        "uri_maps": [{"uri": "a.txt", "hash": _sha256(b"x")}],
    }
    result = verify_collection_hash(not_a_zip, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.malformed"
    assert "ZIP" in result.message


def test_collection_hash_file_count_match() -> None:
    """Test 10: Correct file_count with all files verified -> match."""
    content_a = b"file alpha"
    content_b = b"file beta"
    asset_bytes = _build_zip({"alpha.txt": content_a, "beta.txt": content_b})

    assertion_data = {
        "alg": "sha256",
        "file_count": 2,
        "uri_maps": [
            {"uri": "alpha.txt", "hash": _sha256(content_a)},
            {"uri": "beta.txt", "hash": _sha256(content_b)},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is True
    assert result.status_code == "assertion.collectionHash.match"


def test_collection_hash_file_count_mismatch() -> None:
    """Test 11: Wrong file_count -> incorrectFileCount."""
    content_a = b"file alpha"
    content_b = b"file beta"
    asset_bytes = _build_zip({"alpha.txt": content_a, "beta.txt": content_b})

    assertion_data = {
        "alg": "sha256",
        "file_count": 5,  # wrong - only 2 files in archive
        "uri_maps": [
            {"uri": "alpha.txt", "hash": _sha256(content_a)},
            {"uri": "beta.txt", "hash": _sha256(content_b)},
        ],
    }
    result = verify_collection_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.collectionHash.incorrectFileCount"
    assert "5" in result.message
    assert "2" in result.message


def test_validate_uri_safe() -> None:
    """Test 12: Safe relative URIs pass validation."""
    safe_uris = [
        "OEBPS/content.opf",
        "chapter1.xhtml",
        "images/cover.jpg",
        "META-INF/container.xml",
        "word/document.xml",
        "sub/dir/file.bin",
    ]
    for uri in safe_uris:
        is_valid, msg = validate_uri(uri)
        assert is_valid is True, f"Expected '{uri}' to be valid but got: {msg}"
        assert msg == ""


def test_validate_uri_traversal() -> None:
    """Test 13: Path traversal URIs fail validation."""
    bad_uris = [
        "../escape.txt",
        "sub/../../../etc/passwd",
        "/absolute/path",
        "C:/windows/system32",
        "http://evil.com/file",
        "ftp://host/file",
    ]
    for uri in bad_uris:
        is_valid, msg = validate_uri(uri)
        assert is_valid is False, f"Expected '{uri}' to be invalid"
        assert msg != "", f"Expected non-empty error message for '{uri}'"


# ---------------------------------------------------------------------------
# Text hash tests (14-18)
# ---------------------------------------------------------------------------

_TEXT_MAGIC = b"C2PATXT\x00"


def _make_text_asset_with_wrapper(prefix: bytes, wrapper_payload: bytes, suffix: bytes) -> bytes:
    """Construct a text asset: prefix + wrapper_magic + payload + suffix."""
    return prefix + _TEXT_MAGIC + wrapper_payload + suffix


def test_text_hash_match() -> None:
    """Test 14: Text asset with one wrapper, correct hash -> match."""
    prefix = b"This is the visible text content.\n"
    wrapper_payload = b"\x00\x01manifest_bytes_here"
    suffix = b""
    asset_bytes = _make_text_asset_with_wrapper(prefix, wrapper_payload, suffix)

    # Wrapper spans from len(prefix) to end of file
    wrapper_start = len(prefix)
    wrapper_end = len(asset_bytes)
    exclusion = ExclusionRange(start=wrapper_start, length=wrapper_end - wrapper_start)
    expected_hash = compute_hash(asset_bytes, "sha256", [exclusion])

    assertion_data = {"alg": "sha256", "hash": expected_hash}
    result = verify_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is True
    assert result.status_code == "assertion.dataHash.match"
    assert result.wrapper_count == 1
    assert result.algorithm == "sha256"


def test_text_hash_mismatch() -> None:
    """Test 15: Tampered text (different prefix) -> mismatch."""
    prefix = b"Original visible content.\n"
    wrapper_payload = b"\x00\x01manifest"
    asset_bytes = prefix + _TEXT_MAGIC + wrapper_payload

    # Compute hash for original, then tamper the prefix
    wrapper_start = len(prefix)
    exclusion = ExclusionRange(start=wrapper_start, length=len(asset_bytes) - wrapper_start)
    expected_hash = compute_hash(asset_bytes, "sha256", [exclusion])

    # Tamper: change the prefix
    tampered = b"Tampered visible content.\n" + _TEXT_MAGIC + wrapper_payload
    assertion_data = {"alg": "sha256", "hash": expected_hash}
    result = verify_text_hash(tampered, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.mismatch"


def test_text_hash_no_wrapper() -> None:
    """Test 16: Asset with no wrapper magic -> corruptedWrapper."""
    asset_bytes = b"Plain text with no C2PA wrapper at all."
    assertion_data = {"alg": "sha256", "hash": _sha256(b"x")}
    result = verify_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "manifest.text.corruptedWrapper"
    assert result.wrapper_count == 0


def test_text_hash_multiple_wrappers() -> None:
    """Test 17: Asset with two wrappers -> multipleWrappers."""
    asset_bytes = b"text" + _TEXT_MAGIC + b"manifest1" + _TEXT_MAGIC + b"manifest2"
    assertion_data = {"alg": "sha256", "hash": _sha256(b"x")}
    result = verify_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "manifest.text.multipleWrappers"
    assert result.wrapper_count == 2


def test_text_hash_missing_alg() -> None:
    """Test 18: No algorithm field -> algorithm.unsupported."""
    asset_bytes = b"text" + _TEXT_MAGIC + b"manifest"
    assertion_data = {"hash": _sha256(b"x")}  # no "alg"
    result = verify_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "algorithm.unsupported"


# ---------------------------------------------------------------------------
# Structured text hash tests (19-24)
# ---------------------------------------------------------------------------

_BEGIN = b"-----BEGIN C2PA MANIFEST-----"
_END = b"-----END C2PA MANIFEST-----"


def _make_svg_with_manifest(before: bytes, manifest_body: bytes, after: bytes) -> bytes:
    """Construct a synthetic SVG asset with a structured C2PA delimiter block."""
    return before + _BEGIN + manifest_body + _END + after


def test_structured_text_hash_match() -> None:
    """Test 19: SVG with one delimiter block, correct hash -> match."""
    before = b"<svg><defs></defs><g>content</g>"
    manifest_body = b"\nbase64manifestdata\n"
    after = b"</svg>"
    asset_bytes = _make_svg_with_manifest(before, manifest_body, after)

    # Exclusion: the full delimiter block including begin+body+end markers
    block_start = len(before)
    block_end = len(before) + len(_BEGIN) + len(manifest_body) + len(_END)
    exclusion = ExclusionRange(start=block_start, length=block_end - block_start)
    expected_hash = compute_hash(asset_bytes, "sha256", [exclusion])

    assertion_data = {"alg": "sha256", "hash": expected_hash}
    result = verify_structured_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is True
    assert result.status_code == "assertion.dataHash.match"
    assert result.wrapper_count == 1
    assert result.algorithm == "sha256"


def test_structured_text_hash_mismatch() -> None:
    """Test 20: Tampered SVG (changed content after manifest block) -> mismatch."""
    before = b"<svg><g>original</g>"
    manifest_body = b"\nmanifest\n"
    after = b"</svg>"
    asset_bytes = _make_svg_with_manifest(before, manifest_body, after)

    block_start = len(before)
    block_end = block_start + len(_BEGIN) + len(manifest_body) + len(_END)
    exclusion = ExclusionRange(start=block_start, length=block_end - block_start)
    expected_hash = compute_hash(asset_bytes, "sha256", [exclusion])

    # Tamper: change "original" to "tampered"
    tampered = _make_svg_with_manifest(b"<svg><g>tampered</g>", manifest_body, after)
    assertion_data = {"alg": "sha256", "hash": expected_hash}
    result = verify_structured_text_hash(tampered, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.mismatch"


def test_structured_text_no_delimiters() -> None:
    """Test 21: SVG with no delimiter block -> noManifest."""
    asset_bytes = b"<svg><g>no manifest here</g></svg>"
    assertion_data = {"alg": "sha256", "hash": _sha256(b"x")}
    result = verify_structured_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "manifest.structuredText.noManifest"


def test_structured_text_multiple_blocks() -> None:
    """Test 22: Asset with two delimiter blocks -> multipleReferences."""
    block = _BEGIN + b"\ndata\n" + _END
    asset_bytes = b"<svg>" + block + b"<g/>" + block + b"</svg>"
    assertion_data = {"alg": "sha256", "hash": _sha256(b"x")}
    result = verify_structured_text_hash(asset_bytes, assertion_data)

    assert result.is_valid is False
    assert result.status_code == "manifest.structuredText.multipleReferences"


def test_find_text_wrappers() -> None:
    """Test 23: find_text_wrappers returns correct offsets for multiple wrappers."""
    piece1 = b"first manifest data"
    piece2 = b"second manifest data"
    asset_bytes = b"prefix" + _TEXT_MAGIC + piece1 + _TEXT_MAGIC + piece2

    wrappers = find_text_wrappers(asset_bytes)

    assert len(wrappers) == 2

    # First wrapper: starts at len("prefix"), ends at start of second magic
    w1_start, w1_end = wrappers[0]
    assert w1_start == len(b"prefix")
    assert asset_bytes[w1_start : w1_start + len(_TEXT_MAGIC)] == _TEXT_MAGIC

    # Second wrapper: starts where second magic begins, ends at EOF
    w2_start, w2_end = wrappers[1]
    assert w2_start == len(b"prefix") + len(_TEXT_MAGIC) + len(piece1)
    assert w2_end == len(asset_bytes)

    # Wrappers must not overlap
    assert w1_end == w2_start


def test_find_structured_delimiters() -> None:
    """Test 24: find_structured_delimiters returns correct offsets from SVG content."""
    before = b"<svg><metadata>"
    body = b"\nbase64data\n"
    after = b"</metadata></svg>"
    asset_bytes = before + _BEGIN + body + _END + after

    blocks = find_structured_delimiters(asset_bytes)

    assert len(blocks) == 1
    block_start, block_end = blocks[0]
    assert block_start == len(before)
    assert block_end == len(before) + len(_BEGIN) + len(body) + len(_END)
    # The bytes at the block range should start with the begin marker
    assert asset_bytes[block_start : block_start + len(_BEGIN)] == _BEGIN
    # The bytes immediately before block_end should end with the end marker
    assert asset_bytes[block_end - len(_END) : block_end] == _END
