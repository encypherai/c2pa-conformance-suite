"""Two-pass signing for content-bound C2PA manifests.

Implements the two-pass signing protocol required by C2PA v2.4 for
embedding a c2pa.hash.data assertion that binds the manifest to its
container. The hash must exclude the JUMBF manifest bytes themselves,
creating a circular dependency resolved by:

  Pass 1: Build manifest with placeholder hash, embed, measure exclusion range.
  Pass 2: Compute real hash with exclusion, rebuild manifest, re-embed.
"""

from __future__ import annotations

import math
import uuid
from typing import Any

from c2pa_conformance.builder.manifest_builder import build_manifest_store
from c2pa_conformance.crypto.hashing import (
    HASH_ALGORITHMS,
    ExclusionRange,
    compute_hash,
)
from c2pa_conformance.embedders.jpeg import (
    MAX_SEGMENT_PAYLOAD,
)
from c2pa_conformance.embedders.jpeg import (
    _find_insert_position as jpeg_insert_pos,
)
from c2pa_conformance.embedders.png import _find_idat_position as png_insert_pos

# COSE algorithm ID -> content hash algorithm name
_COSE_ALG_TO_HASH: dict[int, str] = {
    -7: "sha256",
    -35: "sha384",
    -36: "sha512",
    -37: "sha256",
    -38: "sha384",
    -39: "sha512",
    -8: "sha256",
}

_MAX_ITERATIONS = 5


def build_bound_manifest(
    claim_data: dict[str, Any],
    assertions: list[dict[str, Any]],
    private_key: Any,
    cert_chain: list[Any],
    algorithm: int = -7,
    container_type: str = "jpeg",
    container_bytes: bytes = b"",
    manifest_label: str | None = None,
    hash_algorithm: str | None = None,
) -> tuple[bytes, bytes]:
    """Build a content-bound C2PA manifest with a correct data hash.

    Performs iterative two-pass signing: builds a trial manifest to
    determine the exclusion range, then computes the real content hash
    and rebuilds.

    Args:
        claim_data: Claim fields.
        assertions: Assertion dicts (label + data). Do NOT include
            c2pa.hash.data; it is added automatically.
        private_key: Signing key.
        cert_chain: Certificate chain.
        algorithm: COSE algorithm ID (default ES256 = -7).
        container_type: "jpeg", "png", or "sidecar".
        container_bytes: Raw container bytes (before embedding).
        manifest_label: Optional manifest label (auto-generated if None).
        hash_algorithm: Override hash algorithm (default: derived from COSE alg).

    Returns:
        (embedded_container_bytes, jumbf_bytes) tuple.
    """
    if manifest_label is None:
        manifest_label = f"urn:uuid:{uuid.uuid4()}"

    if hash_algorithm is None:
        hash_algorithm = _COSE_ALG_TO_HASH.get(algorithm, "sha256")

    digest_size = HASH_ALGORITHMS[hash_algorithm].digest_size
    placeholder_hash = b"\x00" * digest_size

    if container_type == "sidecar":
        return _build_sidecar(
            claim_data,
            assertions,
            private_key,
            cert_chain,
            algorithm,
            manifest_label,
        )

    insert_pos = _get_insert_position(container_type, container_bytes)

    # Iterative size stabilization: the exclusion length depends on the
    # JUMBF size, which depends on the CBOR-encoded exclusion length.
    exclusion_length = 0
    jumbf_bytes = b""

    for _ in range(_MAX_ITERATIONS):
        data_hash_assertion = _make_data_hash_assertion(
            hash_algorithm,
            placeholder_hash,
            insert_pos,
            exclusion_length,
        )
        all_assertions = assertions + [data_hash_assertion]

        jumbf_bytes = build_manifest_store(
            claim_data=claim_data,
            assertions=all_assertions,
            private_key=private_key,
            cert_chain=cert_chain,
            algorithm=algorithm,
            manifest_label=manifest_label,
        )

        new_length = _compute_embedded_size(container_type, len(jumbf_bytes))
        if new_length == exclusion_length:
            break
        exclusion_length = new_length
    else:
        msg = f"Two-pass signing failed to converge after {_MAX_ITERATIONS} iterations"
        raise RuntimeError(msg)

    # Embed with placeholder hash to produce trial container
    embedded = _do_embed(container_type, container_bytes, jumbf_bytes)

    # Compute real content hash with exclusion range
    exclusion = ExclusionRange(start=insert_pos, length=exclusion_length)
    real_hash = compute_hash(embedded, hash_algorithm, [exclusion])

    # Rebuild with real hash (same byte length, so JUMBF size is unchanged)
    data_hash_assertion = _make_data_hash_assertion(
        hash_algorithm,
        real_hash,
        insert_pos,
        exclusion_length,
    )
    all_assertions = assertions + [data_hash_assertion]

    final_jumbf = build_manifest_store(
        claim_data=claim_data,
        assertions=all_assertions,
        private_key=private_key,
        cert_chain=cert_chain,
        algorithm=algorithm,
        manifest_label=manifest_label,
    )

    if len(final_jumbf) != len(jumbf_bytes):
        msg = (
            f"JUMBF size changed after hash replacement: {len(jumbf_bytes)} -> {len(final_jumbf)}"
        )
        raise RuntimeError(msg)

    final_embedded = _do_embed(container_type, container_bytes, final_jumbf)
    return final_embedded, final_jumbf


def _build_sidecar(
    claim_data: dict[str, Any],
    assertions: list[dict[str, Any]],
    private_key: Any,
    cert_chain: list[Any],
    algorithm: int,
    manifest_label: str,
) -> tuple[bytes, bytes]:
    """Build a sidecar manifest (no content binding)."""
    jumbf = build_manifest_store(
        claim_data=claim_data,
        assertions=assertions,
        private_key=private_key,
        cert_chain=cert_chain,
        algorithm=algorithm,
        manifest_label=manifest_label,
    )
    return jumbf, jumbf


def _make_data_hash_assertion(
    algorithm: str,
    hash_value: bytes,
    exclusion_start: int,
    exclusion_length: int,
) -> dict[str, Any]:
    """Create a c2pa.hash.data assertion dict."""
    data: dict[str, Any] = {
        "alg": algorithm,
        "hash": hash_value,
        "pad": b"",
        "name": "jumbf manifest",
    }
    if exclusion_length > 0:
        data["exclusions"] = [
            {"start": exclusion_start, "length": exclusion_length},
        ]
    return {"label": "c2pa.hash.data", "data": data}


def _get_insert_position(container_type: str, container_bytes: bytes) -> int:
    """Determine where JUMBF will be inserted in the container."""
    if container_type == "jpeg":
        return jpeg_insert_pos(container_bytes)
    if container_type == "png":
        return png_insert_pos(container_bytes)
    msg = f"Unknown container type: {container_type}"
    raise ValueError(msg)


def _compute_embedded_size(container_type: str, jumbf_length: int) -> int:
    """Compute total embedded byte count for a given JUMBF length."""
    if container_type == "jpeg":
        n = max(1, math.ceil(jumbf_length / MAX_SEGMENT_PAYLOAD))
        # Each APP11 segment: 2 (marker) + 2 (Lp) + 2 (CI) + 2 (En) + 4 (Z)
        return jumbf_length + n * 12
    if container_type == "png":
        # caBX chunk: 4 (Length) + 4 (Type) + data + 4 (CRC)
        return jumbf_length + 12
    msg = f"Unknown container type: {container_type}"
    raise ValueError(msg)


def _do_embed(
    container_type: str,
    container_bytes: bytes,
    jumbf_bytes: bytes,
) -> bytes:
    """Embed JUMBF into a container."""
    from c2pa_conformance.embedders import embed_jpeg, embed_png, embed_sidecar

    if container_type == "jpeg":
        return embed_jpeg(container_bytes, jumbf_bytes)
    if container_type == "png":
        return embed_png(container_bytes, jumbf_bytes)
    if container_type == "sidecar":
        return embed_sidecar(jumbf_bytes)
    msg = f"Unknown container type: {container_type}"
    raise ValueError(msg)
