"""Test vector generation orchestrator."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from cryptography.x509.oid import ExtendedKeyUsageOID

from c2pa_conformance.builder.manifest_builder import (
    ManifestSpec,
    build_manifest_store,
    build_multi_manifest_store,
)
from c2pa_conformance.builder.two_pass import build_bound_manifest
from c2pa_conformance.crypto.pki import (
    CertKeyPair,
    generate_intermediate_ca,
    generate_root_ca,
    generate_signer,
)
from c2pa_conformance.embedders import embed_jpeg, embed_png, embed_sidecar
from c2pa_conformance.vectors.assets import minimal_jpeg, minimal_png
from c2pa_conformance.vectors.definitions import VectorDefinition, get_all_definitions

_CONTAINER_EXT = {"jpeg": ".jpg", "png": ".png", "sidecar": ".c2pa"}


def generate_all_vectors(
    output_dir: Path,
    definitions: list[VectorDefinition] | None = None,
    categories: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate all test vectors to the output directory.

    Args:
        output_dir: Root directory for vector output.
        definitions: Optional override; defaults to get_all_definitions().
        categories: Optional filter by category name.

    Returns:
        List of metadata dicts for each generated vector.
    """
    if definitions is None:
        definitions = get_all_definitions()

    if categories:
        definitions = [d for d in definitions if d.category in categories]

    # Generate PKI once for all vectors
    pki = _generate_pki()

    results: list[dict[str, Any]] = []

    for defn in definitions:
        category_dir = output_dir / defn.category
        category_dir.mkdir(parents=True, exist_ok=True)

        ext = _CONTAINER_EXT.get(defn.container, ".bin")
        out_path = category_dir / f"{defn.name}{ext}"
        meta_path = category_dir / f"{defn.name}.json"

        try:
            vector_bytes = _generate_single(defn, pki)
            out_path.write_bytes(vector_bytes)

            metadata: dict[str, Any] = {
                "name": defn.name,
                "category": defn.category,
                "container": defn.container,
                "algorithm": defn.algorithm,
                "description": defn.description,
                "expected_pass": defn.expected_pass,
                "signer_variant": defn.signer_variant,
                "size_bytes": len(vector_bytes),
                "path": str(out_path),
            }
            meta_path.write_text(json.dumps(metadata, indent=2) + "\n")
            results.append(metadata)
        except Exception as exc:
            results.append(
                {
                    "name": defn.name,
                    "category": defn.category,
                    "error": str(exc),
                }
            )

    # Write index
    index_path = output_dir / "index.json"
    index_path.write_text(json.dumps(results, indent=2) + "\n")

    return results


def _generate_pki() -> dict[str, CertKeyPair]:
    """Generate test PKI hierarchy with valid, expired, and wrong-EKU signers."""
    root = generate_root_ca()
    intermediate = generate_intermediate_ca(root)

    now = datetime.datetime.now(datetime.timezone.utc)

    valid_signer = generate_signer(intermediate, common_name="Valid Test Signer")

    expired_signer = generate_signer(
        intermediate,
        common_name="Expired Test Signer",
        not_valid_before=now - datetime.timedelta(days=365),
        not_valid_after=now - datetime.timedelta(days=1),
    )

    wrong_eku_signer = generate_signer(
        intermediate,
        common_name="Wrong EKU Test Signer",
        eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH],
    )

    return {
        "valid": valid_signer,
        "expired": expired_signer,
        "wrong_eku": wrong_eku_signer,
        "intermediate": intermediate,
        "root": root,
    }


def _generate_single(defn: VectorDefinition, pki: dict[str, CertKeyPair]) -> bytes:
    """Generate a single test vector."""
    signer = pki.get(defn.signer_variant, pki["valid"])
    cert_chain = [signer.cert, pki["intermediate"].cert]
    label = f"urn:uuid:test-{defn.name}"

    # Multi-manifest ingredient chain
    if defn.ingredient_chain is not None:
        return _generate_ingredient_vector(defn, pki)

    if defn.content_bound:
        # Two-pass signing: produces content-bound manifest with data hash
        container_base = _get_base_container(defn.container)
        embedded, _ = build_bound_manifest(
            claim_data=defn.claim_data,
            assertions=defn.assertions,
            private_key=signer.key,
            cert_chain=cert_chain,
            algorithm=defn.algorithm,
            container_type=defn.container,
            container_bytes=container_base,
            manifest_label=label,
        )
        if defn.post_embed_mutation is not None:
            embedded = defn.post_embed_mutation(embedded)
        return embedded

    # Standard path: build manifest, optionally mutate, embed
    jumbf_bytes = build_manifest_store(
        claim_data=defn.claim_data,
        assertions=defn.assertions,
        private_key=signer.key,
        cert_chain=cert_chain,
        algorithm=defn.algorithm,
        manifest_label=label,
    )

    if defn.pre_embed_mutation is not None:
        jumbf_bytes = defn.pre_embed_mutation(jumbf_bytes)

    container_bytes = _embed(defn.container, jumbf_bytes)

    if defn.post_embed_mutation is not None:
        container_bytes = defn.post_embed_mutation(container_bytes)

    return container_bytes


def _generate_ingredient_vector(
    defn: VectorDefinition,
    pki: dict[str, CertKeyPair],
) -> bytes:
    """Generate a multi-manifest ingredient vector."""
    signer = pki.get(defn.signer_variant, pki["valid"])
    cert_chain = [signer.cert, pki["intermediate"].cert]

    specs: list[ManifestSpec] = []
    for chain_entry in defn.ingredient_chain:
        specs.append(
            ManifestSpec(
                claim_data=chain_entry.get("claim_data", {}),
                assertions=chain_entry.get("assertions", []),
                private_key=signer.key,
                cert_chain=cert_chain,
                algorithm=defn.algorithm,
                manifest_label=chain_entry.get("manifest_label", ""),
            )
        )

    jumbf_bytes = build_multi_manifest_store(specs)

    if defn.pre_embed_mutation is not None:
        jumbf_bytes = defn.pre_embed_mutation(jumbf_bytes)

    container_bytes = _embed(defn.container, jumbf_bytes)

    if defn.post_embed_mutation is not None:
        container_bytes = defn.post_embed_mutation(container_bytes)

    return container_bytes


def _get_base_container(container_type: str) -> bytes:
    """Return a minimal valid container for the given type."""
    if container_type == "jpeg":
        return minimal_jpeg()
    if container_type == "png":
        return minimal_png()
    return b""


def _embed(container_type: str, jumbf_bytes: bytes) -> bytes:
    """Embed JUMBF into a container of the given type."""
    if container_type == "jpeg":
        base = minimal_jpeg()
        return embed_jpeg(base, jumbf_bytes)
    elif container_type == "png":
        base = minimal_png()
        return embed_png(base, jumbf_bytes)
    elif container_type == "sidecar":
        return embed_sidecar(jumbf_bytes)
    else:
        raise ValueError(f"Unknown container type: {container_type}")
