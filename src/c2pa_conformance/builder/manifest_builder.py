"""C2PA manifest store builder for test vector generation.

Builds complete manifest stores from components, producing raw JUMBF
bytes that can be embedded in container formats or written as sidecar files.
Produces claim v2 format compatible with c2pa-tool.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

import cbor2

from c2pa_conformance.builder.cose_signer import sign_cose
from c2pa_conformance.builder.jumbf_builder import (
    build_cbor_box,
    build_jumd,
    build_superbox,
    build_superbox_from_parts,
)
from c2pa_conformance.parser.jumbf import (
    C2PA_ASSERTION_STORE_UUID,
    C2PA_CBOR_ASSERTION_UUID,
    C2PA_CLAIM_UUID,
    C2PA_MANIFEST_STORE_UUID,
    C2PA_MANIFEST_UUID,
    C2PA_SIGNATURE_UUID,
)

# Version string for claim_generator_info
_GENERATOR_NAME = "c2pa-conformance-suite"
_GENERATOR_VERSION = "0.1.0"


@dataclass
class ManifestSpec:
    """Specification for a single manifest within a multi-manifest store."""

    claim_data: dict[str, Any] = field(default_factory=dict)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    private_key: Any = None
    cert_chain: list[Any] = field(default_factory=list)
    algorithm: int = -7
    manifest_label: str = ""


def build_manifest_store(
    claim_data: dict[str, Any],
    assertions: list[dict[str, Any]],
    private_key: Any,
    cert_chain: list[Any],
    algorithm: int = -7,
    manifest_label: str | None = None,
) -> bytes:
    """Build a complete C2PA manifest store as raw JUMBF bytes.

    Produces a claim v2 format manifest compatible with c2pa-tool.
    The output can be parsed by parse_manifest_store() and verified by
    verify_manifest_signature().

    Args:
        claim_data: Claim fields merged with auto-generated fields.
        assertions: List of assertion dicts, each with 'label' and 'data'.
        private_key: Signing private key.
        cert_chain: X.509 certificate chain [signer, intermediate, ...].
        algorithm: COSE algorithm ID (default ES256 = -7).
        manifest_label: Optional manifest label (auto-generated if None).

    Returns:
        Raw JUMBF bytes for the complete manifest store.
    """
    if manifest_label is None:
        manifest_label = f"urn:uuid:{uuid.uuid4()}"

    manifest_box = _build_manifest_box(
        claim_data=claim_data,
        assertions=assertions,
        private_key=private_key,
        cert_chain=cert_chain,
        algorithm=algorithm,
        manifest_label=manifest_label,
    )

    return build_superbox(C2PA_MANIFEST_STORE_UUID, "c2pa", [manifest_box])


def build_multi_manifest_store(specs: list[ManifestSpec]) -> bytes:
    """Build a manifest store containing multiple manifests.

    The last manifest in the list becomes the active manifest (per C2PA
    convention). Earlier manifests are typically referenced as ingredients
    by the active manifest.
    """
    manifest_boxes: list[bytes] = []

    for spec in specs:
        label = spec.manifest_label or f"urn:uuid:{uuid.uuid4()}"
        mbox = _build_manifest_box(
            claim_data=spec.claim_data,
            assertions=spec.assertions,
            private_key=spec.private_key,
            cert_chain=spec.cert_chain,
            algorithm=spec.algorithm,
            manifest_label=label,
        )
        manifest_boxes.append(mbox)

    return build_superbox(C2PA_MANIFEST_STORE_UUID, "c2pa", manifest_boxes)


def _build_manifest_box(
    claim_data: dict[str, Any],
    assertions: list[dict[str, Any]],
    private_key: Any,
    cert_chain: list[Any],
    algorithm: int,
    manifest_label: str,
) -> bytes:
    """Build a single manifest JUMBF superbox (without the store wrapper)."""
    assertion_boxes: list[bytes] = []
    assertion_refs: list[dict[str, Any]] = []

    for assertion in assertions:
        label = assertion["label"]
        data = assertion.get("data", {})

        cbor_bytes = cbor2.dumps(data)
        cbor_box = build_cbor_box(cbor_bytes)

        # Generate a random salt and embed it in the assertion's JUMD.
        # c2pa-rs verifies assertion hashes by reconstructing the superbox
        # payload (JUMD + content box) with the salt from the JUMD, then
        # comparing SHA-256 of that payload to the claim ref hash.
        # Without salt, SHA-256(raw_cbor) matches the "old style" check
        # in c2pa-rs store.rs:is_old_assertion() and triggers PrereleaseError.
        salt = os.urandom(16)
        jumd_bytes = build_jumd(C2PA_CBOR_ASSERTION_UUID, label, salt=salt)

        # Hash over the superbox payload: JUMD box (with salt) + CBOR content box
        superbox_payload = jumd_bytes + cbor_box
        ref_hash = hashlib.sha256(superbox_payload).digest()

        assertion_box = build_superbox_from_parts(jumd_bytes, [cbor_box])
        assertion_boxes.append(assertion_box)

        assertion_refs.append(
            {
                "url": f"self#jumbf=c2pa.assertions/{label}",
                "hash": ref_hash,
            }
        )

    assertion_store = build_superbox(
        C2PA_ASSERTION_STORE_UUID, "c2pa.assertions", assertion_boxes,
    )

    # Build claim v2 format
    claim = _build_claim_v2(claim_data, assertion_refs, manifest_label)

    claim_cbor = cbor2.dumps(claim)
    claim_box = build_superbox(
        C2PA_CLAIM_UUID, "c2pa.claim.v2", [build_cbor_box(claim_cbor)],
    )

    signature_bytes = sign_cose(claim_cbor, private_key, cert_chain, algorithm)
    signature_box = build_superbox(
        C2PA_SIGNATURE_UUID, "c2pa.signature", [build_cbor_box(signature_bytes)],
    )

    return build_superbox(
        C2PA_MANIFEST_UUID,
        manifest_label,
        [assertion_store, claim_box, signature_box],
    )


def _build_claim_v2(
    claim_data: dict[str, Any],
    assertion_refs: list[dict[str, Any]],
    manifest_label: str,
) -> dict[str, Any]:
    """Build a claim v2 dict with required fields."""
    claim: dict[str, Any] = {}

    # instanceID (required in v2)
    claim["instanceID"] = f"xmp:iid:{uuid.uuid4()}"

    # claim_generator_info (required in v2, single dict)
    generator = claim_data.get("claim_generator", f"{_GENERATOR_NAME}/{_GENERATOR_VERSION}")
    parts = generator.rsplit("/", 1)
    name = parts[0] if parts else generator
    version = parts[1] if len(parts) > 1 else "0.0.0"
    claim["claim_generator_info"] = {"name": name, "version": version}

    # signature URL
    claim["signature"] = (
        f"self#jumbf=/c2pa/{manifest_label}/c2pa.signature"
    )

    # assertion references (v2 uses created_assertions with relative URIs)
    claim["created_assertions"] = assertion_refs

    # hash algorithm at top level (v2)
    claim["alg"] = "sha256"

    # Copy additional fields from claim_data (dc:title, etc.)
    for key, value in claim_data.items():
        if key not in ("claim_generator", "assertions", "signature"):
            claim[key] = value

    return claim
