"""Test vector definitions catalog."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class VectorDefinition:
    """Specification for a single test vector."""

    name: str
    category: str  # "valid", "structural", "crypto", "binding", "timestamp"
    container: str  # "jpeg", "png", "sidecar"
    algorithm: int  # COSE algorithm ID (-7 = ES256)
    claim_data: dict[str, Any] = field(default_factory=dict)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""
    expected_pass: bool = True
    # Mutation applied to raw JUMBF bytes BEFORE embedding
    pre_embed_mutation: Callable[[bytes], bytes] | None = None
    # Mutation applied to container bytes AFTER embedding
    post_embed_mutation: Callable[[bytes], bytes] | None = None
    # Use specific signer variant: "valid", "expired", "wrong_eku"
    signer_variant: str = "valid"
    # Use two-pass signing with content binding (c2pa.hash.data)
    content_bound: bool = False
    # Multi-manifest ingredient chain: list of ManifestSpec dicts
    # When set, the generator builds a multi-manifest store instead
    # of a single manifest. The last entry is the active manifest.
    ingredient_chain: list[dict[str, Any]] | None = None


# Default claim data
_BASE_CLAIM: dict[str, Any] = {
    "claim_generator": "c2pa-conformance-suite/test-vectors",
    "dc:title": "Test Vector",
}

# Default assertion (creative work)
_CREATIVE_WORK: dict[str, Any] = {
    "label": "stds.schema-org.CreativeWork",
    "data": {
        "@type": "CreativeWork",
        "author": [{"@type": "Person", "name": "Test"}],
    },
}


def get_all_definitions() -> list[VectorDefinition]:
    """Return all test vector definitions."""
    return (
        _valid_vectors()
        + _structural_vectors()
        + _crypto_vectors()
        + _binding_vectors()
        + _timestamp_vectors()
        + _ingredient_vectors()
    )


def _valid_vectors() -> list[VectorDefinition]:
    return [
        VectorDefinition(
            name="valid_jpeg_es256",
            category="valid",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Valid JPEG with ES256 signature and content binding",
            content_bound=True,
        ),
        VectorDefinition(
            name="valid_png_es256",
            category="valid",
            container="png",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Valid PNG with ES256 signature and content binding",
            content_bound=True,
        ),
        VectorDefinition(
            name="valid_sidecar",
            category="valid",
            container="sidecar",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Valid sidecar .c2pa manifest",
        ),
    ]


def _structural_vectors() -> list[VectorDefinition]:
    from c2pa_conformance.vectors.mutations import (
        corrupt_box_type,
        strip_claim_generator,
        truncate_jumbf,
    )

    return [
        VectorDefinition(
            name="truncated_jumbf",
            category="structural",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="JUMBF truncated to half size",
            expected_pass=False,
            pre_embed_mutation=truncate_jumbf,
        ),
        VectorDefinition(
            name="corrupt_box_type",
            category="structural",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Corrupted JUMBF box type bytes",
            expected_pass=False,
            pre_embed_mutation=corrupt_box_type,
        ),
        VectorDefinition(
            name="missing_claim_generator",
            category="structural",
            container="jpeg",
            algorithm=-7,
            claim_data={"dc:title": "No Generator"},
            assertions=[_CREATIVE_WORK],
            description="Missing claim_generator field",
            expected_pass=False,
            pre_embed_mutation=strip_claim_generator,
        ),
    ]


def _crypto_vectors() -> list[VectorDefinition]:
    from c2pa_conformance.vectors.mutations import tamper_signature

    return [
        VectorDefinition(
            name="expired_signer",
            category="crypto",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Signed with expired certificate",
            expected_pass=False,
            signer_variant="expired",
        ),
        VectorDefinition(
            name="wrong_eku_signer",
            category="crypto",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Signed with wrong EKU certificate",
            expected_pass=False,
            signer_variant="wrong_eku",
        ),
        VectorDefinition(
            name="tampered_signature",
            category="crypto",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Signature bytes tampered after signing",
            expected_pass=False,
            pre_embed_mutation=tamper_signature,
        ),
    ]


def _binding_vectors() -> list[VectorDefinition]:
    from c2pa_conformance.vectors.mutations import tamper_container_bytes

    return [
        VectorDefinition(
            name="tampered_content",
            category="binding",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Container bytes modified after signing (hash mismatch)",
            expected_pass=False,
            post_embed_mutation=tamper_container_bytes,
        ),
    ]


def _timestamp_vectors() -> list[VectorDefinition]:
    return [
        VectorDefinition(
            name="valid_no_timestamp",
            category="timestamp",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Valid signature with no timestamp token",
        ),
    ]


# Ingredient chain specs: each dict maps to a ManifestSpec
_INGREDIENT_LABEL = "urn:uuid:ingredient-original"
_ACTIVE_LABEL = "urn:uuid:ingredient-active"


def _ingredient_vectors() -> list[VectorDefinition]:
    return [
        VectorDefinition(
            name="ingredient_parentof",
            category="ingredient",
            container="jpeg",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Two-manifest store with parentOf ingredient",
            ingredient_chain=[
                {
                    "manifest_label": _INGREDIENT_LABEL,
                    "claim_data": {
                        "claim_generator": "original-tool/1.0",
                        "dc:title": "Original Image",
                    },
                    "assertions": [_CREATIVE_WORK],
                },
                {
                    "manifest_label": _ACTIVE_LABEL,
                    "claim_data": dict(_BASE_CLAIM),
                    "assertions": [
                        _CREATIVE_WORK,
                        {
                            "label": "c2pa.ingredient",
                            "data": {
                                "dc:title": "Original Image",
                                "relationship": "parentOf",
                                "c2pa_manifest": {
                                    "url": (f"self#jumbf=/c2pa/{_INGREDIENT_LABEL}"),
                                },
                            },
                        },
                    ],
                },
            ],
        ),
        VectorDefinition(
            name="ingredient_componentof",
            category="ingredient",
            container="sidecar",
            algorithm=-7,
            claim_data=dict(_BASE_CLAIM),
            assertions=[_CREATIVE_WORK],
            description="Two-manifest sidecar with componentOf ingredient",
            ingredient_chain=[
                {
                    "manifest_label": _INGREDIENT_LABEL,
                    "claim_data": {
                        "claim_generator": "component-tool/1.0",
                    },
                    "assertions": [_CREATIVE_WORK],
                },
                {
                    "manifest_label": _ACTIVE_LABEL,
                    "claim_data": dict(_BASE_CLAIM),
                    "assertions": [
                        _CREATIVE_WORK,
                        {
                            "label": "c2pa.ingredient",
                            "data": {
                                "dc:title": "Component",
                                "relationship": "componentOf",
                                "c2pa_manifest": {
                                    "url": (f"self#jumbf=/c2pa/{_INGREDIENT_LABEL}"),
                                },
                            },
                        },
                    ],
                },
            ],
        ),
    ]
