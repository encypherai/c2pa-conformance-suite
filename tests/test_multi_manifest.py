"""Tests for multi-manifest store building and ingredient resolution."""

from __future__ import annotations

import pytest

from c2pa_conformance.builder.manifest_builder import (
    ManifestSpec,
    build_multi_manifest_store,
)
from c2pa_conformance.crypto.cose import decode_cose_sign1, verify_signature
from c2pa_conformance.crypto.pki import generate_test_pki
from c2pa_conformance.parser.ingredient import (
    find_ingredient_assertions,
    resolve_ingredients,
)
from c2pa_conformance.parser.manifest import parse_manifest_store


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    output_dir = tmp_path_factory.mktemp("multi_manifest_pki")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="session")
def valid_key(pki: dict):
    return pki["valid_signer"].key


@pytest.fixture(scope="session")
def cert_chain(pki: dict) -> list:
    return [pki["valid_signer"].cert, pki["intermediate"].cert]


INGREDIENT_LABEL = "urn:uuid:ingredient-test-001"
ACTIVE_LABEL = "urn:uuid:active-test-001"


class TestMultiManifestStore:
    def test_two_manifests_parse(self, valid_key, cert_chain) -> None:
        """A store with two manifests parses both."""
        jumbf = build_multi_manifest_store([
            ManifestSpec(
                claim_data={"claim_generator": "original/1.0"},
                assertions=[],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=INGREDIENT_LABEL,
            ),
            ManifestSpec(
                claim_data={"claim_generator": "derived/1.0"},
                assertions=[],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=ACTIVE_LABEL,
            ),
        ])

        store = parse_manifest_store(jumbf)
        assert store.manifest_count == 2
        assert store.active_manifest is not None
        assert store.active_manifest.label == ACTIVE_LABEL

        labels = [m.label for m in store.manifests]
        assert INGREDIENT_LABEL in labels
        assert ACTIVE_LABEL in labels

    def test_signatures_valid(self, valid_key, cert_chain) -> None:
        """Both manifests have valid signatures."""
        jumbf = build_multi_manifest_store([
            ManifestSpec(
                claim_data={},
                assertions=[],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=INGREDIENT_LABEL,
            ),
            ManifestSpec(
                claim_data={},
                assertions=[],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=ACTIVE_LABEL,
            ),
        ])

        store = parse_manifest_store(jumbf)
        for manifest in store.manifests:
            cose = decode_cose_sign1(manifest.signature_bytes)
            assert verify_signature(cose, manifest.claim.raw_cbor) is True


class TestIngredientResolution:
    def _build_ingredient_store(self, valid_key, cert_chain) -> bytes:
        return build_multi_manifest_store([
            ManifestSpec(
                claim_data={
                    "claim_generator": "original/1.0",
                    "dc:title": "Original Image",
                },
                assertions=[
                    {
                        "label": "stds.schema-org.CreativeWork",
                        "data": {"@type": "CreativeWork"},
                    },
                ],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=INGREDIENT_LABEL,
            ),
            ManifestSpec(
                claim_data={"claim_generator": "editor/2.0"},
                assertions=[
                    {
                        "label": "c2pa.ingredient",
                        "data": {
                            "dc:title": "Original Image",
                            "relationship": "parentOf",
                            "c2pa_manifest": {
                                "url": f"self#jumbf=/c2pa/{INGREDIENT_LABEL}",
                            },
                        },
                    },
                ],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=ACTIVE_LABEL,
            ),
        ])

    def test_ingredient_assertion_found(
        self, valid_key, cert_chain,
    ) -> None:
        jumbf = self._build_ingredient_store(valid_key, cert_chain)
        store = parse_manifest_store(jumbf)
        active = store.active_manifest

        refs = find_ingredient_assertions(active)
        assert len(refs) == 1
        assert refs[0].manifest_label == INGREDIENT_LABEL
        assert refs[0].relationship == "parentOf"

    def test_ingredient_resolves(self, valid_key, cert_chain) -> None:
        jumbf = self._build_ingredient_store(valid_key, cert_chain)
        store = parse_manifest_store(jumbf)

        chain = resolve_ingredients(store, store.active_manifest)
        assert len(chain.ingredients) == 1
        assert chain.ingredients[0].manifest is not None
        assert chain.ingredients[0].manifest.label == INGREDIENT_LABEL
        assert INGREDIENT_LABEL in chain.all_manifests
        assert not chain.has_circular_ref

    def test_three_manifest_chain(self, valid_key, cert_chain) -> None:
        """A three-deep chain resolves correctly."""
        grandparent = "urn:uuid:grandparent"
        parent = "urn:uuid:parent"
        child = "urn:uuid:child"

        jumbf = build_multi_manifest_store([
            ManifestSpec(
                claim_data={"claim_generator": "camera/1.0"},
                assertions=[],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=grandparent,
            ),
            ManifestSpec(
                claim_data={"claim_generator": "editor/1.0"},
                assertions=[
                    {
                        "label": "c2pa.ingredient",
                        "data": {
                            "dc:title": "Camera Shot",
                            "relationship": "parentOf",
                            "c2pa_manifest": {
                                "url": f"self#jumbf=/c2pa/{grandparent}",
                            },
                        },
                    },
                ],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=parent,
            ),
            ManifestSpec(
                claim_data={"claim_generator": "publisher/1.0"},
                assertions=[
                    {
                        "label": "c2pa.ingredient",
                        "data": {
                            "dc:title": "Edited Image",
                            "relationship": "parentOf",
                            "c2pa_manifest": {
                                "url": f"self#jumbf=/c2pa/{parent}",
                            },
                        },
                    },
                ],
                private_key=valid_key,
                cert_chain=cert_chain,
                manifest_label=child,
            ),
        ])

        store = parse_manifest_store(jumbf)
        assert store.manifest_count == 3
        assert store.active_manifest.label == child

        chain = resolve_ingredients(store, store.active_manifest)
        assert not chain.has_circular_ref

        all_labels = chain.all_manifests
        assert grandparent in all_labels
        assert parent in all_labels
        assert child in all_labels
        assert len(all_labels) == 3
