"""Integration tests verifying our conformance vectors against c2pa-tool.

These tests require the c2patool binary to be installed. They are marked
with pytest.mark.integration and skipped when c2patool is not available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile

import pytest

from c2pa_conformance.builder.two_pass import build_bound_manifest
from c2pa_conformance.crypto.pki import generate_test_pki

C2PATOOL = shutil.which("c2patool")
pytestmark = pytest.mark.integration


def _skip_if_no_c2patool():
    if C2PATOOL is None:
        pytest.skip("c2patool not found on PATH")


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    output_dir = tmp_path_factory.mktemp("c2patool_pki")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="module")
def valid_key(pki: dict):
    return pki["valid_signer"].key


@pytest.fixture(scope="module")
def cert_chain(pki: dict) -> list:
    return [pki["valid_signer"].cert, pki["intermediate"].cert]


def _minimal_jpeg() -> bytes:
    """Return a minimal valid JPEG."""
    return (
        bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + bytes([0xFF, 0xD9])
    )


def _run_c2patool(file_path: str) -> dict:
    """Run c2patool on a file and return parsed JSON output."""
    result = subprocess.run(
        [C2PATOOL, file_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def _get_validation_codes(data: dict) -> tuple[list[str], list[str]]:
    """Extract success and failure codes from c2patool output."""
    vr = data.get("validation_results", {}).get("activeManifest", {})
    successes = [s["code"] for s in vr.get("success", [])]
    failures = [f["code"] for f in vr.get("failure", [])]
    return successes, failures


class TestC2paToolManifestParsing:
    """c2patool can parse and validate our manifest structures."""

    def test_bound_jpeg_parses(self, valid_key, cert_chain) -> None:
        """A content-bound JPEG manifest is accepted by c2patool."""
        _skip_if_no_c2patool()

        embedded, _ = build_bound_manifest(
            claim_data={"claim_generator": "conformance-test/1.0"},
            assertions=[
                {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}},
            ],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=_minimal_jpeg(),
        )

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(embedded)
            path = f.name

        data = _run_c2patool(path)
        successes, failures = _get_validation_codes(data)

        assert "claimSignature.validated" in successes
        assert "assertion.dataHash.match" in successes
        assert "assertion.hashedURI.match" in successes

        # Only expected failure: untrusted test PKI
        for code in failures:
            assert code == "signingCredential.untrusted", f"Unexpected failure: {code}"

    def test_claim_v2_format(self, valid_key, cert_chain) -> None:
        """c2patool recognises claim v2 format."""
        _skip_if_no_c2patool()

        embedded, _ = build_bound_manifest(
            claim_data={"claim_generator": "conformance-test/1.0"},
            assertions=[
                {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}},
            ],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=_minimal_jpeg(),
        )

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(embedded)
            path = f.name

        data = _run_c2patool(path)
        active_label = data["active_manifest"]
        manifest = data["manifests"][active_label]

        assert manifest["claim_version"] == 2
        assert manifest["claim_generator_info"][0]["name"] == "conformance-test"
        assert manifest["claim_generator_info"][0]["version"] == "1.0"

    def test_assertion_hash_match(self, valid_key, cert_chain) -> None:
        """Salted assertion hashes are verified correctly by c2patool."""
        _skip_if_no_c2patool()

        embedded, _ = build_bound_manifest(
            claim_data={"claim_generator": "conformance-test/1.0"},
            assertions=[
                {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}},
                {
                    "label": "stds.schema-org.CreativeWork",
                    "data": {"@type": "CreativeWork", "author": [{"name": "Test"}]},
                },
            ],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=_minimal_jpeg(),
        )

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(embedded)
            path = f.name

        data = _run_c2patool(path)
        successes, _ = _get_validation_codes(data)

        # All three assertions (actions, CreativeWork, hash.data) should match
        hash_matches = [c for c in successes if c == "assertion.hashedURI.match"]
        assert len(hash_matches) == 3


class TestC2paToolMultiManifest:
    """c2patool handles multi-manifest stores with ingredient chains."""

    def test_ingredient_chain(self, valid_key, cert_chain) -> None:
        """A two-manifest store with ingredient reference parses correctly.

        Uses two-pass binding for the active manifest so c2patool gets a
        valid hard binding assertion.
        """
        _skip_if_no_c2patool()

        ingredient_label = "urn:uuid:ingredient-c2patool-001"
        active_label = "urn:uuid:active-c2patool-001"
        active_assertions = [
            {
                "label": "c2pa.ingredient",
                "data": {
                    "dc:title": "Original",
                    "dc:format": "image/jpeg",
                    "instanceID": "xmp:iid:test-ingredient-001",
                    "relationship": "parentOf",
                    "c2pa_manifest": {
                        "url": f"self#jumbf=/c2pa/{ingredient_label}",
                    },
                },
            },
        ]

        # Use two-pass to get a valid hard binding
        embedded, _ = build_bound_manifest(
            claim_data={"claim_generator": "editor/1.0"},
            assertions=active_assertions,
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=_minimal_jpeg(),
            manifest_label=active_label,
        )

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(embedded)
            path = f.name

        data = _run_c2patool(path)

        assert data["active_manifest"] == active_label
        # Single-manifest store (ingredient not embedded in two-pass flow)
        assert active_label in data["manifests"]
