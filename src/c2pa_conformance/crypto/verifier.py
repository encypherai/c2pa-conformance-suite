"""Full manifest verification: signature + chain + trust + content binding.

Orchestrates the crypto and hash verification modules into a single
verify_manifest() entry point used by the CLI pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from c2pa_conformance.binding.data_hash import verify_data_hash
from c2pa_conformance.crypto.cose import (
    CoseDecodeError,
    CoseSignature,
    CoseVerifyError,
    decode_cose_sign1,
    is_algorithm_allowed,
    verify_signature,
)
from c2pa_conformance.crypto.trust import TrustAnchorStore, evaluate_trust
from c2pa_conformance.crypto.x509_chain import (
    order_chain,
    parse_cert_chain,
    validate_chain,
)
from c2pa_conformance.parser.manifest import Manifest


@dataclass
class VerificationResult:
    """Complete verification result for a single manifest."""

    # Signature verification
    signature_valid: bool = False
    signature_status: str = ""
    signature_message: str = ""
    algorithm_name: str = ""
    algorithm_allowed: bool = True

    # Chain and trust
    chain_valid: bool = False
    chain_status: str = ""
    chain_message: str = ""
    trust_status: str = ""

    # Content binding
    hash_valid: bool | None = None  # None = not checked
    hash_status: str = ""
    hash_message: str = ""

    # COSE decoded data (for context enrichment)
    cose_signature: CoseSignature | None = None


def verify_manifest_signature(
    manifest: Manifest,
    trust_store: TrustAnchorStore | None = None,
    validation_time: datetime | None = None,
) -> VerificationResult:
    """Verify a manifest's COSE_Sign1 signature and certificate chain.

    Steps:
    1. Decode COSE_Sign1 from manifest.signature_bytes
    2. Check algorithm is allowed
    3. Verify signature using claim CBOR as external AAD
    4. Parse and validate X.509 chain from x5chain
    5. Evaluate trust against trust store (if provided)
    """
    result = VerificationResult()

    if not manifest.signature_bytes:
        result.signature_status = "claimSignature.missing"
        result.signature_message = "No signature bytes in manifest"
        return result

    # Step 1: Decode COSE_Sign1
    try:
        cose_sig = decode_cose_sign1(manifest.signature_bytes)
        result.cose_signature = cose_sig
        result.algorithm_name = cose_sig.algorithm_name
    except CoseDecodeError as exc:
        result.signature_status = "claimSignature.missing"
        result.signature_message = str(exc)
        return result

    # Step 2: Check algorithm
    result.algorithm_allowed = is_algorithm_allowed(cose_sig.algorithm_id)
    if not result.algorithm_allowed:
        result.signature_status = "algorithm.unsupported"
        result.signature_message = f"Algorithm {cose_sig.algorithm_name} not in allowed list"
        return result

    # Step 3: Verify signature
    claim_cbor = manifest.claim.raw_cbor if manifest.claim else b""
    try:
        verify_signature(cose_sig, claim_cbor)
        result.signature_valid = True
        result.signature_status = "claimSignature.validated"
        result.signature_message = "Signature verified"
    except CoseVerifyError as exc:
        result.signature_status = "claimSignature.mismatch"
        result.signature_message = str(exc)
        return result

    # Step 4: Parse and validate chain
    if cose_sig.x5chain:
        try:
            certs = parse_cert_chain(cose_sig.x5chain)
            ordered = order_chain(certs)

            # Step 5: Evaluate trust
            if trust_store:
                trust_result = evaluate_trust(ordered, trust_store, validation_time)
                result.chain_valid = trust_result.is_valid
                result.chain_status = trust_result.status_code
                result.chain_message = trust_result.message
                result.trust_status = trust_result.status_code
            else:
                # No trust store -- just validate chain structure
                chain_result = validate_chain(ordered, validation_time)
                result.chain_valid = chain_result.is_valid
                result.chain_status = chain_result.status_code
                result.chain_message = chain_result.message
                result.trust_status = "signingCredential.untrusted"
        except Exception as exc:
            result.chain_status = "signingCredential.invalid"
            result.chain_message = str(exc)

    return result


def verify_manifest_binding(
    manifest: Manifest,
    asset_bytes: bytes,
) -> VerificationResult:
    """Verify the content binding (hash) for a manifest.

    Finds the hard binding assertion and verifies it against the asset bytes.
    Currently supports c2pa.hash.data only.
    """
    result = VerificationResult()

    hb = manifest.hard_binding
    if not hb:
        result.hash_status = "claim.hardBindings.missing"
        result.hash_message = "No hard binding assertion found"
        return result

    if hb.is_hash_data:
        hash_result = verify_data_hash(asset_bytes, hb.data)
        result.hash_valid = hash_result.is_valid
        result.hash_status = hash_result.status_code
        result.hash_message = hash_result.message
    else:
        # Other binding types not yet implemented
        result.hash_status = "assertion.binding.notImplemented"
        result.hash_message = f"Binding type {hb.label} verification not yet implemented"

    return result


def build_crypto_context(
    sig_result: VerificationResult,
    hash_result: VerificationResult | None = None,
) -> dict[str, Any]:
    """Build context dict entries for crypto/hash verification results.

    These are merged into the evaluation context so predicates can
    reference crypto validation state.
    """
    ctx: dict[str, Any] = {
        "signature": {
            "is_valid": sig_result.signature_valid,
            "status_code": sig_result.signature_status,
            "message": sig_result.signature_message,
            "algorithm": sig_result.algorithm_name,
            "algorithm_allowed": sig_result.algorithm_allowed,
        },
        "certificate": {
            "chain_valid": sig_result.chain_valid,
            "status_code": sig_result.chain_status,
            "message": sig_result.chain_message,
        },
        "trust": {
            "status_code": sig_result.trust_status,
            "is_trusted": sig_result.trust_status == "signingCredential.trusted",
        },
    }

    if hash_result and hash_result.hash_valid is not None:
        ctx["hash"] = {
            "is_valid": hash_result.hash_valid,
            "status_code": hash_result.hash_status,
            "message": hash_result.hash_message,
        }

    return ctx
