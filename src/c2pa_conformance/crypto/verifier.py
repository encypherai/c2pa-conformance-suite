"""Full manifest verification: signature + chain + trust + content binding.

Orchestrates the crypto and hash verification modules into a single
verify_manifest() entry point used by the CLI pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography import x509

from c2pa_conformance.binding.data_hash import verify_data_hash
from c2pa_conformance.crypto.cose import (
    CoseDecodeError,
    CoseSignature,
    CoseVerifyError,
    decode_cose_sign1,
    is_algorithm_allowed,
    verify_signature,
)
from c2pa_conformance.crypto.timestamp import validate_timestamp
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

            # PRED-CRYP-017 / VAL-CRYP-0028: when a trusted timestamp proves
            # signing during cert validity, use genTime as the reference time.
            effective_time = _resolve_validation_time(
                cose_sig, ordered, validation_time
            )

            # Step 5: Evaluate trust
            if trust_store:
                trust_result = evaluate_trust(ordered, trust_store, effective_time)
                result.chain_valid = trust_result.is_valid
                result.chain_status = trust_result.status_code
                result.chain_message = trust_result.message
                result.trust_status = trust_result.status_code
            else:
                # No trust store -- just validate chain structure
                chain_result = validate_chain(ordered, effective_time)
                result.chain_valid = chain_result.is_valid
                result.chain_status = chain_result.status_code
                result.chain_message = chain_result.message
                result.trust_status = "signingCredential.untrusted"
        except Exception as exc:
            result.chain_status = "signingCredential.invalid"
            result.chain_message = str(exc)

    return result


def _resolve_validation_time(
    cose_sig: CoseSignature,
    chain: list[x509.Certificate],
    explicit_time: datetime | None,
) -> datetime | None:
    """Determine effective validation time per PRED-CRYP-017 (VAL-CRYP-0028).

    C2PA spec: when a valid timestamp proves signing occurred during the
    certificate's validity window, the validator must use the TSA-attested
    genTime rather than the current wall-clock time for all certificate
    validity checks. This enables short-lived certificates (e.g., Google's
    30-day Pixel Camera certs) to validate after expiry.

    Returns:
        explicit_time if caller set it, timestamp genTime when applicable,
        or None (signals validate_chain to use current time).
    """
    if explicit_time is not None:
        return explicit_time

    tst_data = cose_sig.sig_tst or cose_sig.sig_tst2
    if tst_data is None or not chain:
        return None

    tst_result = validate_timestamp(tst_data, cose_sig.signature_bytes)
    if not tst_result.is_valid or tst_result.gen_time is None:
        return None

    gen_time = tst_result.gen_time
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    # Check genTime within leaf certificate validity window
    leaf = chain[0]
    if leaf.not_valid_before_utc <= gen_time <= leaf.not_valid_after_utc:
        return gen_time

    return None


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
    reference crypto validation state. Wires COSE signature data,
    certificate info, timestamp validation, and OCSP data into paths
    that predicate operators expect.
    """
    is_trusted = sig_result.trust_status == "signingCredential.trusted"

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
            "is_trusted": is_trusted,
        },
        # Aliases expected by predicate operators
        "claim_signature": {"valid": sig_result.signature_valid},
        "signature_verified": sig_result.signature_valid,
        "cert_chain": {"valid": sig_result.chain_valid},
        "signing_credential": {"trusted": is_trusted},
    }

    # Pre-populate emitted statuses for check_status operators in sequences
    emitted: set[str] = set()
    if sig_result.signature_valid:
        emitted.add("claimSignature.validated")
    if sig_result.signature_status:
        emitted.add(sig_result.signature_status)
    if sig_result.chain_valid:
        emitted.add("signingCredential.validated")
    if sig_result.chain_status:
        emitted.add(sig_result.chain_status)
    if sig_result.trust_status:
        emitted.add(sig_result.trust_status)
    if sig_result.algorithm_allowed:
        emitted.add("algorithm.supported")
    ctx["_emitted_statuses"] = emitted

    # Wire COSE signature fields for predicates that reference them
    cose = sig_result.cose_signature
    if cose:
        protected = _cose_header_to_named(cose.protected_header, cose.algorithm_name)
        unprotected = _cose_header_to_named(cose.unprotected_header, "")

        cose_ctx: dict[str, Any] = {
            "protected_header": protected,
            "unprotected_header": unprotected,
            "algorithm_id": cose.algorithm_id,
            "algorithm_name": cose.algorithm_name,
        }

        # x5chain
        if cose.x5chain:
            cose_ctx["unprotected_header"]["x5chain"] = cose.x5chain
            ctx["x5chain"] = cose.x5chain
            ctx["certificates"] = {"signer": True}

            # Parse leaf certificate for signing_certificate context
            cert_info = _parse_cert_summary(cose.x5chain[0])
            if cert_info:
                ctx["signing_certificate"] = cert_info
                # Build validity_periods list for the full chain
                chain_periods = []
                for der in cose.x5chain:
                    ci = _parse_cert_summary(der)
                    if ci and "validity_period" in ci:
                        chain_periods.append(ci["validity_period"])
                if chain_periods:
                    ctx["signing_certificate_chain"] = {
                        "validity_periods": chain_periods,
                    }

        # Timestamp tokens
        tst_tokens: list[Any] = []
        if cose.sig_tst is not None:
            cose_ctx["unprotected_header"]["sigTst"] = cose.sig_tst
            tst_tokens.append(cose.sig_tst)
        if cose.sig_tst2 is not None:
            cose_ctx["unprotected_header"]["sigTst2"] = cose.sig_tst2
            tst_tokens.append(cose.sig_tst2)
        if tst_tokens:
            cose_ctx["unprotected_header"]["tstToken"] = tst_tokens

        # r_vals (OCSP/CRL revocation data)
        if cose.r_vals is not None:
            cose_ctx["unprotected_header"]["rVals"] = cose.r_vals
            if isinstance(cose.r_vals, dict):
                ocsp = cose.r_vals.get("ocspVals", cose.r_vals.get("ocsp", []))
                if isinstance(ocsp, list) and ocsp:
                    ctx["ocsp_responses"] = ocsp

        ctx["cose_signature"] = cose_ctx

        # Validate timestamps and wire results
        _wire_timestamp_context(ctx, cose)

    if hash_result and hash_result.hash_valid is not None:
        ctx["hash"] = {
            "is_valid": hash_result.hash_valid,
            "match": hash_result.hash_valid,
            "status_code": hash_result.hash_status,
            "message": hash_result.hash_message,
        }
        ctx["binding_verified"] = hash_result.hash_valid
        if hash_result.hash_status:
            emitted.add(hash_result.hash_status)

    return ctx


def _cose_header_to_named(
    raw_header: dict[Any, Any],
    algorithm_name: str,
) -> dict[str, Any]:
    """Map COSE integer header keys to string names for predicate access."""
    named: dict[str, Any] = {}
    if not raw_header:
        return named

    # Known COSE header label mappings
    label_map: dict[int, str] = {
        1: "alg",
        4: "kid",
        6: "iat",
        33: "x5chain",
    }

    for k, v in raw_header.items():
        if isinstance(k, int) and k in label_map:
            named[label_map[k]] = v
        elif isinstance(k, str):
            named[k] = v

    # Always use string name for alg, not the raw integer COSE ID
    if algorithm_name:
        named["alg"] = algorithm_name

    return named


def _parse_cert_summary(der_cert: bytes) -> dict[str, Any] | None:
    """Parse basic certificate info from DER-encoded X.509."""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der_cert)
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before,
            "not_after": not_after,
            "validity_period": {
                "not_before": not_before,
                "not_after": not_after,
            },
            "public_key": True,
        }
    except (ValueError, TypeError, AttributeError):
        return None


def _wire_timestamp_context(
    ctx: dict[str, Any],
    cose: CoseSignature,
) -> None:
    """Validate timestamp tokens and wire results into context."""
    from c2pa_conformance.crypto.timestamp import parse_tst_header, validate_timestamp

    tst_data = cose.sig_tst or cose.sig_tst2
    if tst_data is None:
        return

    tst_result = validate_timestamp(tst_data, cose.signature_bytes)

    ctx["timestamp"] = {
        "valid": tst_result.is_valid,
        "status_code": tst_result.status_code,
        "message": tst_result.message,
    }
    ctx["timestamp_validated"] = tst_result.is_valid

    if tst_result.gen_time:
        gen_iso = tst_result.gen_time.isoformat()
        ctx["timeStampToken"] = {"tspInfo": {"genTime": gen_iso}}
        ctx["tst"] = {"signing_time": gen_iso}

        # Extract TSA certificate from timestamp token CMS structure
        tokens = parse_tst_header(tst_data)
        tsa_info = _extract_tsa_cert_info(tokens[0] if tokens else b"")
        if tsa_info:
            ctx["tsa_certificate"] = tsa_info

        # Check timestamp against signer cert validity if available
        signing_cert = ctx.get("signing_certificate", {})
        if signing_cert.get("not_before") and signing_cert.get("not_after"):
            from c2pa_conformance.crypto.timestamp import check_timestamp_validity

            validity_result = check_timestamp_validity(
                tst_result,
                cert_not_before=datetime.fromisoformat(signing_cert["not_before"]),
                cert_not_after=datetime.fromisoformat(signing_cert["not_after"]),
            )
            if validity_result.is_valid:
                ctx["_emitted_statuses"].add("timeStamp.trusted")
                ctx["_emitted_statuses"].add("timeStamp.validated")


def _extract_tsa_cert_info(token_bytes: bytes) -> dict[str, Any] | None:
    """Extract TSA certificate info from an RFC 3161 timestamp token."""
    if not token_bytes:
        return None
    try:
        import warnings

        from cryptography.hazmat.primitives.serialization.pkcs7 import (
            load_der_pkcs7_certificates,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", (DeprecationWarning, UserWarning))
            certs = load_der_pkcs7_certificates(token_bytes)
        if not certs:
            return None
        # First cert is the TSA signing certificate
        tsa = certs[0]
        not_before = tsa.not_valid_before_utc.isoformat()
        not_after = tsa.not_valid_after_utc.isoformat()
        return {
            "subject": tsa.subject.rfc4514_string(),
            "issuer": tsa.issuer.rfc4514_string(),
            "not_before": not_before,
            "not_after": not_after,
            "validity_period": {
                "not_before": not_before,
                "not_after": not_after,
            },
        }
    except (ValueError, TypeError, AttributeError):
        return None
