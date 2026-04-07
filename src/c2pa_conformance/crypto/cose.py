"""COSE_Sign1 decoder and signature verifier for C2PA manifests.

Implements RFC 9052 COSE_Sign1 decoding and verification as required by
the C2PA specification. Does not use pycose; all CBOR decoding is done
manually via cbor2 and all crypto via the cryptography library.

C2PA-specific notes:
- The payload field is nil (detached payload pattern).
- The data signed is the claim CBOR bytes, passed as external_aad.
- Sig_structure: ["Signature1", protected, external_aad, b""]
- ECDSA signatures are raw r||s (COSE encoding), not DER.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CoseDecodeError(Exception):
    """Raised when a COSE_Sign1 structure cannot be decoded."""


class CoseVerifyError(Exception):
    """Raised when signature verification fails."""


# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------

# COSE algorithm IDs per RFC 9052 / IANA COSE Algorithms registry.
_ES256 = -7
_ES384 = -35
_ES512 = -36
_PS256 = -37
_PS384 = -38
_PS512 = -39
_ED25519 = -8


@dataclass
class CoseAlgorithm:
    """Descriptor for a COSE signing algorithm."""

    cose_id: int
    name: str
    # hash_alg is None for EdDSA (hash is implicit in the algorithm).
    hash_alg: hashes.HashAlgorithm | None
    is_deprecated: bool = False


# All algorithms defined in the C2PA v2.4 allowed list.
_ALGORITHM_REGISTRY: dict[int, CoseAlgorithm] = {
    _ES256: CoseAlgorithm(_ES256, "ES256", hashes.SHA256()),
    _ES384: CoseAlgorithm(_ES384, "ES384", hashes.SHA384()),
    _ES512: CoseAlgorithm(_ES512, "ES512", hashes.SHA512()),
    _PS256: CoseAlgorithm(_PS256, "PS256", hashes.SHA256()),
    _PS384: CoseAlgorithm(_PS384, "PS384", hashes.SHA384()),
    _PS512: CoseAlgorithm(_PS512, "PS512", hashes.SHA512()),
    _ED25519: CoseAlgorithm(_ED25519, "Ed25519", None),
}

# C2PA v2.4 allowed algorithm IDs.
_C2PA_ALLOWED_ALGORITHM_IDS: frozenset[int] = frozenset(_ALGORITHM_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Dataclass for a decoded COSE_Sign1
# ---------------------------------------------------------------------------


@dataclass
class CoseSignature:
    """Decoded COSE_Sign1 structure from a C2PA manifest."""

    protected_header: dict[Any, Any]
    unprotected_header: dict[Any, Any]
    algorithm_id: int
    algorithm_name: str
    signature_bytes: bytes
    # DER-encoded X.509 certificates from the x5chain header (key 33).
    x5chain: list[bytes] = field(default_factory=list)
    # Raw sigTst bytes if present (key "sigTst" or integer label).
    sig_tst: bytes | None = None
    # Raw sigTst2 bytes if present.
    sig_tst2: bytes | None = None
    # Raw rVals value if present.
    r_vals: Any | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_algorithm(cose_id: int) -> CoseAlgorithm:
    """Return the CoseAlgorithm for the given COSE algorithm ID.

    Raises CoseDecodeError if the ID is not recognised.
    """
    alg = _ALGORITHM_REGISTRY.get(cose_id)
    if alg is None:
        raise CoseDecodeError(f"Unsupported COSE algorithm ID: {cose_id}")
    return alg


def is_algorithm_allowed(cose_id: int) -> bool:
    """Return True if the algorithm is in the C2PA v2.4 allowed list."""
    return cose_id in _C2PA_ALLOWED_ALGORITHM_IDS


def is_algorithm_deprecated(cose_id: int) -> bool:
    """Return True if the algorithm is marked deprecated in C2PA v2.4."""
    alg = _ALGORITHM_REGISTRY.get(cose_id)
    if alg is None:
        return False
    return alg.is_deprecated


def decode_cose_sign1(raw_bytes: bytes) -> CoseSignature:
    """Decode a COSE_Sign1 structure from raw CBOR bytes.

    Handles both tagged (CBOR tag 18) and untagged forms. The payload
    field must be nil (C2PA detached payload requirement).

    Raises CoseDecodeError on any structural or semantic error.
    """
    try:
        decoded = cbor2.loads(raw_bytes)
    except Exception as exc:
        raise CoseDecodeError(f"CBOR decode failed: {exc}") from exc

    # Strip CBOR tag 18 (COSE_Sign1) if present.
    if isinstance(decoded, cbor2.CBORTag):
        if decoded.tag != 18:
            raise CoseDecodeError(f"Unexpected CBOR tag {decoded.tag}; expected 18")
        decoded = decoded.value

    if not isinstance(decoded, list) or len(decoded) != 4:
        raise CoseDecodeError(
            f"COSE_Sign1 must be a 4-element array; got {type(decoded).__name__}"
            + (f" with {len(decoded)} elements" if isinstance(decoded, list) else "")
        )

    protected_bytes, unprotected, payload, signature = decoded

    if not isinstance(protected_bytes, bytes):
        raise CoseDecodeError(
            f"Protected header must be a bstr; got {type(protected_bytes).__name__}"
        )
    if not isinstance(unprotected, dict):
        raise CoseDecodeError(
            f"Unprotected header must be a map; got {type(unprotected).__name__}"
        )
    if payload is not None:
        raise CoseDecodeError("C2PA requires detached payload (nil); got non-nil payload")
    if not isinstance(signature, bytes):
        raise CoseDecodeError(f"Signature must be a bstr; got {type(signature).__name__}")

    # Decode the protected header CBOR.
    try:
        protected_header: dict[Any, Any] = cbor2.loads(protected_bytes) if protected_bytes else {}
    except Exception as exc:
        raise CoseDecodeError(f"Protected header CBOR decode failed: {exc}") from exc

    if not isinstance(protected_header, dict):
        raise CoseDecodeError("Protected header must decode to a map")

    # Algorithm (key 1 in protected header).
    alg_id = protected_header.get(1)
    if alg_id is None:
        raise CoseDecodeError("Protected header missing required 'alg' parameter (key 1)")
    if not isinstance(alg_id, int):
        raise CoseDecodeError(f"Algorithm ID must be an integer; got {type(alg_id).__name__}")

    alg = get_algorithm(alg_id)  # raises CoseDecodeError for unknown IDs

    # x5chain: check protected header first (C2PA v2), fall back to unprotected.
    # Accepts both text label "x5chain" and integer label 33 per COSE/C2PA spec.
    x5chain_raw = (
        protected_header.get("x5chain")
        or protected_header.get(33)
        or unprotected.get("x5chain")
        or unprotected.get(33)
        or []
    )
    if isinstance(x5chain_raw, bytes):
        x5chain: list[bytes] = [x5chain_raw]
    elif isinstance(x5chain_raw, list):
        x5chain = [b for b in x5chain_raw if isinstance(b, bytes)]
    else:
        x5chain = []

    # Timestamp and revocation fields -- store raw for now.
    sig_tst: bytes | None = None
    sig_tst2: bytes | None = None
    r_vals: Any | None = None

    raw_sig_tst = unprotected.get("sigTst") or protected_header.get("sigTst")
    if raw_sig_tst is not None:
        sig_tst = raw_sig_tst if isinstance(raw_sig_tst, bytes) else cbor2.dumps(raw_sig_tst)

    raw_sig_tst2 = unprotected.get("sigTst2") or protected_header.get("sigTst2")
    if raw_sig_tst2 is not None:
        sig_tst2 = raw_sig_tst2 if isinstance(raw_sig_tst2, bytes) else cbor2.dumps(raw_sig_tst2)

    r_vals = unprotected.get("rVals") or protected_header.get("rVals")

    return CoseSignature(
        protected_header=protected_header,
        unprotected_header=dict(unprotected),
        algorithm_id=alg_id,
        algorithm_name=alg.name,
        signature_bytes=signature,
        x5chain=x5chain,
        sig_tst=sig_tst,
        sig_tst2=sig_tst2,
        r_vals=r_vals,
    )


def verify_signature(cose_sig: CoseSignature, external_aad: bytes) -> bool:
    """Verify the COSE_Sign1 signature against external_aad (the claim bytes).

    Uses x5chain[0] as the signer certificate. Returns True on success,
    raises CoseVerifyError on failure.

    The Sig_structure is: ["Signature1", protected_bytes, external_aad, b""]
    per RFC 9052 section 4.4 (payload is b"" because the payload was nil).
    """
    if not cose_sig.x5chain:
        raise CoseVerifyError("No certificates in x5chain; cannot verify signature")

    # Load the signer certificate from DER bytes.
    try:
        cert = x509.load_der_x509_certificate(cose_sig.x5chain[0])
    except Exception as exc:
        raise CoseVerifyError(f"Failed to parse signer certificate: {exc}") from exc

    public_key = cert.public_key()

    # Rebuild the protected header bytes for the Sig_structure.
    # We need the original bstr -- re-encode from the decoded map.
    protected_bytes = cbor2.dumps(cose_sig.protected_header)

    # Build Sig_structure per RFC 9052 section 4.4.
    # C2PA uses detached payload: external_aad is empty, claim bytes are the payload.
    sig_structure_bytes: bytes = cbor2.dumps(["Signature1", protected_bytes, b"", external_aad])

    alg_id = cose_sig.algorithm_id
    raw_signature = cose_sig.signature_bytes

    try:
        if alg_id in (_ES256, _ES384, _ES512):
            _verify_ecdsa(public_key, raw_signature, sig_structure_bytes, alg_id)
        elif alg_id in (_PS256, _PS384, _PS512):
            _verify_rsa_pss(public_key, raw_signature, sig_structure_bytes, alg_id)
        elif alg_id == _ED25519:
            _verify_ed25519(public_key, raw_signature, sig_structure_bytes)
        else:
            raise CoseVerifyError(f"Unsupported algorithm ID for verification: {alg_id}")
    except CoseVerifyError:
        raise
    except Exception as exc:
        raise CoseVerifyError(f"Signature verification error: {exc}") from exc

    return True


# ---------------------------------------------------------------------------
# Internal verification helpers
# ---------------------------------------------------------------------------


def _verify_ecdsa(
    public_key: Any,
    raw_sig: bytes,
    data: bytes,
    alg_id: int,
) -> None:
    """Verify an ECDSA signature in COSE raw r||s format."""
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise CoseVerifyError(f"Expected EC public key for ECDSA; got {type(public_key).__name__}")

    if len(raw_sig) % 2 != 0:
        raise CoseVerifyError(f"ECDSA raw signature length {len(raw_sig)} is not even")

    key_size = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:key_size], "big")
    s = int.from_bytes(raw_sig[key_size:], "big")
    der_sig = encode_dss_signature(r, s)

    hash_alg = _ALGORITHM_REGISTRY[alg_id].hash_alg
    assert hash_alg is not None  # always set for ECDSA

    try:
        public_key.verify(der_sig, data, ec.ECDSA(hash_alg))
    except Exception as exc:
        raise CoseVerifyError(f"ECDSA verification failed: {exc}") from exc


def _verify_rsa_pss(
    public_key: Any,
    signature: bytes,
    data: bytes,
    alg_id: int,
) -> None:
    """Verify an RSA-PSS signature."""
    if not isinstance(public_key, RSAPublicKey):
        raise CoseVerifyError(f"Expected RSA public key for PSS; got {type(public_key).__name__}")

    hash_alg = _ALGORITHM_REGISTRY[alg_id].hash_alg
    assert hash_alg is not None

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hash_alg,
        )
    except Exception as exc:
        raise CoseVerifyError(f"RSA-PSS verification failed: {exc}") from exc


def _verify_ed25519(
    public_key: Any,
    signature: bytes,
    data: bytes,
) -> None:
    """Verify an Ed25519 signature."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise CoseVerifyError(f"Expected Ed25519 public key; got {type(public_key).__name__}")

    try:
        public_key.verify(signature, data)
    except Exception as exc:
        raise CoseVerifyError(f"Ed25519 verification failed: {exc}") from exc
