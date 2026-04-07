"""crJSON serializer for C2PA conformance validation results.

Serializes a parsed ManifestStore and ConformanceReport into the crJSON
format consumed by the rubric evaluator. crJSON is a JSON-LD representation
of a C2PA manifest store with validation results, keyed on assertion labels
and structured for jmespath expression evaluation.

Spec reference: C2PA Conformance Program crJSON specification.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any

# crJSON schema context URI
_CRJSON_CONTEXT = {"@vocab": "https://c2pa.org/crjson/"}

# Generator metadata embedded in every crJSON output
_GENERATOR_NAME = "c2pa-conformance-suite"
_GENERATOR_VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Status code classification
# ---------------------------------------------------------------------------

# Suffix patterns that indicate a success outcome
_SUCCESS_SUFFIXES: tuple[str, ...] = (
    ".match",
    ".validated",
    ".trusted",
    ".insideValidity",
    ".notRevoked",
)

# Exact codes that indicate success but do not end with a shared suffix
_SUCCESS_EXACT: frozenset[str] = frozenset({"algorithm.supported"})

# Patterns that indicate an informational (non-failure, non-success) outcome
_INFORMATIONAL_PATTERNS: tuple[str, ...] = (
    ".additionalExclusionsPresent",
    "signingCredential.ocsp.inaccessible",
    "signingCredential.ocsp.skipped",
    "signingCredential.ocsp.unknown",
    "algorithm.deprecated",
    "timeOfSigning.outsideValidity",
    "timeStamp.credentialInvalid",
    "timeStamp.malformed",
    "timeStamp.mismatch",
    "timeStamp.outsideValidity",
    "timeStamp.untrusted",
)


def classify_status_code(code: str) -> str:
    """Classify a C2PA status code as 'success', 'informational', or 'failure'.

    Success codes end with patterns like .match, .validated, .trusted,
    .insideValidity, .notRevoked, or are exact matches like algorithm.supported.

    Informational codes match known advisory patterns.

    Everything else is classified as 'failure'.
    """
    if not code:
        return "failure"

    if code in _SUCCESS_EXACT:
        return "success"

    for suffix in _SUCCESS_SUFFIXES:
        if code.endswith(suffix):
            return "success"

    for pattern in _INFORMATIONAL_PATTERNS:
        if pattern in code or code == pattern:
            return "informational"

    return "failure"


# ---------------------------------------------------------------------------
# RFC 4514 DN parsing
# ---------------------------------------------------------------------------

_RDN_ATTRS = ("CN", "O", "OU", "C", "L", "ST", "STREET", "DC", "UID")


def _parse_rdn_string(rdn_string: str) -> dict[str, str]:
    """Parse an RFC 4514 DN string into a component dict.

    Handles the most common RDN attributes: CN, O, OU, C, L, ST.
    RFC 4514 presents the most-significant RDN first; the cryptography
    library's rfc4514_string() presents them in reverse order
    (least-significant first). Either order is handled correctly here
    because this function parses by key=value pairs, not by position.

    Example input:  'CN=Pixel Camera,O=Google LLC,C=US'
    Example output: {'CN': 'Pixel Camera', 'O': 'Google LLC', 'C': 'US'}
    """
    result: dict[str, str] = {}
    if not rdn_string:
        return result

    # Split on commas that are NOT preceded by a backslash escape.
    # RFC 4514 escapes embedded commas as \, so we split only on bare commas.
    parts = re.split(r"(?<!\\),", rdn_string)
    for part in parts:
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().upper()
        # Unescape RFC 4514 escaped characters (\XX hex or \<special>)
        value = re.sub(r"\\([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value.strip())
        value = re.sub(r"\\(.)", r"\1", value)
        if key in _RDN_ATTRS:
            result[key] = value

    return result


# ---------------------------------------------------------------------------
# Certificate info extraction
# ---------------------------------------------------------------------------


def _parse_cert_info_from_der(der_bytes: bytes) -> dict[str, Any] | None:
    """Parse a DER-encoded X.509 certificate into crJSON certificateInfo format.

    Returns a dict with serialNumber, issuer, subject, and validity, or None
    if the certificate cannot be parsed.
    """
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der_bytes)

        serial_hex = format(cert.serial_number, "x")
        # Prefix with leading zero if odd length (canonical hex form)
        if len(serial_hex) % 2:
            serial_hex = "0" + serial_hex

        issuer_dn = cert.issuer.rfc4514_string()
        subject_dn = cert.subject.rfc4514_string()

        return {
            "serialNumber": serial_hex,
            "issuer": _parse_rdn_string(issuer_dn),
            "subject": _parse_rdn_string(subject_dn),
            "validity": {
                "notBefore": cert.not_valid_before_utc.isoformat(),
                "notAfter": cert.not_valid_after_utc.isoformat(),
            },
        }
    except Exception:
        return None


def _parse_tsa_cert_info_from_token(token_bytes: bytes) -> dict[str, Any] | None:
    """Extract the TSA signing certificate from an RFC 3161 timestamp token CMS structure."""
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

        tsa = certs[0]
        serial_hex = format(tsa.serial_number, "x")
        if len(serial_hex) % 2:
            serial_hex = "0" + serial_hex

        issuer_dn = tsa.issuer.rfc4514_string()
        subject_dn = tsa.subject.rfc4514_string()

        return {
            "serialNumber": serial_hex,
            "issuer": _parse_rdn_string(issuer_dn),
            "subject": _parse_rdn_string(subject_dn),
            "validity": {
                "notBefore": tsa.not_valid_before_utc.isoformat(),
                "notAfter": tsa.not_valid_after_utc.isoformat(),
            },
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Assertion serialization
# ---------------------------------------------------------------------------


def _build_assertions_map(assertions: list[Any]) -> dict[str, Any]:
    """Convert a list of Assertion objects into a crJSON keyed assertions map.

    Multiple assertions sharing the same label are disambiguated by appending
    a __N suffix starting at __1 for the second occurrence.

    The assertion data is emitted as-is (the CBOR-decoded dict). Binary
    values (bytes) are base64-encoded with a 'b64\\'' prefix per crJSON
    convention.
    """
    counts: dict[str, int] = {}
    result: dict[str, Any] = {}

    for assertion in assertions:
        label: str = assertion.label
        n = counts.get(label, 0)
        counts[label] = n + 1

        key = label if n == 0 else f"{label}__{n}"
        result[key] = _encode_assertion_data(assertion.data)

    return result


def _encode_assertion_data(data: Any) -> Any:
    """Recursively encode assertion data, converting bytes to b64' strings."""
    if isinstance(data, bytes):
        return "b64'" + base64.b64encode(data).decode("ascii") + "'"
    if isinstance(data, dict):
        return {k: _encode_assertion_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_encode_assertion_data(item) for item in data]
    return data


# ---------------------------------------------------------------------------
# Claim serialization
# ---------------------------------------------------------------------------


def _build_claim_v2(claim: Any) -> dict[str, Any]:
    """Serialize a Claim object to crJSON claim.v2 structure."""
    raw: dict[str, Any] = claim.data or {}

    # claim_generator_info: normalize to a single dict (crJSON uses the first entry)
    cgi = claim.claim_generator_info
    cgi_out: dict[str, Any] = {}
    if isinstance(cgi, list) and cgi:
        cgi_out = cgi[0] if isinstance(cgi[0], dict) else {}
    elif isinstance(cgi, dict):
        cgi_out = cgi

    created: list[Any] = raw.get("created_assertions") or []
    gathered: list[Any] = raw.get("gathered_assertions") or []
    redacted: list[Any] = raw.get("redacted_assertions") or []

    return _encode_assertion_data(
        {
            "instanceID": raw.get("instanceID", raw.get("instance_id", "")),
            "signature": claim.signature_ref,
            "claim_generator_info": cgi_out,
            "alg": raw.get("alg", ""),
            "created_assertions": created if isinstance(created, list) else [],
            "gathered_assertions": gathered if isinstance(gathered, list) else [],
            "redacted_assertions": redacted if isinstance(redacted, list) else [],
        }
    )


# ---------------------------------------------------------------------------
# Signature info serialization
# ---------------------------------------------------------------------------


def _build_signature_info(
    sig_result: Any | None,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Build the crJSON signature block from VerificationResult and context.

    Uses context keys populated by build_crypto_context:
    - signing_certificate: parsed cert summary with subject/issuer RFC 4514 strings
    - tsa_certificate: parsed TSA cert summary
    - timeStampToken.tspInfo.genTime: ISO timestamp string

    Falls back to parsing DER bytes from cose_signature.x5chain when available.
    """
    sig_out: dict[str, Any] = {}

    algorithm = ""
    cert_info: dict[str, Any] | None = None
    tsa_info: dict[str, Any] | None = None

    if sig_result is not None:
        algorithm = (sig_result.algorithm_name or "").lower()
        cose = sig_result.cose_signature
        if cose and cose.x5chain:
            cert_info = _parse_cert_info_from_der(cose.x5chain[0])

            # Timestamp token: try sig_tst first, then sig_tst2
            tst_bytes = cose.sig_tst or cose.sig_tst2
            if tst_bytes:
                tsa_info = _parse_tsa_cert_info_from_token(tst_bytes)

    # Supplement with context if DER parsing produced nothing
    if cert_info is None:
        signing_cert_ctx = context.get("signing_certificate", {})
        if isinstance(signing_cert_ctx, dict) and signing_cert_ctx:
            cert_info = {
                "serialNumber": "",
                "issuer": _parse_rdn_string(signing_cert_ctx.get("issuer", "")),
                "subject": _parse_rdn_string(signing_cert_ctx.get("subject", "")),
                "validity": {
                    "notBefore": signing_cert_ctx.get("not_before", ""),
                    "notAfter": signing_cert_ctx.get("not_after", ""),
                },
            }

    if tsa_info is None:
        tsa_cert_ctx = context.get("tsa_certificate", {})
        if isinstance(tsa_cert_ctx, dict) and tsa_cert_ctx:
            tsa_info = {
                "serialNumber": "",
                "issuer": _parse_rdn_string(tsa_cert_ctx.get("issuer", "")),
                "subject": _parse_rdn_string(tsa_cert_ctx.get("subject", "")),
                "validity": {
                    "notBefore": tsa_cert_ctx.get("not_before", ""),
                    "notAfter": tsa_cert_ctx.get("not_after", ""),
                },
            }

    if algorithm:
        sig_out["algorithm"] = algorithm

    if cert_info:
        sig_out["certificateInfo"] = cert_info

    # Timestamp info
    tst_block = context.get("timeStampToken", {})
    gen_time = ""
    if isinstance(tst_block, dict):
        tsp_info = tst_block.get("tspInfo", {})
        if isinstance(tsp_info, dict):
            gen_time = tsp_info.get("genTime", "")

    if gen_time or tsa_info:
        ts_entry: dict[str, Any] = {}
        if gen_time:
            ts_entry["timestamp"] = gen_time
        if tsa_info:
            ts_entry["certificateInfo"] = tsa_info
        sig_out["timeStampInfo"] = ts_entry

    return sig_out


# ---------------------------------------------------------------------------
# Validation results serialization
# ---------------------------------------------------------------------------


def _build_validation_results(
    report: Any,
    manifest_label: str,
    assertions_map: dict[str, Any],
    spec_version: str,
) -> dict[str, Any]:
    """Classify EvalResult entries from a ConformanceReport into crJSON validationResults.

    SKIP results are excluded entirely. Each non-skip result is classified as
    success, informational, or failure and placed in the corresponding list.

    Each entry carries: code, url (JUMBF pointer), and explanation.
    """
    from c2pa_conformance.evaluator.engine import ResultType

    success_list: list[dict[str, Any]] = []
    informational_list: list[dict[str, Any]] = []
    failure_list: list[dict[str, Any]] = []

    for eval_result in report.results:
        if eval_result.result == ResultType.SKIP:
            continue

        code = eval_result.status_code or ""
        explanation = eval_result.message or ""

        # Determine JUMBF URL for this result
        url = _jumbf_url_for_result(eval_result, manifest_label, assertions_map)

        entry: dict[str, Any] = {"code": code, "url": url, "explanation": explanation}

        # Honor the engine's explicit result type; fall back to code-based classification
        if eval_result.result == ResultType.INFORMATIONAL:
            informational_list.append(entry)
        elif eval_result.result == ResultType.FAIL or eval_result.result == ResultType.ERROR:
            failure_list.append(entry)
        elif eval_result.result == ResultType.PASS:
            # Double-check via status code in case code carries informational semantics
            classification = classify_status_code(code)
            if classification == "informational":
                informational_list.append(entry)
            else:
                success_list.append(entry)
        else:
            # Fallback: classify by code
            classification = classify_status_code(code)
            if classification == "success":
                success_list.append(entry)
            elif classification == "informational":
                informational_list.append(entry)
            else:
                failure_list.append(entry)

    return {
        "success": success_list,
        "informational": informational_list,
        "failure": failure_list,
        "specVersion": spec_version,
        "validationTime": datetime.now(timezone.utc).isoformat(),
    }


def _jumbf_url_for_result(
    eval_result: Any,
    manifest_label: str,
    assertions_map: dict[str, Any],
) -> str:
    """Derive a JUMBF URL for a validation result entry.

    Chooses the most specific JUMBF target based on the status code prefix:
    - assertion-level codes -> c2pa.assertions/<label>
    - signature-level codes -> c2pa.signature
    - claim-level codes     -> c2pa.claim
    - default               -> c2pa.claim
    """
    code = eval_result.status_code or ""
    details = eval_result.details or {}

    # Explicit assertion label in details takes precedence
    assertion_label = details.get("assertion_label", "")
    if assertion_label:
        return f"self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{assertion_label}"

    # Route by status code prefix
    if code.startswith("assertion.") or code.startswith("claimSignature."):
        # For assertion codes, try to find the relevant assertion label
        inferred = _infer_assertion_label(code, assertions_map)
        if inferred:
            return f"self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{inferred}"

    _signature_prefixes = (
        "claimSignature.",
        "signingCredential.",
        "timeStamp.",
        "timeOfSigning.",
        "algorithm.",
    )
    if any(code.startswith(p) for p in _signature_prefixes):
        return f"self#jumbf=/c2pa/{manifest_label}/c2pa.signature"

    if code.startswith("claim.") or code.startswith("assertion.") or code.startswith("manifest."):
        return f"self#jumbf=/c2pa/{manifest_label}/c2pa.claim"

    return f"self#jumbf=/c2pa/{manifest_label}/c2pa.claim"


def _infer_assertion_label(code: str, assertions_map: dict[str, Any]) -> str:
    """Infer which assertion label a status code refers to from naming conventions.

    Checks known assertion-type prefixes in the status code against the
    assertion labels present in the manifest.
    """
    # Common assertion label segments embedded in status codes
    # e.g. "assertion.dataHash.match" -> "c2pa.hash.data"
    #      "assertion.bmffHash.match" -> "c2pa.hash.bmff"
    code_to_label: dict[str, str] = {
        "dataHash": "c2pa.hash.data",
        "bmffHash": "c2pa.hash.bmff",
        "boxesHash": "c2pa.hash.boxes",
        "collectionHash": "c2pa.hash.collection",
        "multiAssetHash": "c2pa.hash.multi-asset",
    }
    for fragment, candidate_label in code_to_label.items():
        if fragment in code:
            # Check if the manifest actually has this assertion
            for key in assertions_map:
                if key.startswith(candidate_label):
                    return key
    return ""


# ---------------------------------------------------------------------------
# Manifest serialization
# ---------------------------------------------------------------------------


def _build_manifest_entry(
    manifest: Any,
    sig_result: Any | None,
    context: dict[str, Any],
    report: Any,
    spec_version: str,
) -> dict[str, Any]:
    """Serialize a single Manifest to its crJSON manifest entry."""
    assertions_map = _build_assertions_map(manifest.assertions)

    entry: dict[str, Any] = {
        "label": manifest.label,
        "assertions": assertions_map,
    }

    if manifest.claim:
        entry["claim.v2"] = _build_claim_v2(manifest.claim)

    sig_block = _build_signature_info(sig_result, context)
    if sig_block:
        entry["signature"] = sig_block

    entry["validationResults"] = _build_validation_results(
        report, manifest.label, assertions_map, spec_version
    )

    return entry


# ---------------------------------------------------------------------------
# Primary entry point
# ---------------------------------------------------------------------------


def serialize_to_crjson(
    store: object,
    report: object,
    sig_result: object | None,
    context: dict[str, Any],
    spec_version: str = "2.4",
) -> dict[str, Any]:
    """Serialize validation results to crJSON format.

    Args:
        store: ManifestStore from parser.manifest.
        report: ConformanceReport from evaluator.engine.
        sig_result: VerificationResult from crypto.verifier, or None.
        context: The evaluation context dict produced by _build_context and
                 build_crypto_context in cli.py.
        spec_version: C2PA spec version string, defaults to "2.4".

    Returns:
        A dict ready for json.dumps() that conforms to the crJSON schema.
        The manifests list is in reverse store order (active manifest first).
    """
    version = context.get("generator_version", _GENERATOR_VERSION)

    # Reverse the manifests list so the active manifest (last in store) appears first
    manifests_reversed = list(reversed(store.manifests))  # type: ignore[attr-defined]

    manifest_entries: list[dict[str, Any]] = []
    for manifest in manifests_reversed:
        # Signature and crypto context apply only to the active manifest.
        # Ingredient manifests do not carry separate sig_result structures.
        is_active = (
            store.active_manifest is not None  # type: ignore[attr-defined]
            and manifest.label == store.active_manifest.label  # type: ignore[attr-defined]
        )
        manifest_sig_result = sig_result if is_active else None

        entry = _build_manifest_entry(
            manifest=manifest,
            sig_result=manifest_sig_result,
            context=context,
            report=report,
            spec_version=spec_version,
        )
        manifest_entries.append(entry)

    return {
        "@context": _CRJSON_CONTEXT,
        "manifests": manifest_entries,
        "jsonGenerator": {
            "name": _GENERATOR_NAME,
            "version": version,
        },
    }
