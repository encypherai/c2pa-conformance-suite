"""Normalize c2pa-tool output to the conformance suite's status code format."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedResult:
    """A single normalized validation result."""

    rule_id: str = ""
    status_code: str = ""
    result: str = ""  # "pass", "fail", "informational"
    message: str = ""


@dataclass
class NormalizedReport:
    """Normalized validation report from c2pa-tool."""

    asset_path: str = ""
    manifest_count: int = 0
    active_manifest: str = ""
    results: list[NormalizedResult] = field(default_factory=list)
    raw_validation_status: list[dict[str, Any]] = field(default_factory=list)


def normalize_c2pa_tool_output(json_output: dict | None) -> NormalizedReport:
    """Convert c2pa-tool JSON output to normalized format.

    c2pa-tool outputs a structure like::

        {
            "manifests": {
                "<label>": {
                    "claim_generator": "...",
                    "validation_status": [
                        {"code": "assertion.dataHash.match", "url": "...", "explanation": "..."},
                        ...
                    ]
                }
            },
            "active_manifest": "<label>"
        }
    """
    report = NormalizedReport()

    if not json_output:
        return report

    manifests = json_output.get("manifests", {})
    report.manifest_count = len(manifests)
    report.active_manifest = json_output.get("active_manifest", "")

    # Extract validation_status from the active manifest
    active_label = report.active_manifest
    if active_label and active_label in manifests:
        manifest_data = manifests[active_label]
        validation_status = manifest_data.get("validation_status", [])
        report.raw_validation_status = validation_status

        for entry in validation_status:
            if not isinstance(entry, dict):
                continue

            code = entry.get("code", "")
            explanation = entry.get("explanation", "")

            result = _classify_status_code(code)

            report.results.append(
                NormalizedResult(
                    status_code=code,
                    result=result,
                    message=explanation,
                )
            )

    return report


# Status codes that indicate success
_PASS_CODES = frozenset(
    {
        "assertion.dataHash.match",
        "assertion.bmffHash.match",
        "assertion.boxesHash.match",
        "assertion.collectionHash.match",
        "claimSignature.validated",
        "signingCredential.trusted",
        "signingCredential.ocsp.notRevoked",
        "timeStamp.trusted",
        "timeStamp.validated",
    }
)

# Status codes that indicate failure
_FAIL_CODES = frozenset(
    {
        "assertion.dataHash.mismatch",
        "assertion.bmffHash.mismatch",
        "assertion.boxesHash.mismatch",
        "assertion.collectionHash.mismatch",
        "claimSignature.mismatch",
        "claimSignature.missing",
        "signingCredential.untrusted",
        "signingCredential.invalid",
        "signingCredential.ocsp.revoked",
        "algorithm.unsupported",
        "claim.malformed",
        "manifest.inaccessible",
    }
)


def _classify_status_code(code: str) -> str:
    """Classify a C2PA status code as pass, fail, or informational."""
    if code in _PASS_CODES:
        return "pass"
    if code in _FAIL_CODES:
        return "fail"
    # Heuristic: check for keywords in the code string.
    # Check fail keywords first so "mismatch" is not caught by the "match" pass keyword.
    lower = code.lower()
    if any(k in lower for k in ("mismatch", "missing", "invalid", "revoked", "malformed")):
        return "fail"
    if any(k in lower for k in ("match", "validated", "trusted", "notrevo")):
        return "pass"
    return "informational"
