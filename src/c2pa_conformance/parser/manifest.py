"""C2PA Manifest Store parser.

Parses a JUMBF box tree into a structured manifest store representation
that the predicate evaluator can work with. This is the bridge between
raw JUMBF parsing and the declarative evaluation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import cbor2

from c2pa_conformance.parser.jumbf import (
    CBOR_BOX,
    JUMB,
    JUMBFBox,
    JUMBFParseError,
    parse_jumbf,
)


class ManifestParseError(Exception):
    """Raised when a C2PA manifest structure is malformed."""


@dataclass
class Assertion:
    """A single C2PA assertion."""

    label: str
    data: dict[str, Any] = field(default_factory=dict)
    raw_cbor: bytes = b""
    box: JUMBFBox | None = None

    @property
    def is_hash_data(self) -> bool:
        return self.label == "c2pa.hash.data"

    @property
    def is_hash_bmff(self) -> bool:
        return self.label in ("c2pa.hash.bmff", "c2pa.hash.bmff.v2", "c2pa.hash.bmff.v3")

    @property
    def is_hash_boxes(self) -> bool:
        return self.label == "c2pa.hash.boxes"

    @property
    def is_hash_multi_asset(self) -> bool:
        return self.label == "c2pa.hash.multi-asset"

    @property
    def is_hash_collection(self) -> bool:
        return self.label == "c2pa.hash.collection"

    @property
    def is_hard_binding(self) -> bool:
        return any(
            [
                self.is_hash_data,
                self.is_hash_bmff,
                self.is_hash_boxes,
                self.is_hash_multi_asset,
                self.is_hash_collection,
            ]
        )


@dataclass
class Claim:
    """A parsed C2PA claim."""

    data: dict[str, Any] = field(default_factory=dict)
    raw_cbor: bytes = b""

    @property
    def claim_generator(self) -> str:
        cg = self.data.get("claim_generator", "")
        if cg:
            return str(cg)
        # Fall back to claim_generator_info (v2 format)
        info = self.data.get("claim_generator_info")
        if isinstance(info, dict):
            name = info.get("name", "")
            version = info.get("version", "")
            return f"{name}/{version}" if version else str(name)
        if isinstance(info, list) and info:
            item = info[0]
            if isinstance(item, dict):
                name = item.get("name", "")
                version = item.get("version", "")
                return f"{name}/{version}" if version else str(name)
        return ""

    @property
    def claim_generator_info(self) -> list[dict[str, Any]]:
        info = self.data.get("claim_generator_info", [])
        if isinstance(info, dict):
            return [info]
        if isinstance(info, list):
            return info
        return []

    @property
    def signature_ref(self) -> str:
        return str(self.data.get("signature", ""))

    @property
    def assertion_refs(self) -> list[dict[str, Any]]:
        # Claim v2 uses created_assertions + gathered_assertions;
        # claim v1 uses assertions.
        refs = self.data.get("assertions", [])
        if not refs:
            created = self.data.get("created_assertions", [])
            gathered = self.data.get("gathered_assertions", [])
            refs = (created if isinstance(created, list) else []) + (
                gathered if isinstance(gathered, list) else []
            )
        if isinstance(refs, list):
            return refs
        return []

    @property
    def is_update_manifest(self) -> bool:
        return bool(self.data.get("update_manifest"))


@dataclass
class Manifest:
    """A single C2PA manifest within a manifest store."""

    label: str
    claim: Claim | None = None
    assertions: list[Assertion] = field(default_factory=list)
    signature_bytes: bytes = b""
    box: JUMBFBox | None = None

    @property
    def hard_binding(self) -> Assertion | None:
        for assertion in self.assertions:
            if assertion.is_hard_binding:
                return assertion
        return None

    @property
    def is_update(self) -> bool:
        return self.claim is not None and self.claim.is_update_manifest

    def get_assertion(self, label: str) -> Assertion | None:
        for assertion in self.assertions:
            if assertion.label == label:
                return assertion
        return None

    def get_assertions(self, label: str) -> list[Assertion]:
        return [a for a in self.assertions if a.label == label]


@dataclass
class ManifestStore:
    """A complete C2PA Manifest Store parsed from JUMBF."""

    manifests: list[Manifest] = field(default_factory=list)
    active_manifest: Manifest | None = None
    raw_bytes: bytes = b""

    @property
    def manifest_count(self) -> int:
        return len(self.manifests)

    def get_manifest(self, label: str) -> Manifest | None:
        for m in self.manifests:
            if m.label == label:
                return m
        return None


def _decode_cbor_payload(box: JUMBFBox) -> dict[str, Any]:
    """Decode a CBOR box payload into a dict."""
    cbor_box = box.find_child(CBOR_BOX)
    if cbor_box is None:
        # Try the box payload directly if it's not a superbox
        if box.payload:
            try:
                result = cbor2.loads(box.payload)
                if isinstance(result, dict):
                    return result
            except Exception:
                pass
        return {}

    try:
        result = cbor2.loads(cbor_box.payload)
        if isinstance(result, dict):
            return result
        return {"_value": result}
    except Exception as exc:
        raise ManifestParseError(f"Failed to decode CBOR in box '{box.label}': {exc}") from exc


def _parse_assertion(box: JUMBFBox) -> Assertion:
    """Parse a single assertion from its JUMBF superbox."""
    cbor_child = box.find_child(CBOR_BOX)
    raw = cbor_child.payload if cbor_child else b""

    data: dict[str, Any] = {}
    if raw:
        try:
            decoded = cbor2.loads(raw)
            if isinstance(decoded, dict):
                data = decoded
        except Exception:
            pass

    return Assertion(
        label=box.label,
        data=data,
        raw_cbor=raw,
        box=box,
    )


def _parse_manifest(manifest_box: JUMBFBox) -> Manifest:
    """Parse a single manifest from its JUMBF superbox."""
    manifest = Manifest(label=manifest_box.label, box=manifest_box)

    for child in manifest_box.children:
        if not child.is_superbox:
            continue

        label_lower = child.label.lower()

        # Claim box
        if label_lower.startswith("c2pa.claim"):
            cbor_child = child.find_child(CBOR_BOX)
            raw = cbor_child.payload if cbor_child else b""
            data: dict[str, Any] = {}
            if raw:
                try:
                    decoded = cbor2.loads(raw)
                    if isinstance(decoded, dict):
                        data = decoded
                except Exception:
                    pass
            manifest.claim = Claim(data=data, raw_cbor=raw)

        # Assertion store
        elif label_lower.startswith("c2pa.assertions"):
            for assertion_box in child.children:
                if assertion_box.is_superbox:
                    manifest.assertions.append(_parse_assertion(assertion_box))

        # Signature box
        elif label_lower.startswith("c2pa.signature"):
            cbor_child = child.find_child(CBOR_BOX)
            if cbor_child:
                manifest.signature_bytes = cbor_child.payload

    return manifest


def parse_manifest_store(jumbf_bytes: bytes) -> ManifestStore:
    """Parse raw JUMBF bytes into a ManifestStore.

    This is the primary entry point for manifest parsing. Takes the raw
    JUMBF bytes extracted from any container format and returns a fully
    parsed ManifestStore.

    Args:
        jumbf_bytes: Raw JUMBF bytes (the complete manifest store).

    Returns:
        Parsed ManifestStore with manifests, claims, and assertions.
    """
    store = ManifestStore(raw_bytes=jumbf_bytes)

    try:
        boxes = parse_jumbf(jumbf_bytes)
    except JUMBFParseError as exc:
        raise ManifestParseError(f"Failed to parse JUMBF: {exc}") from exc

    if not boxes:
        return store

    # The top-level box should be the manifest store superbox.
    # Use the first superbox regardless of trailing boxes (some formats
    # include zero-padding that produces phantom trailing entries).
    root = boxes[0] if boxes[0].is_superbox else None

    manifest_boxes: list[JUMBFBox]
    if root and root.children:
        # Standard: single manifest store superbox containing manifest superboxes
        manifest_boxes = [c for c in root.children if c.is_superbox and c.box_type == JUMB]
    else:
        # Fallback: sequence of manifest superboxes at top level
        manifest_boxes = [b for b in boxes if b.is_superbox and b.box_type == JUMB]

    for mbox in manifest_boxes:
        manifest = _parse_manifest(mbox)
        store.manifests.append(manifest)

    # The active manifest is the last one in the store
    if store.manifests:
        store.active_manifest = store.manifests[-1]

    return store
