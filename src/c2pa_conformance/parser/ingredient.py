"""Ingredient resolver: recursive manifest chain traversal.

Locates ingredient assertions in a manifest, resolves referenced manifests
within the same ManifestStore, and traverses the chain recursively.
Detects circular references and handles redacted assertions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from c2pa_conformance.parser.manifest import Manifest, ManifestStore


class IngredientError(Exception):
    """Raised when ingredient resolution fails."""


@dataclass
class IngredientRef:
    """A resolved ingredient reference."""

    assertion_label: str  # e.g., "c2pa.ingredient"
    manifest_label: str  # The referenced manifest's label
    relationship: str  # e.g., "parentOf", "componentOf"
    title: str = ""  # dc:title from the ingredient assertion
    manifest: Manifest | None = None  # The resolved manifest (if found)


@dataclass
class IngredientChain:
    """The complete ingredient chain for a manifest."""

    root_manifest_label: str
    ingredients: list[IngredientRef] = field(default_factory=list)
    all_manifests: list[str] = field(default_factory=list)  # all manifest labels in chain
    has_circular_ref: bool = False
    circular_ref_label: str = ""
    depth: int = 0
    redacted_assertions: list[str] = field(default_factory=list)


# Ingredient assertion labels (all versions)
_INGREDIENT_LABELS = frozenset(
    {
        "c2pa.ingredient",
        "c2pa.ingredient.v2",
        "c2pa.ingredient.v3",
    }
)


def is_ingredient_assertion(label: str) -> bool:
    """Check if an assertion label is an ingredient assertion."""
    return label in _INGREDIENT_LABELS


def find_ingredient_assertions(manifest: Manifest) -> list[IngredientRef]:
    """Find all ingredient assertions in a manifest.

    Returns a list of IngredientRef with the referenced manifest label
    extracted from the assertion data.
    """
    refs: list[IngredientRef] = []

    for assertion in manifest.assertions:
        if not is_ingredient_assertion(assertion.label):
            continue

        data = assertion.data

        # Extract manifest reference
        manifest_label = _extract_manifest_label(data)
        relationship = str(data.get("relationship", "parentOf"))
        title = str(data.get("dc:title", data.get("title", "")))

        refs.append(
            IngredientRef(
                assertion_label=assertion.label,
                manifest_label=manifest_label,
                relationship=relationship,
                title=title,
            )
        )

    return refs


def _extract_manifest_label(data: dict[str, Any]) -> str:
    """Extract the referenced manifest label from ingredient assertion data.

    Checks multiple fields in order of precedence:
    1. activeManifest (direct label reference)
    2. c2pa_manifest.url (JUMBF URI, extract the manifest label)
    """
    # Direct manifest label
    active = data.get("activeManifest")
    if active and isinstance(active, str):
        return active

    # JUMBF URI reference
    c2pa_manifest = data.get("c2pa_manifest", {})
    if isinstance(c2pa_manifest, dict):
        url = c2pa_manifest.get("url", "")
        if isinstance(url, str) and url:
            label = _parse_jumbf_uri(url)
            if label:
                return label

    return ""


def _parse_jumbf_uri(uri: str) -> str:
    """Extract manifest label from a JUMBF URI.

    Formats:
    - self#jumbf=/c2pa/<label>/...
    - urn:<something>  (treated as a label directly)
    - anything else: returned as-is
    """
    if "#jumbf=" in uri:
        # Extract path after /c2pa/
        parts = uri.split("#jumbf=")
        if len(parts) == 2:
            path = parts[1]
            segments = [s for s in path.split("/") if s]
            if len(segments) >= 2 and segments[0] == "c2pa":
                return segments[1]

    # Fallback: treat the whole string as a label if it looks like a URN
    if uri.startswith("urn:"):
        return uri

    return uri


def resolve_ingredients(
    store: ManifestStore,
    manifest: Manifest,
    visited: set[str] | None = None,
    depth: int = 0,
    max_depth: int = 100,
) -> IngredientChain:
    """Recursively resolve all ingredients for a manifest.

    Traverses the ingredient chain depth-first, detecting circular
    references and collecting redacted assertions.

    Args:
        store: The ManifestStore containing all manifests.
        manifest: The manifest to resolve ingredients for.
        visited: Set of already-visited manifest labels (for circular detection).
        depth: Current recursion depth.
        max_depth: Maximum recursion depth before stopping.

    Returns:
        IngredientChain describing the full chain.
    """
    if visited is None:
        visited = set()

    chain = IngredientChain(
        root_manifest_label=manifest.label,
        depth=depth,
    )
    chain.all_manifests.append(manifest.label)

    # Collect redacted assertions from this manifest's claim
    if manifest.claim and manifest.claim.data:
        redacted = manifest.claim.data.get("redacted_assertions", [])
        if isinstance(redacted, list):
            for r in redacted:
                if isinstance(r, str):
                    chain.redacted_assertions.append(r)

    # Validate no self-redaction
    for r in list(chain.redacted_assertions):
        if manifest.label in r:
            for assertion in manifest.assertions:
                if assertion.label in r:
                    chain.redacted_assertions.append(
                        f"INVALID: {manifest.label} redacts own assertion {assertion.label}"
                    )

    if depth >= max_depth:
        return chain

    # Check for circular reference
    if manifest.label in visited:
        chain.has_circular_ref = True
        chain.circular_ref_label = manifest.label
        return chain

    visited.add(manifest.label)

    # Find ingredient assertions
    refs = find_ingredient_assertions(manifest)

    for ref in refs:
        if not ref.manifest_label:
            chain.ingredients.append(ref)
            continue

        # Resolve the referenced manifest
        ingredient_manifest = store.get_manifest(ref.manifest_label)
        ref.manifest = ingredient_manifest
        chain.ingredients.append(ref)

        if ingredient_manifest:
            chain.all_manifests.append(ref.manifest_label)

            # Check for circular reference before recursing
            if ref.manifest_label in visited:
                chain.has_circular_ref = True
                chain.circular_ref_label = ref.manifest_label
                continue

            # Recurse into ingredient's ingredients
            sub_chain = resolve_ingredients(
                store, ingredient_manifest, visited.copy(), depth + 1, max_depth
            )

            if sub_chain.has_circular_ref:
                chain.has_circular_ref = True
                chain.circular_ref_label = sub_chain.circular_ref_label

            chain.all_manifests.extend(sub_chain.all_manifests[1:])  # skip root (already added)
            chain.redacted_assertions.extend(sub_chain.redacted_assertions)

    return chain


def find_hard_binding_manifest(
    store: ManifestStore,
    manifest: Manifest,
) -> Manifest | None:
    """Find the manifest that contains the hard binding for content validation.

    For standard manifests, this is the manifest itself.
    For update manifests, follow the parentOf chain to find the first
    standard manifest with a hard binding.
    """
    if not manifest.is_update:
        return manifest if manifest.hard_binding else None

    # Follow parentOf chain
    visited: set[str] = {manifest.label}
    current = manifest

    while current.is_update:
        refs = find_ingredient_assertions(current)
        parent_ref = None
        for ref in refs:
            if ref.relationship == "parentOf":
                parent_ref = ref
                break

        if not parent_ref or not parent_ref.manifest_label:
            return None

        if parent_ref.manifest_label in visited:
            return None  # circular

        visited.add(parent_ref.manifest_label)
        parent = store.get_manifest(parent_ref.manifest_label)
        if not parent:
            return None

        if not parent.is_update and parent.hard_binding:
            return parent
        current = parent

    return current if current.hard_binding else None
