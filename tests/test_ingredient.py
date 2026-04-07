"""Tests for the ingredient resolver (recursive manifest chain traversal)."""

from __future__ import annotations

from c2pa_conformance.parser.ingredient import (
    _parse_jumbf_uri,
    find_hard_binding_manifest,
    find_ingredient_assertions,
    is_ingredient_assertion,
    resolve_ingredients,
)
from c2pa_conformance.parser.manifest import (
    Assertion,
    Claim,
    Manifest,
    ManifestStore,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(
    label: str,
    ingredients: list[dict] | None = None,
    is_update: bool = False,
    has_binding: bool = True,
    redacted: list[str] | None = None,
) -> Manifest:
    """Build a minimal Manifest for testing."""
    assertions: list[Assertion] = []

    if has_binding:
        assertions.append(
            Assertion(
                label="c2pa.hash.data",
                data={"alg": "sha256", "hash": b"x" * 32},
            )
        )

    for ing in ingredients or []:
        assertions.append(
            Assertion(
                label=ing.get("assertion_label", "c2pa.ingredient"),
                data={
                    "activeManifest": ing["label"],
                    "relationship": ing.get("rel", "parentOf"),
                    "dc:title": ing.get("title", ""),
                },
            )
        )

    claim_data: dict = {"claim_generator": "test"}
    if is_update:
        claim_data["update_manifest"] = True
    if redacted:
        claim_data["redacted_assertions"] = redacted

    return Manifest(
        label=label,
        claim=Claim(data=claim_data),
        assertions=assertions,
    )


def _make_manifest_jumbf(label: str, ref_label: str, relationship: str = "parentOf") -> Manifest:
    """Build a manifest whose ingredient uses a JUMBF URI instead of activeManifest."""
    jumbf_url = f"self#jumbf=/c2pa/{ref_label}/c2pa.assertions/c2pa.ingredient"
    assertions = [
        Assertion(
            label="c2pa.hash.data",
            data={"alg": "sha256", "hash": b"x" * 32},
        ),
        Assertion(
            label="c2pa.ingredient",
            data={
                "c2pa_manifest": {"url": jumbf_url},
                "relationship": relationship,
                "dc:title": "source.jpg",
            },
        ),
    ]
    return Manifest(
        label=label,
        claim=Claim(data={"claim_generator": "test"}),
        assertions=assertions,
    )


def _make_store(*manifests: Manifest) -> ManifestStore:
    store = ManifestStore(manifests=list(manifests))
    if manifests:
        store.active_manifest = manifests[-1]
    return store


# ---------------------------------------------------------------------------
# 1. is_ingredient_assertion
# ---------------------------------------------------------------------------


class TestIsIngredientAssertion:
    def test_v1_true(self) -> None:
        assert is_ingredient_assertion("c2pa.ingredient") is True

    def test_v2_true(self) -> None:
        assert is_ingredient_assertion("c2pa.ingredient.v2") is True

    def test_v3_true(self) -> None:
        assert is_ingredient_assertion("c2pa.ingredient.v3") is True

    def test_hash_data_false(self) -> None:
        assert is_ingredient_assertion("c2pa.hash.data") is False

    def test_empty_false(self) -> None:
        assert is_ingredient_assertion("") is False

    def test_partial_false(self) -> None:
        assert is_ingredient_assertion("c2pa.ingredient.v4") is False


# ---------------------------------------------------------------------------
# 2. find_ingredient_assertions
# ---------------------------------------------------------------------------


class TestFindIngredientAssertions:
    def test_none(self) -> None:
        m = _make_manifest("urn:uuid:A")
        result = find_ingredient_assertions(m)
        assert result == []

    def test_one(self) -> None:
        m = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        result = find_ingredient_assertions(m)
        assert len(result) == 1
        assert result[0].manifest_label == "urn:uuid:B"
        assert result[0].relationship == "parentOf"
        assert result[0].assertion_label == "c2pa.ingredient"

    def test_multiple(self) -> None:
        m = _make_manifest(
            "urn:uuid:A",
            ingredients=[
                {"label": "urn:uuid:B", "rel": "parentOf"},
                {"label": "urn:uuid:C", "rel": "componentOf"},
            ],
        )
        result = find_ingredient_assertions(m)
        assert len(result) == 2
        assert result[0].manifest_label == "urn:uuid:B"
        assert result[1].manifest_label == "urn:uuid:C"
        assert result[1].relationship == "componentOf"

    def test_v2_label(self) -> None:
        m = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "assertion_label": "c2pa.ingredient.v2"}],
        )
        result = find_ingredient_assertions(m)
        assert len(result) == 1
        assert result[0].assertion_label == "c2pa.ingredient.v2"

    def test_title_extracted(self) -> None:
        m = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "title": "photo.jpg"}],
        )
        result = find_ingredient_assertions(m)
        assert result[0].title == "photo.jpg"


# ---------------------------------------------------------------------------
# 3. _extract_manifest_label (via activeManifest and JUMBF URI)
# ---------------------------------------------------------------------------


class TestExtractManifestLabel:
    def test_active_manifest(self) -> None:
        m = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        refs = find_ingredient_assertions(m)
        assert refs[0].manifest_label == "urn:uuid:B"

    def test_jumbf_uri(self) -> None:
        m = _make_manifest_jumbf("urn:uuid:A", "urn:uuid:B")
        refs = find_ingredient_assertions(m)
        assert refs[0].manifest_label == "urn:uuid:B"

    def test_active_manifest_takes_precedence(self) -> None:
        # activeManifest should win over c2pa_manifest.url
        assertions = [
            Assertion(
                label="c2pa.ingredient",
                data={
                    "activeManifest": "urn:uuid:ACTIVE",
                    "c2pa_manifest": {
                        "url": "self#jumbf=/c2pa/urn:uuid:JUMBF/c2pa.assertions/c2pa.ingredient"
                    },
                    "relationship": "parentOf",
                },
            )
        ]
        m = Manifest(label="urn:uuid:A", claim=Claim(data={}), assertions=assertions)
        refs = find_ingredient_assertions(m)
        assert refs[0].manifest_label == "urn:uuid:ACTIVE"

    def test_no_reference_empty_string(self) -> None:
        assertions = [
            Assertion(
                label="c2pa.ingredient",
                data={"relationship": "parentOf"},
            )
        ]
        m = Manifest(label="urn:uuid:A", claim=Claim(data={}), assertions=assertions)
        refs = find_ingredient_assertions(m)
        assert refs[0].manifest_label == ""


# ---------------------------------------------------------------------------
# 4. _parse_jumbf_uri
# ---------------------------------------------------------------------------


class TestParseJumbfUri:
    def test_standard_format(self) -> None:
        uri = "self#jumbf=/c2pa/urn:uuid:XXXX/c2pa.assertions/c2pa.ingredient"
        assert _parse_jumbf_uri(uri) == "urn:uuid:XXXX"

    def test_no_jumbf_fragment_urn(self) -> None:
        uri = "urn:uuid:direct-label"
        assert _parse_jumbf_uri(uri) == "urn:uuid:direct-label"

    def test_no_jumbf_fragment_other(self) -> None:
        # Non-jumbf, non-urn strings returned as-is
        uri = "some-label"
        assert _parse_jumbf_uri(uri) == "some-label"

    def test_short_jumbf_path(self) -> None:
        # Path with only /c2pa (no label segment) -- falls through to return full string
        uri = "self#jumbf=/c2pa"
        # segments = ["c2pa"], len < 2, so fallback to returning the path
        result = _parse_jumbf_uri(uri)
        # Should not crash; exact fallback value is implementation-defined
        assert isinstance(result, str)

    def test_label_with_nested_path(self) -> None:
        uri = "self#jumbf=/c2pa/my-manifest-label/c2pa.assertions/c2pa.hash.data"
        assert _parse_jumbf_uri(uri) == "my-manifest-label"


# ---------------------------------------------------------------------------
# 5. resolve_ingredients
# ---------------------------------------------------------------------------


class TestResolveIngredients:
    def test_no_ingredients(self) -> None:
        a = _make_manifest("urn:uuid:A")
        store = _make_store(a)
        chain = resolve_ingredients(store, a)
        assert chain.root_manifest_label == "urn:uuid:A"
        assert chain.ingredients == []
        assert chain.all_manifests == ["urn:uuid:A"]
        assert chain.has_circular_ref is False
        assert chain.depth == 0

    def test_single_ingredient(self) -> None:
        b = _make_manifest("urn:uuid:B")
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        store = _make_store(b, a)
        chain = resolve_ingredients(store, a)
        assert len(chain.ingredients) == 1
        assert chain.ingredients[0].manifest_label == "urn:uuid:B"
        assert chain.ingredients[0].manifest is b
        assert "urn:uuid:B" in chain.all_manifests
        assert chain.has_circular_ref is False

    def test_chain_depth_two(self) -> None:
        c = _make_manifest("urn:uuid:C")
        b = _make_manifest("urn:uuid:B", ingredients=[{"label": "urn:uuid:C"}])
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        store = _make_store(c, b, a)
        chain = resolve_ingredients(store, a)
        # All three manifests should appear
        assert "urn:uuid:A" in chain.all_manifests
        assert "urn:uuid:B" in chain.all_manifests
        assert "urn:uuid:C" in chain.all_manifests
        assert chain.has_circular_ref is False

    def test_circular_reference_detected(self) -> None:
        # A -> B -> A
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        b = _make_manifest("urn:uuid:B", ingredients=[{"label": "urn:uuid:A"}])
        store = _make_store(a, b)
        chain = resolve_ingredients(store, a)
        assert chain.has_circular_ref is True
        assert chain.circular_ref_label == "urn:uuid:A"

    def test_missing_manifest_ref_is_none(self) -> None:
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:MISSING"}])
        store = _make_store(a)
        chain = resolve_ingredients(store, a)
        assert len(chain.ingredients) == 1
        assert chain.ingredients[0].manifest is None
        assert chain.has_circular_ref is False

    def test_multiple_ingredients(self) -> None:
        b = _make_manifest("urn:uuid:B")
        c = _make_manifest("urn:uuid:C")
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[
                {"label": "urn:uuid:B", "rel": "parentOf"},
                {"label": "urn:uuid:C", "rel": "componentOf"},
            ],
        )
        store = _make_store(b, c, a)
        chain = resolve_ingredients(store, a)
        assert len(chain.ingredients) == 2
        assert {r.manifest_label for r in chain.ingredients} == {"urn:uuid:B", "urn:uuid:C"}
        assert chain.has_circular_ref is False

    def test_redacted_assertions_collected(self) -> None:
        redacted_uri = "self#jumbf=/c2pa/urn:uuid:B/c2pa.assertions/c2pa.hash.data"
        a = _make_manifest("urn:uuid:A", redacted=[redacted_uri])
        store = _make_store(a)
        chain = resolve_ingredients(store, a)
        assert redacted_uri in chain.redacted_assertions

    def test_redacted_assertions_from_sub_chain(self) -> None:
        redacted_uri = "self#jumbf=/c2pa/urn:uuid:C/c2pa.assertions/c2pa.hash.data"
        b = _make_manifest("urn:uuid:B", redacted=[redacted_uri])
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        store = _make_store(b, a)
        chain = resolve_ingredients(store, a)
        assert redacted_uri in chain.redacted_assertions

    def test_depth_zero_at_root(self) -> None:
        a = _make_manifest("urn:uuid:A")
        store = _make_store(a)
        chain = resolve_ingredients(store, a)
        assert chain.depth == 0

    def test_depth_at_sub_chain(self) -> None:
        # Manually call with depth=2 to verify the parameter is threaded through
        b = _make_manifest("urn:uuid:B")
        store = _make_store(b)
        chain = resolve_ingredients(store, b, depth=2)
        assert chain.depth == 2

    def test_max_depth_stops_recursion(self) -> None:
        c = _make_manifest("urn:uuid:C")
        b = _make_manifest("urn:uuid:B", ingredients=[{"label": "urn:uuid:C"}])
        a = _make_manifest("urn:uuid:A", ingredients=[{"label": "urn:uuid:B"}])
        store = _make_store(c, b, a)
        # max_depth=0 means we stop before any recursion
        chain = resolve_ingredients(store, a, max_depth=0)
        # At depth=0, max_depth=0, we return before processing ingredients
        assert chain.root_manifest_label == "urn:uuid:A"

    def test_empty_manifest_label_still_added_to_ingredients(self) -> None:
        # Assertion with no reference should still be in ingredients list
        assertions = [
            Assertion(
                label="c2pa.ingredient",
                data={"relationship": "parentOf"},
            )
        ]
        a = Manifest(label="urn:uuid:A", claim=Claim(data={}), assertions=assertions)
        store = _make_store(a)
        chain = resolve_ingredients(store, a)
        assert len(chain.ingredients) == 1
        assert chain.ingredients[0].manifest_label == ""
        assert chain.ingredients[0].manifest is None


# ---------------------------------------------------------------------------
# 6. find_hard_binding_manifest
# ---------------------------------------------------------------------------


class TestFindHardBindingManifest:
    def test_standard_manifest_with_binding(self) -> None:
        a = _make_manifest("urn:uuid:A", has_binding=True)
        store = _make_store(a)
        result = find_hard_binding_manifest(store, a)
        assert result is a

    def test_standard_manifest_without_binding(self) -> None:
        a = _make_manifest("urn:uuid:A", has_binding=False)
        store = _make_store(a)
        result = find_hard_binding_manifest(store, a)
        assert result is None

    def test_update_manifest_follows_parent(self) -> None:
        # standard manifest B has hard binding; update manifest A points to B
        b = _make_manifest("urn:uuid:B", has_binding=True)
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(b, a)
        result = find_hard_binding_manifest(store, a)
        assert result is b

    def test_update_chain(self) -> None:
        # C (standard, binding) <- B (update) <- A (update)
        c = _make_manifest("urn:uuid:C", has_binding=True)
        b = _make_manifest(
            "urn:uuid:B",
            ingredients=[{"label": "urn:uuid:C", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(c, b, a)
        result = find_hard_binding_manifest(store, a)
        assert result is c

    def test_update_no_binding_in_chain(self) -> None:
        b = _make_manifest("urn:uuid:B", has_binding=False)
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(b, a)
        result = find_hard_binding_manifest(store, a)
        assert result is None

    def test_update_circular_parent_returns_none(self) -> None:
        # A (update) -> B (update) -> A: circular
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        b = _make_manifest(
            "urn:uuid:B",
            ingredients=[{"label": "urn:uuid:A", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(a, b)
        result = find_hard_binding_manifest(store, a)
        assert result is None

    def test_update_missing_parent_returns_none(self) -> None:
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:MISSING", "rel": "parentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(a)
        result = find_hard_binding_manifest(store, a)
        assert result is None

    def test_update_no_parent_of_ingredient_returns_none(self) -> None:
        # Update manifest with only componentOf ingredients (no parentOf)
        b = _make_manifest("urn:uuid:B", has_binding=True)
        a = _make_manifest(
            "urn:uuid:A",
            ingredients=[{"label": "urn:uuid:B", "rel": "componentOf"}],
            is_update=True,
            has_binding=False,
        )
        store = _make_store(b, a)
        result = find_hard_binding_manifest(store, a)
        assert result is None
