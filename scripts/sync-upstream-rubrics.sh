#!/bin/bash
# Sync rubric files from the c2pa-org/conformance upstream repo.
#
# Fetches the latest rubric YAML files from the asset-rubrics branch and
# copies them into the vendored location at src/c2pa_conformance/data/rubrics/.
#
# Requires: gh (GitHub CLI) with c2pa-org access.
#
# Usage:
#   ./scripts/sync-upstream-rubrics.sh [branch]
#
# Default branch: sherifhanna-google/asset-rubrics

set -euo pipefail

REPO="c2pa-org/conformance"
BRANCH="${1:-sherifhanna-google/asset-rubrics}"
DEST="src/c2pa_conformance/data/rubrics"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

echo "Syncing rubrics from $REPO ($BRANCH) -> $DEST"

# Sync composed rubric files
for f in asset-rubric-conformance0.1-spec2.2.yml \
         asset-rubric-conformance0.2-spec2.2.yml \
         asset-rubric-conformance0.2-spec2.4.yml \
         asset-rubric-integrity.yml \
         asset-rubric-signals-local.yml; do
    echo "  Fetching $f ..."
    gh api "repos/$REPO/contents/asset-rubrics/$f?ref=$BRANCH" \
        --jq '.content' 2>/dev/null | tr -d '\n' | base64 -d > "$DEST/$f" 2>/dev/null
done

# Sync composable fragments
mkdir -p "$DEST/composables"
for f in $(gh api "repos/$REPO/git/trees/$BRANCH?recursive=1" \
    --jq '.tree[] | select(.path | test("^asset-rubrics/composables/")) | .path' 2>/dev/null); do
    fname=$(basename "$f")
    echo "  Fetching composables/$fname ..."
    gh api "repos/$REPO/contents/$f?ref=$BRANCH" \
        --jq '.content' 2>/dev/null | tr -d '\n' | base64 -d > "$DEST/composables/$fname" 2>/dev/null
done

# Sync test vectors
VECTORS_DEST="tests/fixtures/upstream_rubric_vectors"
mkdir -p "$VECTORS_DEST/unit"

for f in $(gh api "repos/$REPO/git/trees/$BRANCH?recursive=1" \
    --jq '.tree[] | select(.path | test("^asset-rubrics/test/[^/]+\\.json$")) | .path' 2>/dev/null); do
    fname=$(basename "$f")
    echo "  Fetching test/$fname ..."
    gh api "repos/$REPO/contents/$f?ref=$BRANCH" \
        --jq '.content' 2>/dev/null | tr -d '\n' | base64 -d > "$VECTORS_DEST/$fname" 2>/dev/null
done

for f in $(gh api "repos/$REPO/git/trees/$BRANCH?recursive=1" \
    --jq '.tree[] | select(.path | test("^asset-rubrics/test/unit/")) | .path' 2>/dev/null); do
    fname=$(basename "$f")
    echo "  Fetching test/unit/$fname ..."
    gh api "repos/$REPO/contents/$f?ref=$BRANCH" \
        --jq '.content' 2>/dev/null | tr -d '\n' | base64 -d > "$VECTORS_DEST/unit/$fname" 2>/dev/null
done

echo "Done. Synced from $BRANCH."
echo "Run tests: uv run pytest tests/test_jsonformula_rubric.py -v"
