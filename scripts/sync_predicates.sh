#!/usr/bin/env bash
# Sync predicates.json from the C2PA Knowledge Graph repo.
#
# Usage: ./scripts/sync_predicates.sh [path-to-kg-repo]
#
# If no path is given, looks for ../c2pa-knowledge-graph relative to this repo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/src/c2pa_conformance/data/predicates.json"

KG_REPO="${1:-$(cd "$REPO_ROOT/.." && pwd)/c2pa-knowledge-graph}"
SOURCE="$KG_REPO/versions/2.4/predicates.json"

if [ ! -f "$SOURCE" ]; then
    echo "ERROR: predicates.json not found at $SOURCE"
    echo "Usage: $0 [path-to-c2pa-knowledge-graph]"
    exit 1
fi

cp "$SOURCE" "$TARGET"
echo "Synced predicates.json from $SOURCE"
echo "  -> $TARGET"

# Show coverage stats
python3 -c "
import json
p = json.load(open('$TARGET'))
cs = p['coverage_summary']
print(f\"  Predicates: {cs['total_predicates']}\")
print(f\"  Rules: {cs['rules_formalized']}/{cs['total_v24_rules']} ({cs['coverage_percent']}%)\")
"
