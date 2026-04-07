# Contributing

## Development setup

```bash
git clone https://github.com/encypherai/c2pa-conformance-suite.git
cd c2pa-conformance-suite
uv sync --all-extras
```

Run the tests:

```bash
uv run pytest
```

Run lint:

```bash
uv run ruff check .
```

## Syncing predicates from the Knowledge Graph

The bundled `predicates.json` comes from the
[C2PA Knowledge Graph](https://github.com/encypherai/c2pa-knowledge-graph).
To update it:

```bash
./scripts/sync_predicates.sh /path/to/c2pa-knowledge-graph
```

If the knowledge graph repo is a sibling directory, the script finds it
automatically:

```bash
./scripts/sync_predicates.sh
```

## Adding a new operator

Operators live in `src/c2pa_conformance/evaluator/engine.py`. The pattern:

1. Write a function `_eval_<op_name>(context, condition) -> tuple[bool, str]`.
2. Add an entry to the `_OPERATORS` dict.
3. Add tests in `tests/test_operators.py` or `tests/test_operators_advanced.py`.
4. Run `tests/test_kg_integration.py` to verify the new operator resolves any
   previously unhandled predicates.

## Adding an extractor

Extractors live in `src/c2pa_conformance/extractors/`. Each extractor must:

- Implement `detect(path) -> bool` and `extract(path) -> ExtractionResult`.
- Register itself in `extractors/__init__.py`.
- Include at least one unit test with a minimal fixture.

## Code style

- Python 3.11+ type annotations throughout.
- `ruff` for lint and format. Configuration is in `pyproject.toml`.
- ASCII-only source files and documentation.
- No `@ts-ignore` equivalents: fix type errors at their root.

## Commit messages

Use imperative subject lines with a conventional commit prefix:

```
feat(engine): add regex_match operator
fix(parser): handle missing claim_generator_info field
docs: update quick-start example
```

One commit per logical change. Do not bundle unrelated fixes.

## Running integration tests with c2pa-tool

Some tests require `c2patool` on PATH. Install it from
[c2pa-rs](https://github.com/contentauth/c2pa-rs) and run:

```bash
uv run pytest -m integration
```

## Reporting issues

Open an issue at
https://github.com/encypherai/c2pa-conformance-suite/issues. Include the
asset format, the predicate ID if applicable, and the full error output.
