# Contributing to `pq-edge-bridge`

Thank you for contributing to `pq-edge-bridge` by **Corax CoLAB**!

## Development Setup

1. Install `liboqs` (`0.16.0`) and `liboqs-python`:
   ```bash
   ./deploy/scripts/install_liboqs.sh
   ```
2. Install the package with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run all quality gates before opening a pull request:
   ```bash
   ruff check src tests benchmarks
   mypy src tests
   pytest -v
   ```

## Engineering Standards

- **Zero Stubs:** No mock/placeholder cryptography or unimplemented stubs.
- **Strict Typing:** All code in `src/` and `tests/` must pass `mypy --strict`.
- **English Only:** All code, comments, docstrings, documentation, and commit messages must be in English.
- **License:** All contributions are licensed under the [Apache License 2.0](LICENSE).
