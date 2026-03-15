# Contributing to secretscreen

## Dev setup

Requires Python 3.11+.

```bash
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
```

## Code style

This project uses [Ruff](https://github.com/astral-sh/ruff) for linting and formatting.

```bash
ruff check src/ tests/   # lint
ruff format --check .    # format check
ruff format .            # auto-format
```

Both checks run in CI. PRs that fail either check will not merge.

## Type checking

```bash
mypy src/secretscreen/
```

## PR process

1. Fork the repo and create a branch from `main`.
2. Make your changes. Add tests for new behavior.
3. Ensure `pytest`, `ruff check src/ tests/`, `ruff format --check .`, and `mypy src/secretscreen/` all pass.
4. Open a PR against `main`. Fill in the template.
5. CI must pass before merge.
