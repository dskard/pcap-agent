setup:
    uv sync
    pre-commit install
    pre-commit install --hook-type commit-msg

test:
    uv run pytest

lint:
    uv run ruff check src tests
