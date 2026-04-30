setup:
    uv sync
    pre-commit install
    pre-commit install --hook-type commit-msg

test:
    uv run pytest

lint:
    uv run ruff check src tests

run-repl *args="":
    uv run pcap-agent --ui console {{ args }}

run-app *args="":
    uv run pcap-agent --ui app {{ args }}
