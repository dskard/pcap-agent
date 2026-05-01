# Contributing

## Prerequisites

- Python 3.13
- [uv](https://docs.astral.sh/uv/) — the project uses `uv` for dependency management and running tools; never use `pip3` directly
- [just](https://just.systems/) — task runner used by the Justfile
- Docker (optional) — only needed to run the local observability stack

## Setting up the development environment

1. Clone the repository:

   ```bash
   git clone <repo-url>
   cd pcap-agent
   ```

2. Copy the example environment file and fill in your Anthropic API key:

   ```bash
   cp .envrc.example .envrc
   # edit .envrc and set ANTHROPIC_API_KEY
   ```

   If you use [direnv](https://direnv.net/), run `direnv allow` to load the variables automatically. Otherwise source the file manually:

   ```bash
   source .envrc
   ```

3. Install dependencies and pre-commit hooks:

   ```bash
   just setup
   ```

   This runs `uv sync` and `pre-commit install`.

## Project structure

See [docs/architecture.md](docs/architecture.md) for a full description of the source layout and key design decisions.

## Making changes

### Branch naming

Follow the convention `dsk-<issue-number>-<short-slug>`, e.g. `dsk-42-add-http-tool`.

### Adding a dependency

Always use `uv add`, never `pip3 install`:

```bash
uv add <package>
```

For dev-only dependencies:

```bash
uv add --group dev <package>
```

### Adding a new tool

1. Create `src/pcap_agent/tools/<name>.py`.
2. Call `_state.require_connection()` to obtain the DuckDB connection.
3. Return plain dicts; use `{"error": ..., "hint": ...}` for expected failures.
4. Register the tool in `agent.py` inside the `_tools` list.
5. Add integration tests in `tests/test_<name>_tool.py`.

See [docs/architecture.md](docs/architecture.md) for more details.

### Code style

The project uses [ruff](https://docs.astral.sh/ruff/) with rules `E`, `F`, `I` and a line length of 88. Run the linter before committing:

```bash
just lint
```

Pre-commit hooks run ruff automatically on staged files, so you will also get feedback at commit time.

## Running tests

Run the full test suite:

```bash
just test
```

Or directly with pytest:

```bash
uv run pytest
```

To run a single file or test:

```bash
uv run pytest tests/test_query_tool.py
uv run pytest tests/test_query_tool.py::TestQuery::test_select_all
```

### Test fixtures

| Fixture | Scope | Description |
|---|---|---|
| `ingested_db` | session | Ingests the synthetic PCAP once and sets `_state._conn`. Use for any test that needs data in the DB. |
| `ingested_conn` | session | Returns `_state.require_connection()` after `ingested_db` runs. Use when you need the raw connection. |
| `duckdb_conn` | function | Fresh in-memory connection with schema applied. Use for DB-layer unit tests that don't need the full ingest pipeline. |

### Important test isolation notes

- `ingest_pcap` closes `_state._conn` when switching databases. Never restore a saved connection object after calling `ingest_pcap` with a different `db_dir` — re-open via `duckdb.connect(saved_path)` instead.
- When a test needs custom DB state that the shared session fixture does not provide, swap the singleton using `_state.set_connection()` inside a function-scoped fixture and restore it in teardown.
- pytest collects files alphabetically. Test ordering matters because the session-scoped `_state._conn` is shared across all files. See `CLAUDE.md` for the full pitfall list.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

Example: `feat(tools): add http-request reassembly tool`

## Environment variables reference

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | Claude API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Claude model to use |
| `PCAP_AGENT_DB_DIR` | `~/.cache/pcap-agent` | Directory for DuckDB storage |
| `PCAP_AGENT_UI` | `console` | UI mode (`console` or `app`) |
| `PCAP_AGENT_LOG_LEVEL` | `WARNING` | Root logger level |
| `PCAP_AGENT_LOG_FILE` | `""` | Route logs to this file instead of stderr |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `""` | OpenTelemetry OTLP endpoint (empty = telemetry off) |
