# pcap-agent

AI agent that ingests PCAP files into DuckDB and answers questions about network traffic.

## Stack

- **Python 3.13**, managed with **uv** (never use pip3 directly — always `uv add`)
- **DuckDB** for packet storage and query
- **Polars** DataFrames from the parser layer; inserted row-by-row via `executemany`
- **Scapy** for PCAP parsing
- **chatlas** for the agent loop
- **ruff** (`E`, `F`, `I` rules, line length 88) — run `uv run ruff check` before committing
- **pytest** — run with `uv run pytest`

## Project layout

```
src/pcap_agent/
  config.py          # frozen Config dataclass, loaded from env/.env
  agent.py           # create_agent() — ChatAnthropic session + all 7 tools registered
  cli.py             # click entry point: flags, spinner ingest, console/app dispatch
  db.py              # DuckDB schema DDL, ingest(), get_cached()/set_cached()
  parser.py          # Scapy → Polars DataFrames (ParsedPcap)
  telemetry.py       # OTel SDK init (setup()), instrument_tool(), metric record helpers
  tools/
    _state.py        # module-level singleton connection: set/get/require/reset
    ingest.py        # ingest_pcap() — parse + persist + auto-run analysis
    analysis.py      # get_protocol_breakdown(), get_top_talkers()
    query.py         # query() — validated ad-hoc SQL with safety guardrails
    detection.py     # detect_port_scans(), detect_anomalies() — on-demand only
    reassembly.py    # reassemble_stream() — TCP/UDP payload reassembly with 64 KB cap
tests/
  conftest.py        # session fixtures: synthetic_pcap, ingested_db, ingested_conn
  constants.py       # packet counts and IPs shared across all test files
```

## Architecture decisions

- **Single shared connection** (`tools/_state.py`): all tools share one DuckDB connection per session. No locking; single-threaded CLI use only.
- **Tools return plain dicts** so the agent can serialize and reason about results.
- **Expected errors return structured dicts** `{"error": ..., "hint": ...}`; unexpected exceptions propagate. This lets the agent self-correct on bad input without crashing.
- **`ingest_pcap` closes the previous connection** when switching to a different DB file (DuckDB single-writer constraint). Any fixture or caller that holds a reference to the old connection object must re-open by path, not restore the closed handle.
- **Telemetry is a no-op by default** (`telemetry.py`): `setup(endpoint, log_level)` always configures the root logger via `logging.basicConfig(..., force=True)`, then returns early if `endpoint` is empty (skipping all OTel SDK initialisation). All 7 tools are wrapped with `instrument_tool()` in `agent.py`; spans and metrics are only emitted when an OTLP endpoint is configured. Metric counters (`record_packets_ingested`, `record_queries_run`, `record_anomalies_detected`) live in the tool functions themselves so the CLI initial ingest also records metrics.

## Schema

```sql
packets        (packet_id PK, timestamp, src_ip, dst_ip, protocol, length, ttl)
tcp_segments   (packet_id, sport, dport, flags, seq, ack, payload)
udp_datagrams  (packet_id, sport, dport, payload)
icmp_messages  (packet_id, type, code, payload)
pcap_meta      (sha256 PK, pcap_path, ingested_at)  -- caching table
```

## Adding a new tool

1. Create `src/pcap_agent/tools/<name>.py`
2. Call `_state.require_connection()` to get the connection — raises `RuntimeError` if no PCAP ingested yet
3. Return plain dicts; return `{"error": ..., "hint": ...}` for expected failures
4. Add integration tests in `tests/test_<name>_tool.py` using the `ingested_db` session fixture
5. Run `uv run ruff check` and `uv run pytest`

## Testing patterns

- **`ingested_db`** (session-scoped): ingests the synthetic PCAP once; sets `_state._conn`. Use this for any test that needs data in the DB.
- **`ingested_conn`**: returns `_state.require_connection()` after `ingested_db` runs. Use when you need the raw connection.
- **`duckdb_conn`** (function-scoped): fresh in-memory connection with schema. Use for DB-layer unit tests that don't need the full ingest pipeline.
- **`_restore_state`** (in `test_ingest.py`): saves `_state._db_path` before the test, closes the post-test connection, and **re-opens** the saved path — because `ingest_pcap` closes the previous connection on DB switch, making object-level restore impossible.

### Test isolation pitfall
`ingest_pcap` closes `_state._conn` when switching databases. Never try to restore a saved connection object after calling `ingest_pcap` with a different `db_dir` — it will already be closed. Re-open via `duckdb.connect(saved_path)` instead.

### DuckDB BLOB sizing
Use `OCTET_LENGTH(col)` to measure byte length of `BLOB` columns. `LENGTH()` is not overloaded for `BLOB` in DuckDB and raises a `BinderException` at runtime.

### IsolationForest contamination calibration
The contamination parameter controls the percentile threshold, not a strict count. `contamination=c` flags all samples whose score falls below `np.percentile(scores, 100*c)`. For a fixture with well-separated anomalies, calibrate by running the detector at increasing contamination values until all known-anomalous packets appear; the required value may be higher than `n_anomalies / n_total` due to score clustering near the boundary.

### Temporarily swapping `_state._conn` in function-scoped fixtures
When a tool test needs custom data (e.g. binary payloads, oversized chunks) that the shared session fixture doesn't provide, use `duckdb_conn` and swap the singleton inside a function-scoped fixture:

```python
@pytest.fixture()
def custom_conn(self, duckdb_conn):
    # insert custom rows...
    old = _state.get_connection()
    old_path = _state.get_db_path()
    _state.set_connection(duckdb_conn, ":memory:")
    yield duckdb_conn
    _state.set_connection(old, old_path) if old else _state.reset()
```

This keeps the session `_state._conn` intact for all other test files.

### Testing OTel instrumentation without a real OTLP server
Use `InMemorySpanExporter` and `InMemoryMetricReader` from the OTel SDK to unit-test spans and metrics without needing a running collector. Directly set `telemetry._tracer` / `telemetry._meter` / `telemetry._metrics` in the fixture instead of calling `setup()`, to avoid mutating global OTel provider state across tests. Call `telemetry._reset()` in `autouse` teardown.

To patch multiple OTel symbols inside a function that does lazy imports (e.g. `setup()`), use `contextlib.ExitStack` — Python's `with` statement does not support `*`-unpacking a list of context managers.

### Root logger level in tests
`telemetry.setup()` configures the root logger via `logging.basicConfig(..., force=True)`, which always replaces existing handlers. Tests that call `setup()` with a non-default level must restore `logging.getLogger().level` (and handlers) in a `try/finally` block, because the `reset_telemetry` autouse fixture does not reset root logger state.

### Test file ordering matters
pytest collects files alphabetically. Tests in `test_query_tool.py` run after `test_ingest.py::TestIngestCaching`, which temporarily replaces the session connection. The `_restore_state` fixture must leave `_state._conn` in a valid open state or later test files will see a closed connection.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | Claude API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Model to use |
| `PCAP_AGENT_DB_DIR` | `~/.cache/pcap-agent` | Where DuckDB files are stored |
| `PCAP_AGENT_UI` | `console` | UI mode |
| `PCAP_AGENT_LOG_LEVEL` | `WARNING` | Root logger level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `PCAP_AGENT_LOG_FILE` | `""` | Route log output to this file (append mode) instead of stderr |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `""` | OpenTelemetry OTLP endpoint |

Tests set `ANTHROPIC_API_KEY=test-dummy-key` via `pytest_configure` in `conftest.py`.

## CLI config loading order

`config.py` runs `_load()` at module import time and raises if `ANTHROPIC_API_KEY` is unset. The CLI sets `os.environ` values from click flags **before** importing any `pcap_agent` module that transitively imports `config`. Keep all `pcap_agent` imports inside the command function body, not at the top of `cli.py`.

## Justfile targets

| Target | Description |
|---|---|
| `just setup` | Install dependencies and pre-commit hooks |
| `just test` | Run the test suite |
| `just lint` | Run ruff over `src` and `tests` |
| `just run-repl [args...]` | Start the console REPL; pass any CLI flags or a PCAP path as extra args |
| `just run-app [args...]` | Start the Shiny web UI; same variadic args |
| `just grafana-up` | Start `grafana/otel-lgtm` container (Grafana on :3000, OTLP HTTP on :4318) |
| `just grafana-down` | Stop and remove the Grafana container |

## Branch naming

`dsk-<issue-number>-<short-slug>` — e.g. `dsk-5-query-tool-sql-guardrails`
