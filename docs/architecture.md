# Architecture

pcap-agent is a single-process CLI application that ingests PCAP files into a local DuckDB database and exposes a Claude-powered conversational interface for querying and analysing the captured network traffic.

## High-level flow

```
PCAP file
   │
   ▼
parser.py          Scapy → Polars DataFrames (ParsedPcap)
   │
   ▼
db.py              DuckDB schema DDL + bulk insert via executemany
   │
   ▼
tools/_state.py    Module-level singleton DuckDB connection
   │
   ├── tools/analysis.py      get_protocol_breakdown(), get_top_talkers()
   ├── tools/query.py         query()  — validated ad-hoc SQL
   ├── tools/detection.py     detect_port_scans(), detect_anomalies()
   └── tools/reassembly.py    reassemble_stream()
         │
         ▼
agent.py           ChatAnthropic session — all 7 tools registered + OTel-wrapped
         │
         ▼
cli.py             Click entry point — flags → env vars → ingest spinner → chat UI
```

## Source layout

```
src/pcap_agent/
  config.py          Frozen Config dataclass, loaded once from env / .env at import time
  agent.py           create_agent() — ChatAnthropic session with all 7 tools
  cli.py             Click entry point: flags, spinner ingest, console/app dispatch
  db.py              DuckDB schema DDL, ingest(), get_cached() / set_cached()
  parser.py          Scapy → Polars DataFrames (ParsedPcap)
  telemetry.py       OTel SDK init (setup()), instrument_tool(), metric helpers
  tools/
    _state.py        Module-level singleton connection: set / get / require / reset
    ingest.py        ingest_pcap() — parse + persist + auto-run analysis
    analysis.py      get_protocol_breakdown(), get_top_talkers()
    query.py         query() — validated ad-hoc SQL with safety guardrails
    detection.py     detect_port_scans(), detect_anomalies() — on-demand only
    reassembly.py    reassemble_stream() — TCP/UDP payload reassembly (64 KB cap)
```

## Database schema

```sql
packets        (packet_id PK, timestamp, src_ip, dst_ip, protocol, length, ttl)
tcp_segments   (packet_id FK, sport, dport, flags, seq, ack, payload BLOB)
udp_datagrams  (packet_id FK, sport, dport, payload BLOB)
icmp_messages  (packet_id FK, type, code, payload BLOB)
pcap_meta      (sha256 PK, pcap_path, ingested_at)  -- content-addressed cache
```

`pcap_meta` is used to skip re-parsing a file that has already been ingested. The SHA-256 of the PCAP file is the cache key, so the same file stored at a different path is still recognised as a cache hit.

## Key design decisions

### Single shared DuckDB connection

All tools share one `duckdb.Connection` object stored in `tools/_state.py`. There is no connection pool and no locking. This is intentional: DuckDB's single-writer model and the strictly single-threaded CLI use case make a pool unnecessary. The connection is opened at ingest time and reused for the lifetime of the session.

When `ingest_pcap` is called with a different `db_dir`, it closes the current connection before opening a new one. Any caller that holds a reference to the old connection object must re-open by path rather than restoring the closed handle.

### Tools return plain dicts

All tool functions return `dict` objects so the agent can directly serialise and reason about the data without extra marshalling. Expected errors (bad SQL, no data ingested) return `{"error": "...", "hint": "..."}` so the agent can self-correct without crashing. Unexpected exceptions propagate normally.

### Agent system prompt

`agent.py` uses a terse, security-analyst persona. When a PCAP file is provided on the CLI, the path is appended to the system prompt so the agent knows the data is already loaded and can skip the ingest step.

### Config loading order

`config.py` runs `_load()` at module import time and raises immediately if `ANTHROPIC_API_KEY` is unset. To allow CLI flags to override environment variables, `cli.py` writes flag values into `os.environ` *before* importing any module that transitively imports `config`. All `pcap_agent` imports are therefore deferred to the body of the `main()` function rather than placed at the top of `cli.py`.

## Adding a new tool

1. Create `src/pcap_agent/tools/<name>.py`.
2. Call `_state.require_connection()` to obtain the connection — this raises `RuntimeError` when no PCAP has been ingested yet.
3. Return plain dicts; use `{"error": ..., "hint": ...}` for expected failures.
4. Register the tool in `agent.py` inside the `_tools` list.
5. Add integration tests in `tests/test_<name>_tool.py` using the `ingested_db` session fixture.
6. Run `uv run ruff check` and `uv run pytest`.
