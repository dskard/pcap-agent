# Observability

pcap-agent emits structured logs, distributed traces, and metrics via the [OpenTelemetry](https://opentelemetry.io/) SDK. Telemetry is **off by default** — the application runs normally with no external dependencies until an OTLP endpoint is configured.

## Logging

Logging is always enabled. The root logger is configured in `telemetry.setup()` via `logging.basicConfig(..., force=True)`.

| Option | Default | Description |
|---|---|---|
| `--log-level` / `PCAP_AGENT_LOG_LEVEL` | `WARNING` | Minimum log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `--log-file` / `PCAP_AGENT_LOG_FILE` | `""` (stderr) | Write logs to this file in append mode instead of stderr |

Example — write `DEBUG` logs to a file:

```bash
pcap-agent --log-level DEBUG --log-file pcap-agent.log capture.pcap
```

Or via environment variables:

```bash
export PCAP_AGENT_LOG_LEVEL=DEBUG
export PCAP_AGENT_LOG_FILE=pcap-agent.log
pcap-agent capture.pcap
```

## Traces and metrics

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the agent initialises three OTLP HTTP exporters:

| Signal | Endpoint path |
|---|---|
| Traces | `<base>/v1/traces` |
| Metrics | `<base>/v1/metrics` |
| Logs bridge | `<base>/v1/logs` |

All seven tool functions are wrapped with `instrument_tool()` in `agent.py`. Each call produces an OTel span named after the function. Span attributes include the tool name and every argument (stringified).

### Metrics

| Metric name | Type | Description |
|---|---|---|
| `pcap_agent.packets_ingested` | Counter | Total packets inserted into DuckDB |
| `pcap_agent.queries_run` | Counter | Total ad-hoc SQL queries executed |
| `pcap_agent.anomalies_detected` | Counter | Total anomalies returned by `detect_anomalies` |
| `pcap_agent.tool_call_latency` | Histogram (seconds) | Wall-clock duration of each tool call, labelled by `tool` |

## Local observability stack

A ready-to-use all-in-one stack based on [grafana/otel-lgtm](https://hub.docker.com/r/grafana/otel-lgtm) (Loki + Grafana + Tempo + Mimir) is provided via the Justfile.

**Start the stack:**

```bash
just grafana-up
```

This starts a Docker container that exposes:

| Service | URL |
|---|---|
| Grafana UI | <http://localhost:3000> |
| OTLP HTTP endpoint | <http://localhost:4318> |

**Configure the agent to send telemetry:**

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
pcap-agent capture.pcap
```

Or set it in your `.env` file:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

**Stop the stack:**

```bash
just grafana-down
```

## Implementation details

The telemetry module (`src/pcap_agent/telemetry.py`) is structured so that no OTel SDK packages are imported unless an endpoint is configured. This means the application starts without error even when the OTel SDK packages are absent from the environment (they are included as runtime dependencies but the import is lazy).

The `instrument_tool()` decorator is a no-op when `_tracer is None`, so all tool functions work identically with or without telemetry enabled.

Metric counters are recorded inside the tool functions themselves (not only in the decorator) so that the CLI ingest step — which runs before the agent loop starts — also contributes to the metrics.
