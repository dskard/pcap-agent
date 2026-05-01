# pcap-agent

AI-powered network traffic analyst. Point it at a PCAP file and ask questions in plain English — the agent ingests the capture into a local DuckDB database, then uses Claude to answer questions, detect anomalies, and reconstruct TCP/UDP streams.

## Features

- Natural-language interface to packet data powered by Claude
- Fast SQL queries over DuckDB (millions of packets, sub-second responses)
- Protocol breakdown and top-talkers analysis out of the box
- Port-scan and anomaly detection (IsolationForest)
- TCP/UDP stream reassembly with up to 64 KB payload
- Console REPL and Shiny web UI
- OpenTelemetry traces, metrics, and structured logs (optional)

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.13+ |
| [uv](https://docs.astral.sh/uv/) | latest |
| [just](https://just.systems/) | latest |
| Docker | optional — for the local observability stack |

An **Anthropic API key** is required. Get one at <https://console.anthropic.com>.

## Setup

1. Clone the repository:

   ```bash
   git clone <repo-url>
   cd pcap-agent
   ```

2. Configure environment variables:

   ```bash
   cp .envrc.example .envrc
   # edit .envrc — at minimum set ANTHROPIC_API_KEY
   source .envrc          # or: direnv allow
   ```

3. Install dependencies and pre-commit hooks:

   ```bash
   just setup
   ```

## Getting started

Ingest a PCAP file and start the console REPL in one command:

```bash
just run-repl capture.pcap
```

Or use the Shiny web UI:

```bash
just run-app capture.pcap
```

You can also omit the file and provide it once the session starts:

```bash
just run-repl
# agent will prompt you for a path
```

### Example session

```
Loaded capture.pcap (new) — 4 213 packets
  Protocols: TCP 72%, UDP 21%, ICMP 7%
  Top talker: 192.168.1.5 (1 847 packets)

> What are the top destination ports?
> Are there any signs of a port scan?
> Reassemble the TCP stream between 192.168.1.5 and 10.0.0.1
```

## Configuration

All options can be set via CLI flags or environment variables. CLI flags take precedence.

| Variable | Default | CLI flag | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | `--api-key` | Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | `--model` | Claude model name |
| `PCAP_AGENT_DB_DIR` | `~/.cache/pcap-agent` | `--db-dir` | Directory for DuckDB storage |
| `PCAP_AGENT_UI` | `console` | `--ui` | UI mode: `console` or `app` |
| `PCAP_AGENT_LOG_LEVEL` | `WARNING` | `--log-level` | Log level: `DEBUG` `INFO` `WARNING` `ERROR` `CRITICAL` |
| `PCAP_AGENT_LOG_FILE` | `""` | `--log-file` | Write logs to a file instead of stderr |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `""` | `--otlp-endpoint` | OTLP endpoint (empty = telemetry off) |

Set variables in `.envrc` (or `.env`) to avoid repeating them on every invocation.

## Documentation

- [Architecture](docs/architecture.md) — source layout, data flow, and design decisions
- [Observability](docs/observability.md) — logging, tracing, metrics, and the local Grafana stack
- [Contributing](CONTRIBUTING.md) — dev environment setup, testing, and contribution guidelines

## Justfile targets

| Target | Description |
|---|---|
| `just setup` | Install dependencies and pre-commit hooks |
| `just test` | Run the test suite |
| `just lint` | Run ruff over `src` and `tests` |
| `just run-repl [args...]` | Start the console REPL |
| `just run-app [args...]` | Start the Shiny web UI |
| `just grafana-up` | Start the local Grafana / OTLP stack (Docker) |
| `just grafana-down` | Stop and remove the Grafana container |

## License

See [LICENSE](LICENSE).
