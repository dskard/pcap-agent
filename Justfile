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

grafana-up:
    docker run -d --name pcap-agent-grafana \
        -p 3000:3000 \
        -p 4317:4317 \
        -p 4318:4318 \
        grafana/otel-lgtm:latest
    @echo "Grafana running at http://localhost:3000"
    @echo "OTLP endpoint at http://localhost:4318"

grafana-down:
    docker stop pcap-agent-grafana && docker rm pcap-agent-grafana
