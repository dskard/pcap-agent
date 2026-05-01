"""CLI entry point for pcap-agent."""

import os
import sys
from pathlib import Path
from typing import Any

import click


def _print_synopsis(pcap_file: str, result: dict[str, Any]) -> None:
    label = "(from cache)" if result.get("cached") else "(new)"
    click.echo(
        f"\nLoaded {Path(pcap_file).name} {label} — {result['n_packets']} packets"
    )

    protocols = result.get("protocol_counts", [])
    if protocols:
        parts = ", ".join(
            f"{p['protocol']} {p['pct']}%" for p in protocols
        )
        click.echo(f"  Protocols: {parts}")

    talkers = result.get("top_talkers", [])
    if talkers:
        top = talkers[0]
        click.echo(
            f"  Top talker: {top['src_ip']} ({top['packet_count']} packets)"
        )


@click.command()
@click.argument("pcap_file", required=False, type=click.Path(exists=True))
@click.option(
    "--api-key",
    envvar="ANTHROPIC_API_KEY",
    default="",
    help="Anthropic API key [env: ANTHROPIC_API_KEY]",
)
@click.option(
    "--model",
    envvar="ANTHROPIC_MODEL",
    default="claude-sonnet-4-6",
    show_default=True,
    help="Claude model name [env: ANTHROPIC_MODEL]",
)
@click.option(
    "--ui",
    envvar="PCAP_AGENT_UI",
    default="console",
    show_default=True,
    type=click.Choice(["console", "app"]),
    help="UI mode: console (REPL) or app (Shiny web UI) [env: PCAP_AGENT_UI]",
)
@click.option(
    "--db-dir",
    envvar="PCAP_AGENT_DB_DIR",
    default="~/.cache/pcap-agent",
    show_default=True,
    help="Directory for DuckDB storage [env: PCAP_AGENT_DB_DIR]",
)
@click.option(
    "--otlp-endpoint",
    envvar="OTEL_EXPORTER_OTLP_ENDPOINT",
    default="",
    help="OpenTelemetry OTLP exporter endpoint [env: OTEL_EXPORTER_OTLP_ENDPOINT]",
)
@click.option(
    "--log-level",
    envvar="PCAP_AGENT_LOG_LEVEL",
    default="WARNING",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Logging level [env: PCAP_AGENT_LOG_LEVEL]",
)
def main(
    pcap_file: str | None,
    api_key: str,
    model: str,
    ui: str,
    db_dir: str,
    otlp_endpoint: str,
    log_level: str,
) -> None:
    """PCAP analysis agent powered by Claude.

    Optionally provide a PCAP_FILE to ingest before starting the chat session.
    """
    if not api_key:
        click.echo(
            "Error: ANTHROPIC_API_KEY is not set. "
            "Provide it via --api-key or the ANTHROPIC_API_KEY environment variable.",
            err=True,
        )
        sys.exit(1)

    db_dir_expanded = os.path.expanduser(db_dir)

    # Set env vars before importing config-dependent modules so the module-level
    # config singleton sees the values resolved from CLI flags.
    os.environ["ANTHROPIC_API_KEY"] = api_key
    os.environ["ANTHROPIC_MODEL"] = model
    os.environ["PCAP_AGENT_UI"] = ui
    os.environ["PCAP_AGENT_DB_DIR"] = db_dir_expanded
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = otlp_endpoint
    os.environ["PCAP_AGENT_LOG_LEVEL"] = log_level

    from pcap_agent import telemetry

    telemetry.setup(otlp_endpoint, log_level)

    if pcap_file:
        from rich.progress import Progress, SpinnerColumn, TextColumn

        from pcap_agent.tools.ingest import ingest_pcap

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(f"Ingesting {pcap_file}…", total=None)
            result = ingest_pcap(pcap_file, db_dir=db_dir_expanded)
        if not result.get("n_packets"):
            click.echo("Warning: no packets were ingested from the file.", err=True)
        else:
            _print_synopsis(pcap_file, result)

    from pcap_agent.agent import create_agent

    chat = create_agent(api_key=api_key, model=model, pcap_file=pcap_file)

    if ui == "app":
        chat.app()
    else:
        chat.console()
