"""Configuration resolved from environment variables and .env file."""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    anthropic_api_key: str = field(repr=False)
    anthropic_model: str
    pcap_agent_ui: str
    pcap_agent_db_dir: str
    otel_exporter_otlp_endpoint: str
    pcap_agent_verbose: bool


def _load() -> Config:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY is not set. "
            "Provide it in your environment or .env file."
        )
    return Config(
        anthropic_api_key=api_key,
        anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        pcap_agent_ui=os.environ.get("PCAP_AGENT_UI", "console"),
        pcap_agent_db_dir=os.path.expanduser(
            os.environ.get("PCAP_AGENT_DB_DIR", "~/.cache/pcap-agent")
        ),
        otel_exporter_otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
        pcap_agent_verbose=os.environ.get("PCAP_AGENT_VERBOSE", "").lower()
        in ("1", "true", "yes"),
    )


config = _load()
