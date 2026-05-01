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
    pcap_agent_log_level: str
    pcap_agent_log_file: str


_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _load() -> Config:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY is not set. "
            "Provide it in your environment or .env file."
        )
    log_level = os.environ.get("PCAP_AGENT_LOG_LEVEL", "WARNING").upper()
    if log_level not in _VALID_LOG_LEVELS:
        raise ValueError(
            f"PCAP_AGENT_LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}, "
            f"got {log_level!r}"
        )
    return Config(
        anthropic_api_key=api_key,
        anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        pcap_agent_ui=os.environ.get("PCAP_AGENT_UI", "console"),
        pcap_agent_db_dir=os.path.expanduser(
            os.environ.get("PCAP_AGENT_DB_DIR", "~/.cache/pcap-agent")
        ),
        otel_exporter_otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
        pcap_agent_log_level=log_level,
        pcap_agent_log_file=os.environ.get("PCAP_AGENT_LOG_FILE", ""),
    )


config = _load()
