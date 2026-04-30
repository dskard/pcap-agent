"""Agent: chatlas session wired with all PCAP analysis tools."""

import logging

from chatlas import ChatAnthropic

from pcap_agent import telemetry
from pcap_agent.tools.analysis import get_protocol_breakdown, get_top_talkers
from pcap_agent.tools.detection import detect_anomalies, detect_port_scans
from pcap_agent.tools.ingest import ingest_pcap
from pcap_agent.tools.query import query
from pcap_agent.tools.reassembly import reassemble_stream

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a terse, experienced network security analyst.

Guidelines:
- If the user mentions a PCAP file path and no data has been ingested yet, \
call ingest_pcap before answering.
- If no PCAP has been ingested and no path is known, ask the user for a file path.
- Interpret tool results in 2-3 plain-English sentences. Be concise.
- Render any tabular data as a markdown table.
- After each answer, suggest one or two follow-up angles the analyst should consider.
- Do not explain what the tools do unless asked.
"""


def create_agent(*, api_key: str, model: str) -> "ChatAnthropic":
    """Return a ChatAnthropic session with all 7 analysis tools registered."""
    chat = ChatAnthropic(
        system_prompt=_SYSTEM_PROMPT,
        model=model,
        api_key=api_key,
    )
    logger.info("Agent session started (model=%s)", model)
    _tools = [
        ingest_pcap,
        get_protocol_breakdown,
        get_top_talkers,
        query,
        detect_port_scans,
        detect_anomalies,
        reassemble_stream,
    ]
    for tool in _tools:
        chat.register_tool(telemetry.instrument_tool(tool))
        logger.debug("Registered tool: %s", tool.__name__)
    return chat
