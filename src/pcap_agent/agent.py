"""Agent: chatlas session wired with all PCAP analysis tools."""

import logging

from chatlas import ChatAnthropic, ToolRejectError

from pcap_agent import telemetry
from pcap_agent.tools.analysis import get_protocol_breakdown, get_top_talkers
from pcap_agent.tools.decode_payload import decode_payload
from pcap_agent.tools.detection import detect_anomalies, detect_port_scans
from pcap_agent.tools.ingest import ingest_pcap
from pcap_agent.tools.layer2 import get_layer2_summary
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
- When a payload is returned as hex-encoded bytes, call decode_payload \
to decompress or unpack it before presenting results to the user.

Capability boundary:

Supported protocols and layers:
- Layer 2: Ethernet (MAC addresses, VLAN tags), ARP
- Layer 3: IPv4, IPv6
- Layer 4: TCP, UDP, ICMP, ICMPv6
- Capture metadata: link-layer type, radiotap WiFi headers

Not supported (no data captured or decoded):
- Application layer: DHCP, DNS, HTTP, TLS/SNI
- WAN/carrier: PPPoE, MPLS
- Switching/discovery: STP, LLDP, CDP
- IP options and fragmentation
- TCP options
- Transport: SCTP, GRE, IPsec
"""

_PCAP_LOADED_SUFFIX = "\nA PCAP file has already been ingested: `{pcap_file}`. \
The data is ready for analysis."

def create_agent(
    *, api_key: str, model: str, pcap_file: str | None = None, schema: str | None = None
) -> "ChatAnthropic":
    """Return a ChatAnthropic session with all 9 analysis tools registered."""
    system_prompt = _SYSTEM_PROMPT
    if pcap_file:
        system_prompt += _PCAP_LOADED_SUFFIX.format(pcap_file=pcap_file)
    if schema:
        system_prompt += "\n\n" + schema

    chat = ChatAnthropic(
        system_prompt=system_prompt,
        model=model,
        api_key=api_key,
    )
    logger.info("Agent session started (model=%s)", model)

    def _reject_non_dict_input(request):
        if not isinstance(request.arguments, dict):
            raise ToolRejectError(
                "Tool input must be an object, not a primitive value."
            )

    chat.on_tool_request(_reject_non_dict_input)
    _tools = [
        ingest_pcap,
        get_protocol_breakdown,
        get_top_talkers,
        get_layer2_summary,
        query,
        detect_port_scans,
        detect_anomalies,
        reassemble_stream,
        decode_payload,
    ]
    for tool in _tools:
        chat.register_tool(telemetry.instrument_tool(tool))
        logger.debug("Registered tool: %s", tool.__name__)
    return chat
