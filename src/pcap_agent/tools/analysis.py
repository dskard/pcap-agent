"""Read-only analysis tools: protocol breakdown and top talkers."""

import logging

from pcap_agent.tools import _state

logger = logging.getLogger(__name__)

_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def get_protocol_breakdown() -> list[dict]:
    """Return per-protocol packet counts sorted descending by count."""
    conn = _state.require_connection()
    total = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    rows = conn.execute(
        "SELECT protocol, COUNT(*) AS count "
        "FROM packets "
        "GROUP BY protocol "
        "ORDER BY count DESC"
    ).fetchall()
    result = []
    for proto_num, count in rows:
        if proto_num is not None:
            name = _PROTO_MAP.get(int(proto_num), f"proto_{proto_num}")
        else:
            name = "unknown"
        pct = round(count / total * 100, 1) if total else 0.0
        result.append({"protocol": name, "count": count, "pct": pct})
    logger.debug("get_protocol_breakdown returned %d protocol(s)", len(result))
    return result


def get_top_talkers(n: int = 10) -> list[dict]:
    """Return top-N source IPs ranked by packet count."""
    if n <= 0:
        return []
    conn = _state.require_connection()
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) AS packet_count "
        "FROM packets "
        "GROUP BY src_ip "
        "ORDER BY packet_count DESC "
        "LIMIT ?",
        [n],
    ).fetchall()
    result = [{"src_ip": r[0], "packet_count": r[1]} for r in rows]
    logger.debug("get_top_talkers(n=%d) returned %d result(s)", n, len(result))
    return result
