"""Stream reassembly tool: rebuilds application-layer payloads from stored packets."""

from __future__ import annotations

import logging

from pcap_agent.tools import _state

logger = logging.getLogger(__name__)

_MAX_BYTES = 64 * 1024  # 64 KB


def reassemble_stream(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
) -> dict:
    """Reassemble application-layer payloads for a given 5-tuple.

    TCP payloads are ordered by sequence number; UDP payloads by timestamp.
    Output is decoded as UTF-8 when possible; otherwise returned as a hex dump.
    Streams longer than 64 KB are truncated; ``truncated`` is True in that case.
    """
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return {
            "error": f"Unsupported protocol: {protocol!r}",
            "hint": "Use 'TCP' or 'UDP'.",
        }

    logger.debug(
        "reassemble_stream: src_ip=%s dst_ip=%s src_port=%d dst_port=%d protocol=%s",
        src_ip, dst_ip, src_port, dst_port, proto,
    )
    conn = _state.require_connection()
    proto_num = 6 if proto == "TCP" else 17

    if proto == "TCP":
        rows = conn.execute(
            """
            SELECT FIRST(t.payload) AS payload
            FROM tcp_segments t
            JOIN packets p ON p.packet_id = t.packet_id
            WHERE p.src_ip = ?
              AND p.dst_ip = ?
              AND t.sport = ?
              AND t.dport = ?
              AND p.protocol = ?
            GROUP BY t.seq
            ORDER BY t.seq
            """,
            [src_ip, dst_ip, src_port, dst_port, proto_num],
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT u.payload
            FROM udp_datagrams u
            JOIN packets p ON p.packet_id = u.packet_id
            WHERE p.src_ip = ?
              AND p.dst_ip = ?
              AND u.sport = ?
              AND u.dport = ?
              AND p.protocol = ?
            ORDER BY p.timestamp
            """,
            [src_ip, dst_ip, src_port, dst_port, proto_num],
        ).fetchall()

    if not rows:
        return {
            "error": "No packets found for the given 5-tuple.",
            "hint": "Check src_ip, dst_ip, src_port, dst_port, and protocol.",
        }

    chunks: list[bytes] = []
    total = 0
    truncated = False

    for (payload,) in rows:
        if payload is None:
            continue
        chunk = bytes(payload) if not isinstance(payload, bytes) else payload
        remaining = _MAX_BYTES - total
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            logger.warning(
                "reassemble_stream: 64 KB cap reached, stream truncated"
            )
            break
        chunks.append(chunk)
        total += len(chunk)

    raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8")
        encoding = "utf-8"
    except (UnicodeDecodeError, ValueError):
        text = raw.hex()
        encoding = "hex"

    logger.info(
        "reassemble_stream: reassembled %d byte(s), encoding=%s", total, encoding
    )
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "payload": text,
        "encoding": encoding,
        "truncated": truncated,
    }
