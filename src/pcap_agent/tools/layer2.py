"""Layer 2 summary tool: link type, Ethernet, ARP, and MAC statistics."""

import logging

from pcap_agent.tools import _state

logger = logging.getLogger(__name__)


def get_layer2_summary() -> dict:
    """Return L2 statistics for the ingested capture.

    Fields: link_type, has_radiotap, total_frame_count, ethernet_frame_count,
    arp_request_count, arp_reply_count, unique_src_mac_count,
    unique_dst_mac_count, distinct_vlan_ids, top_5_src_macs, top_5_dst_macs.

    Returns {"error": ..., "hint": ...} when no ethernet_frames rows exist.
    """
    conn = _state.require_connection()

    eth_count = conn.execute(
        "SELECT COUNT(*) FROM ethernet_frames"
    ).fetchone()[0]
    if eth_count == 0:
        return {
            "error": "No Ethernet frame data found",
            "hint": (
                "This capture may use a non-Ethernet link type,"
                " or no PCAP has been ingested yet."
            ),
        }

    ci = conn.execute(
        "SELECT link_type, has_radiotap FROM capture_info LIMIT 1"
    ).fetchone()
    link_type = ci[0] if ci else None
    has_radiotap = ci[1] if ci else False

    arp_counts = conn.execute(
        "SELECT operation, COUNT(*) FROM arp_packets GROUP BY operation"
    ).fetchall()
    arp_by_op = {op: cnt for op, cnt in arp_counts}

    unique_src = conn.execute(
        "SELECT COUNT(DISTINCT src_mac) FROM ethernet_frames"
    ).fetchone()[0]
    unique_dst = conn.execute(
        "SELECT COUNT(DISTINCT dst_mac) FROM ethernet_frames"
    ).fetchone()[0]

    vlan_rows = conn.execute(
        "SELECT DISTINCT vlan_id FROM ethernet_frames"
        " WHERE vlan_id IS NOT NULL ORDER BY vlan_id"
    ).fetchall()
    distinct_vlan_ids = [r[0] for r in vlan_rows]

    top_src = conn.execute(
        "SELECT src_mac, COUNT(*) AS cnt FROM ethernet_frames"
        " GROUP BY src_mac ORDER BY cnt DESC LIMIT 5"
    ).fetchall()
    top_dst = conn.execute(
        "SELECT dst_mac, COUNT(*) AS cnt FROM ethernet_frames"
        " GROUP BY dst_mac ORDER BY cnt DESC LIMIT 5"
    ).fetchall()

    result = {
        "link_type": link_type,
        "has_radiotap": has_radiotap,
        "total_frame_count": eth_count,
        "ethernet_frame_count": eth_count,
        "arp_request_count": arp_by_op.get(1, 0),
        "arp_reply_count": arp_by_op.get(2, 0),
        "unique_src_mac_count": unique_src,
        "unique_dst_mac_count": unique_dst,
        "distinct_vlan_ids": distinct_vlan_ids,
        "top_5_src_macs": [{"mac": r[0], "count": r[1]} for r in top_src],
        "top_5_dst_macs": [{"mac": r[0], "count": r[1]} for r in top_dst],
    }
    logger.debug("get_layer2_summary: %d ethernet frames", eth_count)
    return result
